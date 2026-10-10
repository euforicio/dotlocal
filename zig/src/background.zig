//! CLI supervisors detach their session and keep app output in private files.
const std = @import("std");
const runner = @import("dotlocal").runner;
const process = @import("dotlocal").process;
const A = std.mem.Allocator;
const Io = std.Io;

const Ready = struct { version: u32 = 1, supervisor: process.Identity, records: []const runner.Record };
pub const Started = struct { ready: std.json.Parsed(Ready), log_path: []const u8 };

pub const Launch = struct {
    allocator: A,
    io: Io,
    manager: runner.Manager,
    log_path: []const u8,
    records: std.ArrayList(runner.Record) = .empty,
    expected: usize = 1,

    pub fn open(a: A, io: Io, state: []const u8, token: []const u8) !Launch {
        if (token.len != 32) return error.InvalidBackgroundToken;
        for (token) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidBackgroundToken;
        const path = try std.fmt.allocPrint(a, "{s}/background/{s}", .{ state, token });
        defer a.free(path);
        var manager = try runner.Manager.open(a, io, path);
        errdefer manager.deinit();
        return .{ .allocator = a, .io = io, .manager = manager, .log_path = try std.fs.path.join(a, &.{ path, "app.log" }) };
    }
    pub fn deinit(self: *Launch) void {
        self.records.deinit(self.allocator);
        self.allocator.free(self.log_path);
        self.manager.deinit();
    }
    pub fn ready(self: *Launch, record: runner.Record) !void {
        try self.records.append(self.allocator, record);
        if (self.records.items.len != self.expected) return;
        const data = try std.json.Stringify.valueAlloc(self.allocator, Ready{ .supervisor = try process.current(), .records = self.records.items }, .{});
        defer self.allocator.free(data);
        // Linux may use an unnamed O_TMPFILE, which only link() can publish.
        var atomic = try self.manager.directory.createFileAtomic(self.io, "ready.json", .{ .permissions = .fromMode(0o600) });
        defer atomic.deinit(self.io);
        try atomic.file.setPermissions(self.io, .fromMode(0o600));
        try atomic.file.writeStreamingAll(self.io, data);
        try atomic.file.sync(self.io);
        try atomic.link(self.io);
    }
    fn readReady(self: *Launch, identity: process.Identity) !?std.json.Parsed(Ready) {
        const file = self.manager.directory.openFile(self.io, "ready.json", .{ .follow_symlinks = false, .allow_directory = false }) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer file.close(self.io);
        try process.validateOwned(file.handle, 0o600, false);
        var buffer: [4096]u8 = undefined;
        var reader = file.reader(self.io, &buffer);
        const data = try reader.interface.allocRemaining(self.allocator, .limited(1024 * 1024));
        defer self.allocator.free(data);
        const parsed = try std.json.parseFromSlice(Ready, self.allocator, data, .{ .allocate = .alloc_always });
        errdefer parsed.deinit();
        const supervisor = parsed.value.supervisor;
        if (parsed.value.version != 1 or parsed.value.records.len == 0 or parsed.value.records.len > 256 or supervisor.uid != identity.uid or supervisor.pid != identity.pid or supervisor.start != identity.start or supervisor.pgid != supervisor.pid) return error.InvalidBackgroundIdentity;
        for (parsed.value.records) |record| {
            if (record.supervisor.pid != supervisor.pid or record.supervisor.start != supervisor.start or record.supervisor_uid != supervisor.uid or try runner.classify(record) != .active) return error.BackgroundStartFailed;
        }
        try self.manager.directory.deleteFile(self.io, "ready.json");
        return parsed;
    }
};

/// Stops a supervisor that has not reported readiness, then any app group it
/// left behind. The supervisor stays this process's unreaped child until
/// `reap` releases it, so its PID cannot be reused in between.
fn cancel(a: A, io: Io, state: []const u8, child: *std.process.Child, identity: process.Identity) void {
    if (child.id != null) process.signalProcess(identity, .TERM) catch {};
    const deadline = Io.Clock.awake.now(io).toNanoseconds() + 7 * std.time.ns_per_s;
    while (child.id != null and Io.Clock.awake.now(io).toNanoseconds() < deadline) {
        if ((runner.reap(io, child, false) catch break) != null) break;
        Io.sleep(io, .fromMilliseconds(20), .awake) catch break;
    }
    // Child.kill sends TERM and blocks; a supervisor that ignored TERM needs KILL.
    if (child.id) |pid| {
        std.posix.kill(pid, .KILL) catch {};
        _ = runner.reap(io, child, true) catch {};
    }
    // A stuck or killed supervisor may leave app groups and records behind.
    var manager = runner.Manager.open(a, io, state) catch return;
    defer manager.deinit();
    const records = manager.records() catch return;
    defer records.deinit();
    for (records.value.records) |record| if (record.supervisor.pid == identity.pid and record.supervisor.start == identity.start and record.supervisor_uid == identity.uid) {
        process.signal(record.liveIdentity(), .KILL) catch {};
        manager.removeMatching(record.endpoint.name, record.identity) catch {};
    };
}

fn appsListening(records: []const runner.Record) !bool {
    for (records) |record| {
        if (try runner.classify(record) != .active) return error.BackgroundStartFailed;
        if (!record.endpoint.proxy) continue;
        if (!std.mem.eql(u8, record.endpoint.host, "127.0.0.1") or record.endpoint.port == 0) return error.InvalidBackgroundEndpoint;
        if (!try portListening(record.endpoint.port)) return false;
    }
    return true;
}

fn portListening(port: u16) !bool {
    // Zig 0.17's Threaded netConnectIpPosix panics for non-none timeouts.
    // A nonblocking native loopback probe keeps startup cancellation bounded.
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    defer _ = c.close(fd);
    if (c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)) < 0 or c.fcntl(fd, c.F.SETFL, @as(c_int, @bitCast(c.O{ .NONBLOCK = true }))) < 0) return error.SocketFailed;
    const address: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (c.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address))) == 0) return true;
    switch (c.errno(-1)) {
        .CONNREFUSED => return false,
        .INPROGRESS, .INTR => {},
        else => return error.ConnectFailed,
    }
    var pollfd: c.pollfd = .{ .fd = fd, .events = c.POLL.OUT, .revents = 0 };
    const count = c.poll(@ptrCast(&pollfd), 1, 100);
    if (count == 0 or (count < 0 and c.errno(-1) == .INTR)) return false;
    if (count < 0) return error.PollFailed;
    var socket_error: c_int = 0;
    var length: c.socklen_t = @sizeOf(c_int);
    if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &socket_error, &length) != 0) return error.SocketFailed;
    return socket_error == 0;
}

/// Returns after registration and TCP listening readiness for proxied apps.
/// The caller owns ready and log_path; the child deliberately outlives this call.
pub fn start(a: A, io: Io, state: []const u8, args: []const []const u8, shorthand: bool, env: *const std.process.Environ.Map) !Started {
    var forwarding = try runner.SignalForwarder.init();
    defer forwarding.deinit();
    var random: [16]u8 = undefined;
    io.random(&random);
    const token = std.fmt.bytesToHex(random, .lower);
    var launch = try Launch.open(a, io, state, &token);
    defer launch.deinit();
    const log = try launch.manager.directory.createFile(io, "app.log", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer log.close(io);
    try log.setPermissions(io, .fromMode(0o600));
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);
    const executable = try std.process.executablePathAlloc(io, a);
    defer a.free(executable);
    try argv.appendSlice(a, &.{ executable, "__background", &token, if (shorthand) "named" else "run" });
    try argv.appendSlice(a, args);
    // Inherit the current group initially so setsid succeeds in the child.
    var child = try std.process.spawn(io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log }, .environ_map = env });
    const identity = process.inspect(child.id.?) catch |err| {
        std.posix.kill(child.id.?, .KILL) catch {};
        _ = runner.reap(io, &child, true) catch {};
        return err;
    };
    errdefer cancel(a, io, state, &child, identity);
    const deadline = Io.Clock.awake.now(io).toNanoseconds() + 30 * std.time.ns_per_s;
    var ready: ?std.json.Parsed(Ready) = null;
    errdefer if (ready) |parsed| parsed.deinit();
    while (true) {
        // Reaping detects an exited supervisor immediately and releases its PID.
        if (try runner.reap(io, &child, false) != null) return error.BackgroundStartFailed;
        if (forwarding.interrupted()) return error.BackgroundStartCancelled;
        if (ready == null) ready = try launch.readReady(identity);
        if (ready) |parsed| if (try appsListening(parsed.value.records)) {
            return .{ .ready = parsed, .log_path = try a.dupe(u8, launch.log_path) };
        };
        if (Io.Clock.awake.now(io).toNanoseconds() >= deadline) return error.BackgroundStartTimeout;
        try Io.sleep(io, .fromMilliseconds(20), .awake);
    }
}
