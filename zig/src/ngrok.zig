//! Optional ngrok CLI adapter. Public exposure occurs only through explicit start().
const std = @import("std");
const process = @import("process.zig");
const runner = @import("runner.zig");
const c = @import("native");
const A = std.mem.Allocator;
const Io = std.Io;
pub const Check = struct {
    allocator: A,
    executable: []u8,
    version: []u8,
    credentials_configured: bool,
    pub fn deinit(self: Check) void {
        self.allocator.free(self.executable);
        self.allocator.free(self.version);
    }
};
pub const Registration = struct { identity: process.Identity, policy: []const u8, url: []const u8 = "" };
pub const Options = struct {
    executable: []const u8 = "/opt/homebrew/bin/ngrok",
    state_dir: []const u8,
    port: u16,
    host_header: []const u8,
    environ_map: ?*const std.process.Environ.Map = null,
    timeout_ms: u32 = 30_000,
    on_spawn: ?*const fn (Registration, ?*anyopaque) anyerror!void = null,
    context: ?*anyopaque = null,
};
fn command(a: A, io: Io, executable: []const u8, args: []const []const u8, environment: ?*const std.process.Environ.Map) !std.process.RunResult {
    if (!std.fs.path.isAbsolute(executable) or std.mem.findScalar(u8, executable, 0) != null) return error.AbsoluteExecutableRequired;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);
    try argv.append(a, executable);
    try argv.appendSlice(a, args);
    return std.process.run(a, io, .{ .argv = argv.items, .environ_map = environment, .stdout_limit = .limited(65536), .stderr_limit = .limited(65536), .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } } });
}
pub fn check(a: A, io: Io, executable: []const u8) !Check {
    return checkWithEnvironment(a, io, executable, null);
}
pub fn checkWithEnvironment(a: A, io: Io, executable: []const u8, environment: ?*const std.process.Environ.Map) !Check {
    const result = try command(a, io, executable, &.{"version"}, environment);
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (!result.term.success()) return error.NgrokUnavailable;
    const version = std.mem.trim(u8, result.stdout, " \r\n\t");
    if (!std.mem.startsWith(u8, version, "ngrok version 3.")) return error.NgrokUpgradeRequired;
    const help = try command(a, io, executable, &.{ "http", "--help" }, environment);
    defer a.free(help.stdout);
    defer a.free(help.stderr);
    for ([_][]const u8{ "--log-format", "--traffic-policy-file", "--inspect" }) |flag| if (!help.term.success() or std.mem.indexOf(u8, help.stdout, flag) == null) return error.NgrokUpgradeRequired;
    var configured = if (environment) |env| if (env.get("NGROK_AUTHTOKEN")) |token| token.len != 0 else false else blk: {
        const token = c.getenv("NGROK_AUTHTOKEN");
        break :blk token != null and std.mem.span(token).len != 0;
    };
    const configuration = try command(a, io, executable, &.{ "config", "check" }, environment);
    defer a.free(configuration.stdout);
    defer a.free(configuration.stderr);
    if (!configuration.term.success() and !configured) return error.NgrokConfigurationInvalid;
    const prefix = "Valid configuration file at ";
    const description = std.mem.trim(u8, configuration.stdout, " \r\n\t");
    if (!configured and std.mem.startsWith(u8, description, prefix)) {
        const path = description[prefix.len..];
        if (!std.fs.path.isAbsolute(path) or std.mem.findScalar(u8, path, 0) != null) return error.NgrokConfigurationInvalid;
        const file = try Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false });
        defer file.close(io);
        var st: c.struct_stat = undefined;
        if (c.fstat(file.handle, &st) != 0 or st.st_uid != process.uid() or (st.st_mode & 0o022) != 0 or (st.st_mode & c.S_IFMT) != c.S_IFREG) return error.UnsafeNgrokConfiguration;
        var file_buffer: [4096]u8 = undefined;
        var file_reader = file.reader(io, &file_buffer);
        const bytes = try file_reader.interface.allocRemaining(a, .limited(1 << 20));
        defer a.free(bytes);
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (!std.mem.startsWith(u8, trimmed, "authtoken:")) continue;
            const token = std.mem.trim(u8, trimmed[10..], " \t\r\"'");
            if (token.len != 0 and token[0] != '#' and !std.mem.eql(u8, token, "null") and !std.mem.eql(u8, token, "~")) configured = true;
        }
    }
    const executable_copy = try a.dupe(u8, executable);
    errdefer a.free(executable_copy);
    return .{ .allocator = a, .executable = executable_copy, .version = try a.dupe(u8, version), .credentials_configured = configured };
}
/// A tunnel URL must be an HTTPS DNS origin, never a documentation/API link or literal address.
pub fn validateURL(url: []const u8) !void {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix) or url.len > 2048) return error.InvalidNgrokURL;
    const host = url[prefix.len..];
    if (host.len == 0 or host.len > 253 or std.mem.findAny(u8, host, "/:@?#[]\\ \r\n\t") != null or std.mem.findScalar(u8, host, '.') == null) return error.InvalidNgrokURL;
    var labels = std.mem.splitScalar(u8, host, '.');
    var alphabetic = false;
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return error.InvalidNgrokURL;
        for (label) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '-') return error.InvalidNgrokURL;
            alphabetic = alphabetic or std.ascii.isAlphabetic(ch);
        }
    }
    if (!alphabetic or std.ascii.eqlIgnoreCase(host, "ngrok.com") or std.ascii.endsWithIgnoreCase(host, ".ngrok.com")) return error.InvalidNgrokURL;
}
/// Parse only a started-tunnel JSON log record; other logged links are not readiness.
pub fn extractURL(a: A, line: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, a, line, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const message = parsed.value.object.get("msg") orelse return null;
    const value = parsed.value.object.get("url") orelse return null;
    if (message != .string or value != .string or !std.mem.eql(u8, message.string, "started tunnel")) return null;
    const normalized = std.mem.trimEnd(u8, value.string, "/");
    try validateURL(normalized);
    return try a.dupe(u8, normalized);
}
pub const Tunnel = struct {
    allocator: A,
    io: Io,
    state_dir: []u8,
    child: std.process.Child,
    registration: Registration,
    stdout_drain: ?Io.Future(void) = null,
    stderr_drain: ?Io.Future(void) = null,
    closed: bool = false,
    cleaned: bool = false,
    pub fn close(self: *Tunnel) !void {
        if (self.cleaned) return;
        defer if (!self.closed) {
            self.child.kill(self.io); // Direct ownership remains valid until reaping.
            if (self.stdout_drain) |*task| task.await(self.io);
            if (self.stderr_drain) |*task| task.await(self.io);
            self.closed = true;
        };
        try clean(self.allocator, self.io, self.state_dir, self.registration);
        self.cleaned = true;
    }
    pub fn deinit(self: *Tunnel) void {
        self.close() catch |err| std.log.err("ngrok cleanup retained for prune: {s}", .{@errorName(err)});
        self.allocator.free(self.registration.url);
        self.allocator.free(self.registration.policy);
        self.allocator.free(self.state_dir);
        self.allocator.destroy(self);
    }
};
/// Creates a separate direct child, then waits for authenticated tunnel readiness.
/// on_spawn journals the exact identity before accepting readiness from its output.
pub fn start(a: A, io: Io, options: Options) !*Tunnel {
    if (options.port == 0 or options.timeout_ms == 0 or options.timeout_ms > 60_000) return error.InvalidNgrokTarget;
    try @import("hosts.zig").validateName(options.host_header, "");
    var preflight = try checkWithEnvironment(a, io, options.executable, options.environ_map);
    defer preflight.deinit();
    if (!preflight.credentials_configured) return error.NgrokAuthenticationRequired;
    var manager = try runner.Manager.open(a, io, options.state_dir);
    defer manager.deinit();
    var random: [16]u8 = undefined;
    io.random(&random);
    const base = try std.fmt.allocPrint(a, "ngrok-policy-{s}.json", .{std.fmt.bytesToHex(random, .lower)});
    defer a.free(base);
    const policy_path = try std.fs.path.join(a, &.{ options.state_dir, base });
    errdefer a.free(policy_path);
    const policy = try std.json.Stringify.valueAlloc(a, .{ .on_http_request = .{.{ .actions = .{.{ .type = "add-headers", .config = .{ .headers = .{ .host = options.host_header } } }} }} }, .{});
    defer a.free(policy);
    const file = try manager.directory.createFile(io, base, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    errdefer manager.directory.deleteFile(io, base) catch {};
    try file.writePositionalAll(io, policy, 0);
    try file.sync(io);
    const target = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}", .{options.port});
    defer a.free(target);
    var child = try std.process.spawn(io, .{ .argv = &.{ options.executable, "http", "--log=stdout", "--log-format=json", "--inspect=false", "--traffic-policy-file", policy_path, target }, .environ_map = options.environ_map, .pgid = 0, .stdin = .ignore, .stdout = .pipe, .stderr = .pipe });
    errdefer child.kill(io);
    const identity = try process.inspect(child.id.?);
    if (identity.uid != process.uid() or identity.pgid != identity.pid) return error.NgrokIdentityConflict;
    if (options.on_spawn) |callback| try callback(.{ .identity = identity, .policy = policy_path }, options.context);
    var buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var reader: Io.File.MultiReader = undefined;
    reader.init(a, io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer reader.deinit();
    const deadline = (Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(options.timeout_ms), .clock = .awake } }).toDeadline(io);
    var url: ?[]u8 = null;
    var offsets: [2]usize = .{ 0, 0 };
    while (url == null) {
        reader.fill(256, deadline) catch |err| return switch (err) {
            error.Timeout => error.NgrokStartupTimeout,
            error.EndOfStream => error.NgrokStartupFailed,
            else => err,
        };
        for (0..2) |index| {
            const bytes = reader.reader(index).buffered();
            if (bytes.len > 64 << 10) return error.NgrokOutputLimit;
            while (std.mem.findScalar(u8, bytes[offsets[index]..], '\n')) |count| {
                const line = std.mem.trimEnd(u8, bytes[offsets[index] .. offsets[index] + count], "\r");
                offsets[index] += count + 1;
                if (std.mem.indexOf(u8, line, "ERR_NGROK_4018") != null or std.mem.indexOf(u8, line, "authentication failed") != null or std.mem.indexOf(u8, line, "ERR_NGROK_105") != null) return error.NgrokAuthenticationRejected;
                if (try extractURL(a, line)) |found| {
                    url = found;
                    break;
                }
            }
            if (url != null) break;
        }
    }
    errdefer a.free(url.?);
    const ready_identity = try process.inspect(identity.pid);
    if (ready_identity.uid != identity.uid or ready_identity.start != identity.start or ready_identity.pgid != identity.pgid) return error.NgrokIdentityConflict;
    const self = try a.create(Tunnel);
    errdefer a.destroy(self);
    self.* = .{ .allocator = a, .io = io, .state_dir = try a.dupe(u8, options.state_dir), .child = child, .registration = .{ .identity = identity, .policy = policy_path, .url = url.? } };
    errdefer a.free(self.state_dir);
    self.stdout_drain = try process.drainPipe(io, child.stdout.?);
    errdefer {
        child.kill(io);
        self.stdout_drain.?.await(io);
    }
    self.stderr_drain = try process.drainPipe(io, child.stderr.?);
    return self;
}
pub fn clean(a: A, io: Io, state_dir: []const u8, registration: Registration) !void {
    const identity = registration.identity;
    if (identity.uid != process.uid() or identity.pid <= 0 or identity.start <= 0 or identity.pgid != identity.pid) return error.NgrokIdentityConflict;
    if (registration.url.len != 0) try validateURL(registration.url);
    const base = std.fs.path.basename(registration.policy);
    if (!std.mem.eql(u8, std.fs.path.dirname(registration.policy) orelse "", state_dir) or !std.mem.startsWith(u8, base, "ngrok-policy-") or !std.mem.endsWith(u8, base, ".json") or base.len != 50) return error.InvalidNgrokRegistration;
    for (base[13..45]) |ch| if (!std.ascii.isHex(ch)) return error.InvalidNgrokRegistration;
    const live = process.inspect(identity.pid) catch |err| switch (err) {
        error.ProcessGone => null,
        else => return err,
    };
    if (live) |current| if (current.uid != identity.uid or current.start != identity.start or current.pgid != identity.pgid) return error.NgrokIdentityConflict;
    var manager = try runner.Manager.open(a, io, state_dir);
    defer manager.deinit();
    const file = manager.directory.openFile(io, base, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (file) |opened| opened.close(io);
    if (file) |opened| try process.validateOwned(opened.handle, 0o600, false);
    if (live != null) {
        try process.signal(identity, .TERM);
        const deadline = Io.Clock.awake.now(io).nanoseconds + 2 * std.time.ns_per_s;
        while (try stillOwned(identity)) {
            if (Io.Clock.awake.now(io).nanoseconds >= deadline) {
                try process.signal(identity, .KILL);
                break;
            }
            try Io.sleep(io, .fromMilliseconds(25), .awake);
        }
        const killed_deadline = Io.Clock.awake.now(io).nanoseconds + 2 * std.time.ns_per_s;
        while (try stillOwned(identity)) {
            if (Io.Clock.awake.now(io).nanoseconds >= killed_deadline) return error.NgrokCleanupTimeout;
            try Io.sleep(io, .fromMilliseconds(25), .awake);
        }
    }
    if (file != null) {
        try manager.directory.deleteFile(io, base);
        const directory_file: Io.File = .{ .handle = manager.directory.handle, .flags = .{ .nonblocking = false } };
        try directory_file.sync(io);
    }
}
fn stillOwned(identity: process.Identity) !bool {
    const current = process.inspect(identity.pid) catch |err| switch (err) {
        error.ProcessGone => return false,
        else => return err,
    };
    if (current.uid != identity.uid or current.start != identity.start or current.pgid != identity.pgid) return error.NgrokIdentityConflict;
    return true;
}
