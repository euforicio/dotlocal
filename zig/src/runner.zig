//! Direct argv execution and a private, durable registry of exact process identities.
const std = @import("std");
const osprocess = @import("process.zig");
pub const projectconfig = @import("projectconfig.zig");
const protocol = @import("protocol.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const native = @import("native");

pub const Identity = struct { pid: c_int, start: i64 };
pub const Endpoint = struct { name: []const u8, proxy: bool, host: []const u8 = "", port: u16 = 0, url: []const u8 = "" };
pub const Record = struct {
    endpoint: Endpoint,
    identity: Identity,
    process_group: c_int,
    uid: u32,
    supervisor: Identity,
    supervisor_uid: u32,
    working_directory: []const u8,
    pub fn liveIdentity(self: Record) osprocess.Identity {
        return .{ .pid = self.identity.pid, .start = self.identity.start, .uid = self.uid, .pgid = self.process_group };
    }
    pub fn owner(self: Record) protocol.Owner {
        return .{ .kind = "process", .pid = self.identity.pid, .process_start = self.identity.start };
    }
    pub fn route(self: Record) protocol.Route {
        return .{ .name = self.endpoint.name, .host = self.endpoint.host, .port = self.endpoint.port, .owner = self.owner() };
    }
};
pub const State = struct { version: u32 = 1, records: []const Record = &.{} };
pub const Status = enum { active, orphaned, stale };
pub const Discovery = struct { record: Record, status: Status };
pub const Options = struct {
    name: []const u8,
    argv: []const []const u8,
    state_directory: []const u8,
    app_port: ?u16 = null,
    environment: ?*const std.process.Environ.Map = null,
    base_environment: ?*const std.process.Environ.Map = null,
    working_directory: ?[]const u8 = null,
    proxy: bool = true,
    force: bool = false,
    stop_timeout_ms: u32 = 5000,
    suspend_until_registered: bool = false,
    before_start: ?*const fn (Endpoint, *std.process.Environ.Map, ?*anyopaque) anyerror!void = null,
    on_prepare_failure: ?*const fn (?*anyopaque) void = null,
    inject_framework_flags: bool = false,
    lan: bool = false,
    after_start: ?*const fn (*Process, ?*anyopaque) anyerror!void = null,
    after_exit: ?*const fn (*Process, ?*anyopaque) void = null,
    hook_context: ?*anyopaque = null,
    node_extra_ca_certs: ?[]const u8 = null,
    vite_allowed_hosts: ?[]const u8 = null,
    tld: []const u8 = @import("routes.zig").default_tld,
    public_url: ?[]const u8 = null,
    stdin: std.process.SpawnOptions.StdIo = .inherit,
    stdout: std.process.SpawnOptions.StdIo = .inherit,
    stderr: std.process.SpawnOptions.StdIo = .inherit,
};
pub const Result = struct {
    identity: Identity,
    term: std.process.Child.Term,
    pub fn exitCode(self: Result) u8 {
        return switch (self.term) {
            .exited => |code| code,
            .signal => |sig| @intCast(128 + @backingInt(sig)),
            else => 1,
        };
    }
};

pub const Manager = struct {
    allocator: Allocator,
    io: Io,
    directory: Io.Dir,
    pub fn open(allocator: Allocator, io: Io, path: []const u8) !Manager {
        if (!std.fs.path.isAbsolute(path)) return error.RelativeStateDirectory;
        const dir = try openPrivateDirectory(io, path);
        errdefer dir.close(io);
        try osprocess.validateOwned(dir.handle, 0o700, true);
        const self: Manager = .{ .allocator = allocator, .io = io, .directory = dir };
        const held = try self.lock();
        defer held.close(io);
        var state = try self.read();
        defer state.deinit();
        return self;
    }
    pub fn deinit(self: *Manager) void {
        self.directory.close(self.io);
    }
    fn lock(self: Manager) !Io.File {
        const file = self.directory.createFile(self.io, "runner.lock", .{ .exclusive = true, .truncate = false, .read = true, .permissions = .fromMode(0o600) }) catch |err| blk: {
            if (err != error.PathAlreadyExists) return err;
            break :blk try self.directory.openFile(self.io, "runner.lock", .{ .mode = .read_write, .follow_symlinks = false });
        };
        errdefer file.close(self.io);
        try osprocess.validateOwned(file.handle, 0o600, false);
        try file.lock(self.io, .exclusive);
        return file;
    }
    fn read(self: Manager) !std.json.Parsed(State) {
        const file = self.directory.openFile(self.io, "runner.json", .{ .follow_symlinks = false }) catch |err| {
            if (err != error.FileNotFound) return err;
            return std.json.parseFromSlice(State, self.allocator, "{\"version\":1,\"records\":[]}", .{ .allocate = .alloc_always });
        };
        defer file.close(self.io);
        try osprocess.validateOwned(file.handle, 0o600, false);
        var buffer: [4096]u8 = undefined;
        var reader = file.reader(self.io, &buffer);
        const data = try reader.interface.allocRemaining(self.allocator, .limited(1024 * 1024));
        defer self.allocator.free(data);
        const state = try std.json.parseFromSlice(State, self.allocator, data, .{ .allocate = .alloc_always });
        errdefer state.deinit();
        try validateState(self.allocator, state.value);
        std.mem.sort(Record, @constCast(state.value.records), {}, lessRecord);
        return state;
    }
    fn write(self: Manager, state: State) !void {
        try validateState(self.allocator, state);
        const sorted = try self.allocator.dupe(Record, state.records);
        defer self.allocator.free(sorted);
        std.mem.sort(Record, sorted, {}, lessRecord);
        const data = try std.json.Stringify.valueAlloc(self.allocator, State{ .version = state.version, .records = sorted }, .{ .whitespace = .indent_2 });
        defer self.allocator.free(data);
        if (data.len > 1024 * 1024) return error.StateTooLarge;
        var atomic = try self.directory.createFileAtomic(self.io, "runner.json", .{ .permissions = .fromMode(0o600), .replace = true });
        defer atomic.deinit(self.io);
        try atomic.file.writeStreamingAll(self.io, data);
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
        const dir_file: Io.File = .{ .handle = self.directory.handle, .flags = .{ .nonblocking = false } };
        try dir_file.sync(self.io);
    }
    pub fn records(self: Manager) !std.json.Parsed(State) {
        const held = try self.lock();
        defer held.close(self.io);
        return self.read();
    }
    pub fn removeMatching(self: Manager, name: []const u8, identity: Identity) !void {
        const held = try self.lock();
        defer held.close(self.io);
        var state = try self.read();
        defer state.deinit();
        var retained: std.ArrayList(Record) = .empty;
        for (state.value.records) |record| {
            if (std.mem.eql(u8, record.endpoint.name, name) and record.identity.pid == identity.pid and record.identity.start == identity.start) continue;
            try retained.append(state.arena.allocator(), record);
        }
        if (retained.items.len == state.value.records.len) return;
        state.value.records = retained.items;
        try self.write(state.value);
    }
    pub fn prune(self: Manager) !usize {
        const held = try self.lock();
        defer held.close(self.io);
        var state = try self.read();
        defer state.deinit();
        var retained: std.ArrayList(Record) = .empty;
        for (state.value.records) |record| if (try alive(record)) {
            try retained.append(state.arena.allocator(), record);
        };
        const removed = state.value.records.len - retained.items.len;
        if (removed > 0) {
            state.value.records = retained.items;
            try self.write(state.value);
        }
        return removed;
    }
    pub fn forceTakeover(self: Manager, route: protocol.Route, grace_ms: u32) !void {
        try route.validate(self.allocator, "");
        if (!std.mem.eql(u8, route.owner.kind, "process") or route.owner.process_start <= 0) return error.IdentityMismatch;
        var state = try self.records();
        defer state.deinit();
        const record = find(state.value, route.name) orelse return error.NotTracked;
        if (!record.owner().eql(route.owner) or !record.endpoint.proxy or !std.mem.eql(u8, record.endpoint.host, route.host) or record.endpoint.port != route.port) return error.IdentityMismatch;
        try self.stopRecord(record, grace_ms);
    }
    /// Stop only the exact locally tracked app group, then remove its record.
    /// The supervisor remains responsible for reaping and route/exposure cleanup.
    pub fn stopRecord(self: Manager, record: Record, grace_ms: u32) !void {
        var state = try self.records();
        defer state.deinit();
        const current = find(state.value, record.endpoint.name) orelse return error.NotTracked;
        if (!current.owner().eql(record.owner()) or current.uid != record.uid or current.process_group != record.process_group) return error.IdentityMismatch;
        if (!(try alive(record))) {
            try self.removeMatching(record.endpoint.name, record.identity);
            return;
        }
        // The group may exit, or its supervisor reap it, between checks.
        try signalLive(record, .TERM);
        const deadline = Io.Clock.awake.now(self.io).toNanoseconds() + @as(i96, grace_ms) * 1_000_000;
        var killed = false;
        const kill_deadline = deadline + 5_000_000_000;
        while (try alive(record)) {
            const now = Io.Clock.awake.now(self.io).toNanoseconds();
            if (now >= deadline and !killed) {
                try signalLive(record, .KILL);
                killed = true;
            }
            if (now >= kill_deadline) return error.StopTimeout;
            try Io.sleep(self.io, .fromMilliseconds(20), .awake);
        }
        try self.removeMatching(record.endpoint.name, record.identity);
    }
};

fn signalLive(record: Record, sig: std.posix.SIG) !void {
    osprocess.signal(record.liveIdentity(), sig) catch |err| if (err != error.ProcessGone) return err;
}

fn lessRecord(_: void, a: Record, b: Record) bool {
    return std.mem.lessThan(u8, a.endpoint.name, b.endpoint.name);
}

fn openPrivateDirectory(io: Io, path: []const u8) !Io.Dir {
    // Walk with no-follow directory handles, so a symlink in a parent cannot
    // redirect either creation or subsequent registry access.
    var parent = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer parent.close(io);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    var part = components.next() orelse return error.InvalidStateDirectory;
    while (true) {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidStateDirectory;
        if (components.next()) |next| {
            const child = parent.openDir(io, part, .{ .follow_symlinks = false }) catch |err| blk: {
                if (err != error.FileNotFound) return err;
                try parent.createDir(io, part, .fromMode(0o700));
                break :blk try parent.openDir(io, part, .{ .follow_symlinks = false });
            };
            parent.close(io);
            parent = child;
            part = next;
        } else {
            parent.createDir(io, part, .fromMode(0o700)) catch |err| if (err != error.PathAlreadyExists) return err;
            return parent.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
        }
    }
}

fn find(state: State, name: []const u8) ?Record {
    for (state.records) |record| if (std.mem.eql(u8, record.endpoint.name, name)) return record;
    return null;
}
// Records always name this user's processes. A reused PID that another user
// owns is denied inspection, and is therefore not the recorded process.
fn alive(record: Record) !bool {
    const live = osprocess.inspect(record.identity.pid) catch |err| switch (err) {
        error.ProcessGone => return false,
        else => return err,
    };
    return live.uid == record.uid and live.start == record.identity.start and live.pgid == record.process_group;
}
pub fn classify(record: Record) !Status {
    if (!(try alive(record))) return .stale;
    const supervisor = osprocess.inspect(record.supervisor.pid) catch |err| switch (err) {
        error.ProcessGone => return .orphaned,
        else => return err,
    };
    return if (supervisor.uid == record.supervisor_uid and supervisor.start == record.supervisor.start) .active else .orphaned;
}
fn validateState(allocator: Allocator, state: State) !void {
    if (state.version != 1 or state.records.len > 1024) return error.InvalidState;
    for (state.records, 0..) |record, i| {
        const separator = std.mem.lastIndexOfScalar(u8, record.endpoint.name, '.') orelse return error.InvalidState;
        const name = try projectconfig.normalizeName(allocator, record.endpoint.name, record.endpoint.name[separator..]);
        defer allocator.free(name);
        if (!std.mem.eql(u8, name, record.endpoint.name)) return error.InvalidState;
        for (state.records[0..i]) |previous| if (std.mem.eql(u8, previous.endpoint.name, name)) return error.InvalidState;
        if (record.identity.pid <= 0 or record.identity.start <= 0 or record.process_group != record.identity.pid or record.uid != osprocess.uid() or record.supervisor.pid <= 0 or record.supervisor.start <= 0 or record.supervisor_uid != osprocess.uid() or !std.fs.path.isAbsolute(record.working_directory)) return error.InvalidState;
        if (record.endpoint.proxy) {
            if (!std.mem.eql(u8, record.endpoint.host, "127.0.0.1") or record.endpoint.port == 0) return error.InvalidState;
            try validateURL(allocator, record.endpoint.url, name);
        } else if (record.endpoint.host.len != 0 or record.endpoint.port != 0 or record.endpoint.url.len != 0) return error.InvalidState;
    }
}
fn validateURL(_: Allocator, url: []const u8, name: []const u8) !void {
    const parsed = std.Uri.parse(url) catch return error.InvalidPublicURL;
    if ((!std.mem.eql(u8, parsed.scheme, "http") and !std.mem.eql(u8, parsed.scheme, "https")) or parsed.user != null or parsed.password != null or !parsed.path.isEmpty() or parsed.query != null or parsed.fragment != null or (parsed.port != null and parsed.port.? == 0)) return error.InvalidPublicURL;
    const host = parsed.host orelse return error.InvalidPublicURL;
    const bytes = switch (host) {
        .raw, .percent_encoded => |v| v,
    };
    if (!std.mem.eql(u8, bytes, name)) return error.InvalidPublicURL;
}

var pending_signals: std.atomic.Value(u32) = .init(0);
var forwarding_in_use: std.atomic.Value(bool) = .init(false);
var wake_write: std.atomic.Value(c_int) = .init(-1);
fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    // Only async-signal-safe work occurs here: an atomic store and a
    // nonblocking self-pipe write that wakes the supervision loop. Process
    // inspection, signaling, and file work happen in that loop.
    if (sig != .CHLD) _ = pending_signals.fetchOr(pendingBit(sig), .release);
    const fd = wake_write.load(.acquire);
    if (fd < 0) return;
    const saved = std.c._errno().*;
    _ = std.c.write(fd, "x", 1);
    std.c._errno().* = saved;
}
/// Owns the process-wide forwarding handlers and a self-pipe that wakes the
/// supervisor on a forwarded signal or any SIGCHLD, so it blocks instead of polling.
pub const SignalForwarder = struct {
    const signals = [_]std.posix.SIG{ .HUP, .INT, .QUIT, .TERM };
    const handled = signals ++ [_]std.posix.SIG{.CHLD};
    old: [handled.len]std.posix.Sigaction,
    wake: [2]c_int,
    pub fn init() !SignalForwarder {
        if (forwarding_in_use.swap(true, .acq_rel)) return error.SignalForwardingInUse;
        errdefer forwarding_in_use.store(false, .release);
        var result: SignalForwarder = undefined;
        if (native.pipe(&result.wake) != 0) return error.SystemResources;
        errdefer for (result.wake) |fd| {
            _ = std.c.close(fd);
        };
        for (result.wake) |fd| {
            if (native.fcntl(fd, native.F_SETFD, @as(c_int, native.FD_CLOEXEC)) != 0) return error.SystemResources;
            const flags = native.fcntl(fd, native.F_GETFL);
            if (flags < 0 or native.fcntl(fd, native.F_SETFL, flags | native.O_NONBLOCK) != 0) return error.SystemResources;
        }
        pending_signals.store(0, .release);
        wake_write.store(result.wake[1], .release);
        const action: std.posix.Sigaction = .{ .handler = .{ .handler = signalHandler }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
        for (handled, 0..) |sig, i| std.posix.sigaction(sig, &action, &result.old[i]);
        return result;
    }
    pub fn deinit(self: *SignalForwarder) void {
        for (handled, 0..) |sig, i| std.posix.sigaction(sig, &self.old[i], null);
        wake_write.store(-1, .release);
        for (self.wake) |fd| _ = std.c.close(fd);
        forwarding_in_use.store(false, .release);
    }
    /// Blocks until a handled signal arrives or `timeout_ms` elapses (-1 waits
    /// indefinitely), then drains the pipe. Callers re-check state after waking.
    fn wait(self: *SignalForwarder, timeout_ms: i32) !void {
        var fds = [_]std.posix.pollfd{.{ .fd = self.wake[0], .events = std.posix.POLL.IN, .revents = 0 }};
        _ = try std.posix.poll(&fds, timeout_ms);
        var buffer: [64]u8 = undefined;
        while (std.c.read(self.wake[0], &buffer, buffer.len) > 0) {}
    }
    /// Startup loops can cancel safely outside the signal handler.
    pub fn interrupted(_: *SignalForwarder) bool {
        return pending_signals.swap(0, .acq_rel) != 0;
    }
};

fn pendingBit(sig: std.posix.SIG) u32 {
    return @as(u32, 1) << @intCast(@backingInt(sig));
}
const terminating = pendingBit(.INT) | pendingBit(.QUIT) | pendingBit(.TERM);

/// An interactive child reading an inherited terminal must be its foreground
/// group, or the kernel stops it with SIGTTIN. Only a foreground supervisor with
/// a terminal stdin hands the terminal over; release gives it back.
const Foreground = struct {
    previous: native.pid_t,
    group: native.pid_t,
    /// Whether the child group currently owns the terminal through this handoff.
    held: bool = true,
    fn acquire(stdin: std.process.SpawnOptions.StdIo, group: c_int) ?Foreground {
        if (stdin != .inherit or native.isatty(0) != 1) return null;
        const current = native.tcgetpgrp(0);
        if (current <= 0 or current != native.getpgrp()) return null;
        if (!setForeground(group)) return null;
        return .{ .previous = current, .group = group };
    }
    fn release(self: *Foreground) void {
        if (self.held) _ = setForeground(self.previous);
        self.held = false;
    }
    /// Job-control passthrough for a child stopped by Ctrl-Z: return the
    /// terminal, stop this supervisor's group so the shell sees the job stop,
    /// and after SIGCONT give the terminal back only if the shell resumed the
    /// job in the foreground (`fg`, not `bg`), then continue the child group.
    /// SIGSTOP, unlike SIGTSTP, also stops an orphaned group such as a session leader.
    fn suspendWithChild(self: *Foreground, child: *const std.process.Child, identity: osprocess.Identity) void {
        self.release();
        _ = std.c.kill(0, .STOP);
        if (native.tcgetpgrp(0) == native.getpgrp()) self.held = setForeground(self.group);
        deliver(child, identity, .CONT);
    }
    /// A background caller may set the foreground group only with SIGTTOU blocked.
    fn setForeground(group: native.pid_t) bool {
        var block = std.posix.sigemptyset();
        std.posix.sigaddset(&block, .TTOU);
        var previous: std.posix.sigset_t = undefined;
        _ = std.c.pthread_sigmask(native.SIG_BLOCK, &block, &previous);
        defer _ = std.c.pthread_sigmask(native.SIG_SETMASK, &previous, &block);
        return native.tcsetpgrp(0, group) == 0;
    }
};
/// Reaps only on the supervising thread. Until this returns a term the PID is
/// this process's unreaped child, so it cannot be reused under a signal.
pub fn reap(io: Io, child: *std.process.Child, block: bool) !?std.process.Child.Term {
    return waitChild(io, child, if (block) 0 else std.c.W.NOHANG);
}
/// With WUNTRACED a stop is returned as `.stopped` and the child stays owned.
fn waitChild(io: Io, child: *std.process.Child, flags: c_int) !?std.process.Child.Term {
    const pid = child.id orelse return error.ProcessGone;
    var status: c_int = 0;
    while (true) {
        const rc = std.c.waitpid(pid, &status, flags);
        if (rc == pid) break;
        if (rc == 0) return null;
        switch (std.c.errno(rc)) {
            .INTR => {},
            // Already reaped elsewhere: forget the PID so it is never signalled after reuse.
            .CHILD => {
                release(io, child);
                return error.ProcessGone;
            },
            else => return error.WaitFailed,
        }
    }
    const term = Io.Threaded.statusToTerm(@bitCast(status));
    if (term != .stopped) release(io, child);
    return term;
}
fn release(io: Io, child: *std.process.Child) void {
    inline for (.{ "stdin", "stdout", "stderr" }) |field| if (@field(child, field)) |file| {
        file.close(io);
        @field(child, field) = null;
    };
    child.id = null;
}

/// Delivers to the verified group, falling back to the unreaped child PID when
/// it has left that group. Delivery failure never aborts supervision.
fn deliver(child: *const std.process.Child, identity: ?osprocess.Identity, sig: std.posix.SIG) void {
    if (identity) |group| if (osprocess.signal(group, sig)) return else |_| {};
    if (child.id) |pid| std.posix.kill(pid, sig) catch {};
}

fn forward(child: *const std.process.Child, identity: osprocess.Identity, pending: u32) void {
    for (SignalForwarder.signals) |sig| if (pending & pendingBit(sig) != 0) deliver(child, identity, sig);
}

/// Child.kill sends SIGTERM and blocks uncancelably; a child that ignores TERM,
/// is stopped, or left its group would hang it. SIGKILL by PID cannot.
fn terminate(io: Io, child: *std.process.Child, identity: ?osprocess.Identity) void {
    const pid = child.id orelse return;
    if (identity) |group| osprocess.signal(group, .KILL) catch {};
    std.posix.kill(pid, .KILL) catch {};
    _ = reap(io, child, true) catch {};
}

fn deadlineAfter(io: Io, ms: u32) i96 {
    return Io.Clock.awake.now(io).toNanoseconds() + @as(i96, ms) * std.time.ns_per_ms;
}

/// Milliseconds until `deadline` for poll, rounded up; -1 without a deadline.
fn pollTimeout(io: Io, deadline: ?i96) i32 {
    const limit = deadline orelse return -1;
    const remaining = limit - Io.Clock.awake.now(io).toNanoseconds();
    if (remaining <= 0) return 0;
    return @intCast(@min(std.math.divCeil(i96, remaining, std.time.ns_per_ms) catch unreachable, std.math.maxInt(i32)));
}

/// Forward signals to one child's group, escalate to SIGKILL `grace_ms` after
/// the first terminating signal, and reap it on this thread. Sleeps until a
/// signal or SIGCHLD arrives, waking on a timer only for the grace deadline.
/// With a terminal handoff, a stopped child suspends the supervisor too.
fn supervise(io: Io, forwarding: *SignalForwarder, child: *std.process.Child, identity: osprocess.Identity, grace_ms: u32, terminal: ?*Foreground) !std.process.Child.Term {
    var deadline: ?i96 = null;
    var killed = false;
    const flags: c_int = if (terminal != null) std.c.W.NOHANG | std.c.W.UNTRACED else std.c.W.NOHANG;
    while (true) {
        if (try waitChild(io, child, flags)) |term| {
            if (term != .stopped) return term;
            terminal.?.suspendWithChild(child, identity);
            continue;
        }
        const pending = pending_signals.swap(0, .acq_rel);
        forward(child, identity, pending);
        if (deadline == null and pending & terminating != 0) deadline = deadlineAfter(io, grace_ms);
        if (deadline) |limit| if (!killed and Io.Clock.awake.now(io).toNanoseconds() >= limit) {
            deliver(child, identity, .KILL);
            killed = true;
        };
        try forwarding.wait(pollTimeout(io, if (killed) null else deadline));
    }
}

pub const Process = struct {
    arena: std.heap.ArenaAllocator,
    manager: Manager,
    child: std.process.Child,
    record: Record,
    result: ?Result = null,
    pub fn signal(self: *Process, sig: std.posix.SIG) !void {
        if (self.result != null) return error.ProcessGone;
        try osprocess.signal(self.record.liveIdentity(), sig);
    }
    fn finish(self: *Process, term: std.process.Child.Term) Result {
        const result: Result = .{ .identity = self.record.identity, .term = term };
        self.result = result;
        self.manager.removeMatching(self.record.endpoint.name, self.record.identity) catch |err| std.log.warn("runner state cleanup: {s}", .{@errorName(err)});
        return result;
    }
    pub fn wait(self: *Process) !Result {
        if (self.result) |result| return result;
        return self.finish(try self.child.wait(self.manager.io));
    }
    pub fn waitWithSignals(self: *Process, grace_ms: u32) !Result {
        var forwarding = try SignalForwarder.init();
        defer forwarding.deinit();
        return self.waitForwarded(&forwarding, grace_ms);
    }
    pub fn waitForwarded(self: *Process, forwarding: *SignalForwarder, grace_ms: u32) !Result {
        return self.waitTerminal(forwarding, grace_ms, null);
    }
    fn waitTerminal(self: *Process, forwarding: *SignalForwarder, grace_ms: u32, terminal: ?*Foreground) !Result {
        if (self.result) |result| return result;
        return self.finish(try supervise(self.manager.io, forwarding, &self.child, self.record.liveIdentity(), grace_ms, terminal));
    }
    pub fn deinit(self: *Process) void {
        if (self.child.id != null) {
            terminate(self.manager.io, &self.child, self.record.liveIdentity());
            self.manager.removeMatching(self.record.endpoint.name, self.record.identity) catch {};
        }
        self.manager.deinit();
        self.arena.deinit();
    }
};

fn inheritedEnvironment(allocator: Allocator) !std.process.Environ.Map {
    // Library consumers can pass their std.process.Init map explicitly. The
    // default snapshots libc's real environment through the current Environ API.
    const environ: std.process.Environ = .{ .block = .{ .slice = std.mem.span(std.c.environ) } };
    return environ.createMap(allocator);
}

pub fn start(allocator: Allocator, io: Io, options: Options) !Process {
    if (options.argv.len == 0 or options.argv.len > 256 or options.argv[0].len == 0) return error.InvalidCommand;
    for (options.argv) |arg| if (arg.len > 32 * 1024 or std.mem.findScalar(u8, arg, 0) != null) return error.InvalidArgument;
    if (!options.proxy and options.app_port != null and options.app_port.? != 0) return error.PortRequiresProxy;
    if (!options.proxy and options.public_url != null) return error.PublicURLRequiresProxy;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const name = try projectconfig.normalizeName(owned, options.name, options.tld);
    const cwd = try Io.Dir.cwd().realPathFileAlloc(io, options.working_directory orelse ".", owned);
    const cwd_dir = try Io.Dir.openDirAbsolute(io, cwd, .{});
    defer cwd_dir.close(io);
    errdefer if (options.on_prepare_failure) |callback| callback(options.hook_context);
    var manager = try Manager.open(allocator, io, options.state_directory);
    errdefer manager.deinit();
    {
        var preflight = try manager.records();
        defer preflight.deinit();
        if (find(preflight.value, name)) |record| if (try alive(record)) return error.AlreadyRunning;
    }

    var env = if (options.base_environment) |base| try base.clone(allocator) else try inheritedEnvironment(allocator);
    defer env.deinit();
    if (options.environment) |configured| {
        if (configured.count() > 256) return error.TooManyEnvironmentEntries;
        var it = configured.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            try projectconfig.validateEnvironmentKey(key);
            if (std.mem.eql(u8, key, "PORT") or std.mem.eql(u8, key, "HOST") or std.mem.eql(u8, key, "DOTLOCAL_URL") or std.mem.eql(u8, key, "NODE_EXTRA_CA_CERTS")) return error.ManagedEnvironmentKey;
            if (value.len > 32 * 1024 or std.mem.findScalar(u8, value, 0) != null) return error.InvalidEnvironmentValue;
            try env.put(key, value);
        }
    }
    var endpoint: Endpoint = .{ .name = name, .proxy = options.proxy };
    var reservation: ?Io.net.Server = null;
    defer if (reservation) |*listener| listener.deinit(io);
    if (options.proxy) {
        const address = try Io.net.IpAddress.parse("127.0.0.1", options.app_port orelse 0);
        reservation = try address.listen(io, .{});
        endpoint.host = "127.0.0.1";
        endpoint.port = reservation.?.socket.address.ip4.port;
        endpoint.url = try owned.dupe(u8, options.public_url orelse try std.fmt.allocPrint(owned, "https://{s}", .{name}));
        try validateURL(allocator, endpoint.url, name);
        var port_buf: [5]u8 = undefined;
        try env.put("PORT", try std.fmt.bufPrint(&port_buf, "{d}", .{endpoint.port}));
        const framework = if (options.lan and options.inject_framework_flags) try @import("framework.zig").resolveBasename(owned, io, cwd, options.argv) else null;
        if (framework != null and std.mem.eql(u8, framework.?, "expo")) {
            _ = env.swapRemove("HOST");
        } else try env.put("HOST", endpoint.host);
        try env.put("DOTLOCAL_URL", endpoint.url);
        if (options.vite_allowed_hosts) |hosts| try env.put("__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS", hosts);
    }
    if (options.node_extra_ca_certs) |path| {
        if (!options.proxy or !std.fs.path.isAbsolute(path)) return error.InvalidCAPath;
        const file = try Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false });
        defer file.close(io);
        if ((try file.stat(io)).kind != .file) return error.InvalidCAPath;
        if (env.get("NODE_EXTRA_CA_CERTS") == null or env.get("NODE_EXTRA_CA_CERTS").?.len == 0) try env.put("NODE_EXTRA_CA_CERTS", path);
    }
    if (options.before_start) |callback| try callback(endpoint, &env, options.hook_context);
    const argv = if (options.inject_framework_flags and options.proxy) try @import("framework.zig").injectScriptFlags(owned, io, cwd, options.argv, endpoint.port, options.lan) else options.argv;
    const held = try manager.lock();
    defer held.close(io);
    var state = try manager.read();
    defer state.deinit();
    if (find(state.value, name)) |record| if (try alive(record)) return error.AlreadyRunning;
    // Hold the reservation until immediately before direct execution. Generic
    // frameworks cannot inherit the reservation and bind that same TCP port.
    if (reservation) |*listener| listener.deinit(io);
    reservation = null;
    var child = try osprocess.spawnSuspended(owned, io, .{ .argv = argv, .cwd = .{ .dir = cwd_dir }, .environ_map = &env, .pgid = 0, .start_suspended = true, .stdin = options.stdin, .stdout = options.stdout, .stderr = options.stderr });
    errdefer terminate(io, &child, null);
    const identity = try osprocess.inspect(child.id.?);
    if (identity.pgid != identity.pid or identity.uid != osprocess.uid()) return error.IdentityMismatch;
    const supervisor = try osprocess.current();
    const record: Record = .{ .endpoint = endpoint, .identity = .{ .pid = identity.pid, .start = identity.start }, .process_group = identity.pgid, .uid = identity.uid, .supervisor = .{ .pid = supervisor.pid, .start = supervisor.start }, .supervisor_uid = supervisor.uid, .working_directory = cwd };
    var retained: std.ArrayList(Record) = .empty;
    for (state.value.records) |existing| if (!std.mem.eql(u8, existing.endpoint.name, name)) {
        try retained.append(state.arena.allocator(), existing);
    };
    try retained.append(state.arena.allocator(), record);
    state.value.records = retained.items;
    try manager.write(state.value);
    if (!options.suspend_until_registered) try osprocess.signal(identity, .CONT);
    return .{ .arena = arena, .manager = manager, .child = child, .record = record };
}

/// With --force, stops this user's tracked owner of the name and returns the
/// listing that owns `expected`'s strings; it must outlive the add call.
fn takeover(allocator: Allocator, io: Io, client: anytype, option: Options, expected: *?protocol.Owner) !?std.json.Parsed(protocol.Response) {
    if (option.force and !option.proxy) return error.ForceRequiresProxy;
    if (!option.force) return null;
    const name = try projectconfig.normalizeName(allocator, option.name, option.tld);
    defer allocator.free(name);
    const list = try client.call(.{ .id = "", .operation = "list" });
    errdefer list.deinit();
    for (list.value.routes orelse &.{}) |route| if (std.mem.eql(u8, route.name, name)) {
        var manager = try Manager.open(allocator, io, option.state_directory);
        defer manager.deinit();
        try manager.forceTakeover(route, option.stop_timeout_ms);
        expected.* = route.owner;
    };
    return list;
}

/// The management daemon observes and supplies the canonical kernel identity
/// itself; clients may not claim a process_start during add. The canonical
/// owner must equal the durable record, so later removal uses the record.
fn register(client: anytype, child: *const Process, expected: ?protocol.Owner, registered: *bool) !void {
    var route = child.record.route();
    route.owner.process_start = 0;
    const response = try client.call(.{ .id = "", .operation = "add", .route = route, .match = if (expected != null) "owner" else "absent", .expected_owner = expected });
    defer response.deinit();
    registered.* = true;
    const canonical = response.value.route orelse return error.MissingCanonicalRoute;
    if (!std.mem.eql(u8, canonical.name, child.record.endpoint.name) or !std.mem.eql(u8, canonical.scheme, "http") or !std.mem.eql(u8, canonical.host, child.record.endpoint.host) or canonical.port != child.record.endpoint.port or !canonical.owner.eql(child.record.owner())) return error.InvalidCanonicalRoute;
}

fn unregister(client: anytype, child: *const Process, registered: *bool) void {
    if (!registered.*) return;
    if (client.call(.{ .id = "", .operation = "remove", .name = child.record.endpoint.name, .match = "owner", .expected_owner = child.record.owner() })) |removed| {
        removed.deinit();
        registered.* = false;
    } else |err| std.log.warn("runner route cleanup: {s}", .{@errorName(err)});
}

pub fn run(allocator: Allocator, io: Io, client: anytype, options: Options) !Result {
    var forwarding = try SignalForwarder.init();
    defer forwarding.deinit();
    var expected: ?protocol.Owner = null;
    const listed = try takeover(allocator, io, client, options, &expected);
    defer if (listed) |parsed| parsed.deinit();
    var spawning = options;
    spawning.suspend_until_registered = true;
    var child = try start(allocator, io, spawning);
    defer child.deinit();
    defer if (options.after_exit) |callback| callback(&child, options.hook_context);
    var registered = false;
    defer unregister(client, &child, &registered);
    if (options.proxy) try register(client, &child, expected, &registered);
    // Released first on exit, before route and hook cleanup.
    var terminal = Foreground.acquire(options.stdin, child.record.process_group);
    defer if (terminal) |*held| held.release();
    try osprocess.signal(child.record.liveIdentity(), .CONT);
    if (options.after_start) |callback| try callback(&child, options.hook_context);
    return child.waitTerminal(&forwarding, options.stop_timeout_ms, if (terminal) |*held| held else null);
}

pub fn removeOwnedSocket(allocator: Allocator, io: Io, path: []const u8) !void {
    const c = @import("net.zig").c;
    if (!std.fs.path.isAbsolute(path)) return error.InvalidSocketPath;
    var dir = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer dir.close(io);
    var parts = std.mem.tokenizeScalar(u8, path, '/');
    var part = parts.next() orelse return error.InvalidSocketPath;
    while (true) {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..") or std.mem.findScalar(u8, part, 0) != null) return error.InvalidSocketPath;
        if (parts.next()) |next| {
            const child = try dir.openDir(io, part, .{ .follow_symlinks = false });
            dir.close(io);
            dir = child;
            part = next;
            continue;
        }
        const name = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(name);
        var stat: c.struct_stat = undefined;
        if (c.fstatat(dir.handle, name, &stat, c.AT_SYMLINK_NOFOLLOW) != 0) {
            if (std.c._errno().* == c.ENOENT) return;
            return error.SocketInspectionFailed;
        }
        if (stat.st_mode & c.S_IFMT != c.S_IFSOCK or stat.st_uid != osprocess.uid() or stat.st_nlink != 1 or stat.st_mode & 0o007 != 0) return error.UnsafeSocket;
        try dir.deleteFile(io, part);
        return;
    }
}
/// Bypass preserves argv and the caller's environment and writes no route/state.
pub fn direct(io: Io, argv: []const []const u8, environ: *const std.process.Environ.Map, cwd: ?[]const u8) !u8 {
    if (argv.len == 0) return error.InvalidCommand;
    var forwarding = try SignalForwarder.init();
    defer forwarding.deinit();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var child = try osprocess.spawnSuspended(arena.allocator(), io, .{ .argv = argv, .cwd = if (cwd) |path| .{ .path = path } else .inherit, .environ_map = environ, .pgid = 0, .start_suspended = true, .stdin = .inherit, .stdout = .inherit, .stderr = .inherit });
    var identity: ?osprocess.Identity = null;
    defer terminate(io, &child, identity);
    identity = try osprocess.inspect(child.id.?);
    var terminal = Foreground.acquire(.inherit, identity.?.pgid);
    defer if (terminal) |*held| held.release();
    try osprocess.signal(identity.?, .CONT);
    const term = try supervise(io, &forwarding, &child, identity.?, 5000, if (terminal) |*held| held else null);
    return (Result{ .identity = .{ .pid = identity.?.pid, .start = identity.?.start }, .term = term }).exitCode();
}
/// One signal supervisor owns every workspace child and cleans each route by
/// its exact canonical process identity. A failed app stops the other children.
/// The terminal stays with the supervisor so Ctrl-C reaches every child.
pub fn runMany(allocator: Allocator, io: Io, client: anytype, options: []const Options) !u8 {
    if (options.len == 0 or options.len > 256) return error.InvalidWorkspace;
    var forwarding = try SignalForwarder.init();
    defer forwarding.deinit();
    const children = try allocator.alloc(Process, options.len);
    defer allocator.free(children);
    const registered = try allocator.alloc(bool, options.len);
    defer allocator.free(registered);
    @memset(registered, false);
    const exited = try allocator.alloc(bool, options.len);
    defer allocator.free(exited);
    @memset(exited, false);
    var count: usize = 0;
    defer for (children[0..count], 0..) |*child, index| {
        if (!exited[index]) if (options[index].after_exit) |callback| callback(child, options[index].hook_context);
        unregister(client, child, &registered[index]);
        child.deinit();
    };
    // Runs first on an error path: signal every live child before the slower
    // per-child hook and route cleanup above, which then reaps each one.
    defer for (children[0..count]) |*child| if (child.child.id != null) deliver(&child.child, child.record.liveIdentity(), .KILL);
    for (options, 0..) |option, index| {
        var expected: ?protocol.Owner = null;
        // The listing owns `expected`'s strings until the add below completes.
        const listed = try takeover(allocator, io, client, option, &expected);
        defer if (listed) |parsed| parsed.deinit();
        var spawning = option;
        spawning.suspend_until_registered = true;
        children[index] = try start(allocator, io, spawning);
        count += 1;
        const child = &children[index];
        if (option.proxy) try register(client, child, expected, &registered[index]);
        if (option.after_start) |callback| try callback(child, option.hook_context);
        try osprocess.signal(child.record.liveIdentity(), .CONT);
    }
    var remaining = count;
    var code: u8 = 0;
    var deadline: ?i96 = null;
    var killed = false;
    while (remaining > 0) {
        const pending = pending_signals.swap(0, .acq_rel);
        if (deadline == null and pending & terminating != 0) deadline = deadlineAfter(io, 5000);
        const kill_now = !killed and deadline != null and Io.Clock.awake.now(io).toNanoseconds() >= deadline.?;
        killed = killed or kill_now;
        for (children[0..count], 0..) |*child, index| {
            if (exited[index]) continue;
            if (try reap(io, &child.child, false)) |term| {
                const result = child.finish(term);
                if (options[index].after_exit) |callback| callback(child, options[index].hook_context);
                unregister(client, child, &registered[index]);
                exited[index] = true;
                remaining -= 1;
                if (result.exitCode() != 0 and code == 0) {
                    // A failed app stops its siblings: TERM now, KILL after grace.
                    code = result.exitCode();
                    if (deadline == null) deadline = deadlineAfter(io, 5000);
                    for (children[0..count], exited[0..count]) |*other, done| if (!done) deliver(&other.child, other.record.liveIdentity(), .TERM);
                }
                continue;
            }
            forward(&child.child, child.record.liveIdentity(), pending);
            if (kill_now) deliver(&child.child, child.record.liveIdentity(), .KILL);
        }
        if (remaining > 0) try forwarding.wait(pollTimeout(io, if (killed) null else deadline));
    }
    return code;
}
