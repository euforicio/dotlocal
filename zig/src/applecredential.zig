//! Root daemon inspection in the authenticated login user's security context.
//! The only public operation runs a fixed absolute Apple Container executable.
const std = @import("std");
const apple = @import("applecontainer.zig");
const A = std.mem.Allocator;
const Io = std.Io;
const c = std.c;
extern "c" fn setgroups(count: c_int, groups: ?[*]const c.gid_t) c_int;

const Login = struct {
    uid: u32,
    gid: u32,
    username: []u8,
    home: [:0]u8,
    fn deinit(self: Login, a: A) void {
        a.free(self.username);
        a.free(self.home);
    }
};
fn login(a: A, uid: u32) !Login {
    if (uid == 0) return error.UnprivilegedLoginRequired;
    const buffer = try a.alloc(u8, 64 * 1024);
    defer a.free(buffer);
    var pwd: c.passwd = undefined;
    var result: ?*c.passwd = null;
    if (c.getpwuid_r(uid, &pwd, buffer.ptr, buffer.len, &result) != 0 or result == null or pwd.uid != uid) return error.InvalidLoginUser;
    const username = std.mem.span(pwd.name orelse return error.InvalidLoginUser);
    const home = std.mem.span(pwd.dir orelse return error.InvalidLoginUser);
    if (username.len == 0 or username.len > 255 or std.mem.findAny(u8, username, "=\r\n") != null or !std.fs.path.isAbsolute(home) or home.len > 4096 or std.mem.findAny(u8, home, "\r\n") != null) return error.InvalidLoginUser;
    const name = try a.dupe(u8, username);
    errdefer a.free(name);
    return .{ .uid = uid, .gid = pwd.gid, .username = name, .home = try a.dupeSentinel(u8, home, 0) };
}

pub fn resolve(a: A, io: Io, executable: []const u8, name: []const u8, requested_port: u16, scheme: []const u8, uid: u32) !apple.Endpoint {
    try apple.validateID(name);
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return error.UnsupportedProtocol;
    if (!std.fs.path.isAbsolute(executable) or std.mem.findScalar(u8, executable, 0) != null) return error.InvalidContainerExecutable;
    if (uid == 0) return error.UnprivilegedLoginRequired;
    if (c.geteuid() == uid) return apple.resolve(a, io, executable, name, requested_port, scheme);
    if (c.geteuid() != 0) return error.CredentialChangeDenied;
    const account = try login(a, uid);
    defer account.deinit(a);
    const program = try a.dupeSentinel(u8, executable, 0);
    defer a.free(program);
    const container = try a.dupeSentinel(u8, name, 0);
    defer a.free(container);
    const user_id = try std.fmt.allocPrintSentinel(a, "{d}", .{uid}, 0);
    defer a.free(user_id);
    const argv = [_:null]?[*:0]const u8{ "/bin/launchctl", "asuser", user_id.ptr, program.ptr, "inspect", container.ptr };
    const data = try execute(a, io, "/bin/launchctl", &argv, account, .fromSeconds(5));
    defer a.free(data);
    return apple.parse(a, data, name, requested_port, scheme);
}

fn pipe() ![2]c.fd_t {
    var fds: [2]c.fd_t = undefined;
    if (c.pipe(&fds) != 0) return error.PipeFailed;
    errdefer {
        _ = c.close(fds[0]);
        _ = c.close(fds[1]);
    }
    for (&fds) |*fd| {
        if (fd.* < 3) {
            const promoted = c.fcntl(fd.*, c.F.DUPFD_CLOEXEC, @as(c_int, 3));
            if (promoted < 0) return error.PipeFailed;
            _ = c.close(fd.*);
            fd.* = promoted;
        }
        if (c.fcntl(fd.*, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)) < 0) return error.PipeFailed;
    }
    const flags = c.fcntl(fds[0], c.F.GETFL);
    const nonblock: c_int = @bitCast(c.O{ .NONBLOCK = true });
    if (flags < 0 or c.fcntl(fds[0], c.F.SETFL, flags | nonblock) < 0) return error.PipeFailed;
    return fds;
}

fn descriptorLimit() !c_int {
    if (@import("builtin").os.tag == .linux) {
        const native = @import("native");
        const value = native.sysconf(native._SC_OPEN_MAX);
        if (value < 3 or value > 4 * 1024 * 1024) return error.InvalidDescriptorLimit;
        return @intCast(value);
    }
    // This kernel cap includes descriptors inherited before a soft rlimit was
    // lowered. Closing the full range prevents privileged listener inheritance.
    var limit: c_int = 0;
    var size: usize = @sizeOf(c_int);
    if (c.sysctlbyname("kern.maxfilesperproc", &limit, &size, null, 0) != 0 or size != @sizeOf(c_int) or limit < 3 or limit > 4 * 1024 * 1024) return error.InvalidDescriptorLimit;
    return limit;
}
// Stable public libproc.h ABI: PROC_PIDLISTFDS (1) fills struct proc_fdinfo.
const FdInfo = extern struct { fd: i32, kind: u32 };
extern "c" fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *anyopaque, size: c_int) c_int;

/// Pre-fork buffer for listing open descriptors in the child, with headroom
/// for descriptors other threads open before fork. Empty where unused.
fn descriptorListing(a: A) ![]FdInfo {
    if (@import("builtin").os.tag != .macos) return a.alloc(FdInfo, 0);
    var capacity: usize = 256;
    while (true) {
        const buffer = try a.alloc(FdInfo, capacity);
        const bytes = proc_pidinfo(c.getpid(), 1, 0, buffer.ptr, @intCast(capacity * @sizeOf(FdInfo)));
        if (bytes <= 0) {
            a.free(buffer);
            return error.DescriptorListingFailed;
        }
        const used: usize = @intCast(@divTrunc(bytes, @sizeOf(FdInfo)));
        if (used * 2 <= capacity or capacity >= 1 << 20) return buffer;
        a.free(buffer);
        capacity *= 2;
    }
}
/// Child-only and async-signal-safe: close every descriptor >= 3 without
/// walking the whole kernel limit. A listing that may be truncated, or a
/// kernel without close_range, falls back to closing the full range.
fn closeInherited(listing: []FdInfo, maximum: c_int) void {
    switch (@import("builtin").os.tag) {
        .linux => {
            const linux = std.os.linux;
            if (linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false })) == .SUCCESS) return;
        },
        .macos => if (listing.len > 0) {
            const bytes = proc_pidinfo(c.getpid(), 1, 0, listing.ptr, @intCast(listing.len * @sizeOf(FdInfo)));
            if (bytes > 0 and @as(usize, @intCast(bytes)) < listing.len * @sizeOf(FdInfo)) {
                const count: usize = @intCast(@divTrunc(bytes, @sizeOf(FdInfo)));
                for (listing[0..count]) |entry| {
                    if (entry.fd < 3) continue;
                    while (c.close(entry.fd) != 0 and c.errno(@as(c_int, -1)) == .INTR) {}
                }
                return;
            }
        },
        else => {},
    }
    var fd: c_int = 3;
    while (fd < maximum) {
        if (c.close(fd) != 0 and c.errno(@as(c_int, -1)) == .INTR) continue;
        fd += 1;
    }
}
fn childBail() noreturn {
    const message = "container credential setup failed\n";
    _ = c.write(2, message.ptr, message.len);
    c._exit(126);
}
fn reap(pid: c.pid_t) void {
    var status: c_int = 0;
    while (c.waitpid(pid, &status, 0) < 0) {
        if (c.errno(@as(c_int, -1)) != .INTR) return;
    }
}
fn drain(a: A, fd: c.fd_t, target: *std.ArrayList(u8), limit: usize, eof: *bool) !void {
    var buffer: [8192]u8 = undefined;
    while (true) {
        const count = c.read(fd, &buffer, buffer.len);
        if (count == 0) {
            eof.* = true;
            return;
        }
        if (count < 0) switch (c.errno(@as(c_int, -1))) {
            .INTR => continue,
            .AGAIN => return,
            else => return error.InspectionReadFailed,
        };
        const n: usize = @intCast(count);
        if (n > limit - target.items.len) return error.InspectionOutputTooLarge;
        try target.appendSlice(a, buffer[0..n]);
    }
}

fn execute(a: A, io: Io, program: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, account: Login, timeout: Io.Duration) ![]u8 {
    const home_env = try std.fmt.allocPrintSentinel(a, "HOME={s}", .{account.home}, 0);
    defer a.free(home_env);
    const user_env = try std.fmt.allocPrintSentinel(a, "USER={s}", .{account.username}, 0);
    defer a.free(user_env);
    const logname_env = try std.fmt.allocPrintSentinel(a, "LOGNAME={s}", .{account.username}, 0);
    defer a.free(logname_env);
    const env = [_:null]?[*:0]const u8{ home_env.ptr, user_env.ptr, logname_env.ptr, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR=/tmp" };
    const out = try pipe();
    defer _ = c.close(out[0]);
    var out_write_open = true;
    defer if (out_write_open) {
        _ = c.close(out[1]);
    };
    const err = try pipe();
    defer _ = c.close(err[0]);
    var err_write_open = true;
    defer if (err_write_open) {
        _ = c.close(err[1]);
    };
    var dev_null = c.open("/dev/null", .{ .CLOEXEC = true });
    if (dev_null < 0) return error.OpenNullFailed;
    defer _ = c.close(dev_null);
    if (dev_null < 3) {
        const promoted = c.fcntl(dev_null, c.F.DUPFD_CLOEXEC, @as(c_int, 3));
        if (promoted < 0) return error.OpenNullFailed;
        _ = c.close(dev_null);
        dev_null = promoted;
    }
    const maximum = try descriptorLimit();
    const listing = try descriptorListing(a);
    defer a.free(listing);
    const privileged = c.geteuid() == 0;
    const empty_mask = std.posix.sigemptyset();
    const default_action: c.Sigaction = .{ .handler = .{ .handler = c.SIG.DFL }, .mask = empty_mask, .flags = 0 };
    const deadline = Io.Clock.awake.now(io).toNanoseconds() + timeout.toNanoseconds();
    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        // All allocations, user lookup, formatting and descriptor discovery
        // finish before fork. This branch uses only async-signal-safe libc calls.
        if (c.setpgid(0, 0) != 0 or c.dup2(dev_null, 0) < 0 or c.dup2(out[1], 1) < 0 or c.dup2(err[1], 2) < 0) childBail();
        if (privileged and setgroups(0, null) != 0) childBail();
        if (c.setgid(account.gid) != 0 or c.setuid(account.uid) != 0 or c.getuid() != account.uid or c.geteuid() != account.uid or c.getgid() != account.gid or c.getegid() != account.gid) childBail();
        if (c.chdir(account.home.ptr) != 0 or c.sigprocmask(@intCast(c.SIG.SETMASK), &empty_mask, null) != 0) childBail();
        var sig: c_int = 1;
        while (sig < 32) : (sig += 1) {
            const signal: c.SIG = @fromBackingInt(@intCast(sig));
            if (signal != .KILL and signal != .STOP and c.sigaction(signal, &default_action, null) != 0) childBail();
        }
        closeInherited(listing, maximum);
        _ = c.execve(program, argv, &env);
        childBail();
    }
    _ = c.close(out[1]);
    out_write_open = false;
    _ = c.close(err[1]);
    err_write_open = false;
    var reaped = false;
    defer if (!reaped) {
        // This is our unreaped direct child, so the PID cannot be reused.
        _ = c.kill(-pid, .KILL);
        _ = c.kill(pid, .KILL);
        reap(pid);
    };
    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(a);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(a);
    var stdout_eof = false;
    var stderr_eof = false;
    var status: c_int = 0;
    var exited = false;
    while (!exited or !stdout_eof or !stderr_eof) {
        if (Io.Clock.awake.now(io).toNanoseconds() >= deadline) return error.InspectionTimedOut;
        var fds = [_]c.pollfd{
            .{ .fd = if (stdout_eof) -1 else out[0], .events = c.POLL.IN, .revents = 0 },
            .{ .fd = if (stderr_eof) -1 else err[0], .events = c.POLL.IN, .revents = 0 },
        };
        const ready = c.poll(&fds, fds.len, 20);
        if (ready < 0 and c.errno(@as(c_int, -1)) != .INTR) return error.InspectionPollFailed;
        if (!stdout_eof) try drain(a, out[0], &stdout, 8 << 20, &stdout_eof);
        if (!stderr_eof) try drain(a, err[0], &stderr, 64 << 10, &stderr_eof);
        // Keep the group leader unreaped until both capture pipes close, so
        // a timeout still owns a PID anchor for killing remaining descendants.
        if (!exited and stdout_eof and stderr_eof) {
            const waited = c.waitpid(pid, &status, c.W.NOHANG);
            if (waited == pid) {
                exited = true;
                reaped = true;
            }
            if (waited < 0 and c.errno(@as(c_int, -1)) != .INTR) return error.InspectionWaitFailed;
        }
        try io.checkCancel();
    }
    if (!c.W.IFEXITED(@bitCast(status)) or c.W.EXITSTATUS(@bitCast(status)) != 0) return error.InspectionFailed;
    return stdout.toOwnedSlice(a);
}

test "real login credential lookup rejects root" {
    try std.testing.expectError(error.UnprivilegedLoginRequired, login(std.testing.allocator, 0));
    const account = try login(std.testing.allocator, c.geteuid());
    defer account.deinit(std.testing.allocator);
    try std.testing.expectEqual(c.geteuid(), account.uid);
    try std.testing.expect(account.username.len > 0 and std.fs.path.isAbsolute(account.home));
}

test "native inspection bridge executes own real UID with a scrubbed environment" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const account = try login(a, c.geteuid());
    defer account.deinit(a);
    const argv = [_:null]?[*:0]const u8{ "/usr/bin/id", "-u" };
    const data = try execute(a, io, "/usr/bin/id", &argv, account, .fromSeconds(5));
    defer a.free(data);
    const uid = try std.fmt.parseInt(u32, std.mem.trim(u8, data, "\r\n"), 10);
    try std.testing.expectEqual(account.uid, uid);
    const env_argv = [_:null]?[*:0]const u8{"/usr/bin/env"};
    const environment = try execute(a, io, "/usr/bin/env", &env_argv, account, .fromSeconds(5));
    defer a.free(environment);
    const expected = try std.fmt.allocPrint(a, "HOME={s}\nUSER={s}\nLOGNAME={s}\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nTMPDIR=/tmp\n", .{ account.home, account.username, account.username });
    defer a.free(expected);
    try std.testing.expectEqualStrings(expected, environment);
}

test "native bridge bounds real child execution and output" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const account = try login(a, c.geteuid());
    defer account.deinit(a);
    const sleeping = [_:null]?[*:0]const u8{ "/bin/sleep", "60" };
    try std.testing.expectError(error.InspectionTimedOut, execute(a, io, "/bin/sleep", &sleeping, account, .fromMilliseconds(50)));
    const excessive = [_:null]?[*:0]const u8{"/usr/bin/yes"};
    try std.testing.expectError(error.InspectionOutputTooLarge, execute(a, io, "/usr/bin/yes", &excessive, account, .fromSeconds(5)));
}

test "native bridge child inherits no descriptor above stdio" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const account = try login(a, c.geteuid());
    defer account.deinit(a);
    // dup2 clears close-on-exec, so only the explicit child cleanup closes it.
    const null_fd = c.open("/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
    try std.testing.expect(null_fd >= 0);
    defer _ = c.close(null_fd);
    try std.testing.expectEqual(@as(c_int, 900), c.dup2(null_fd, 900));
    defer _ = c.close(900);
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "(: >&900) 2>/dev/null && echo open || echo closed" };
    const data = try execute(a, io, "/bin/sh", &argv, account, .fromSeconds(5));
    defer a.free(data);
    try std.testing.expectEqualStrings("closed\n", data);
}
