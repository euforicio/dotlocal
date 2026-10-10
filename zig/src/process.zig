pub const file_stat = @import("file_stat.zig");
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const native = @import("native");
extern "c" fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *anyopaque, size: c_int) c_int;
// Stable public libproc.h ABI, PROC_PIDTBSDINFO (3).
const BsdInfo = extern struct {
    flags: u32,
    status: u32,
    xstatus: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    reserved: u32,
    comm: [16]u8,
    name: [32]u8,
    nfiles: u32,
    pgid: u32,
    jobc: u32,
    tdev: u32,
    tpgid: u32,
    nice: i32,
    start_tvsec: u64,
    start_tvusec: u64,
};

pub const Identity = struct { uid: u32, pid: c_int, start: i64, pgid: c_int };

/// Kernel start time prevents a recycled PID from authorizing a signal.
pub fn inspect(pid: c_int) !Identity {
    if (pid <= 0) return error.InvalidProcessID;
    if (builtin.os.tag == .linux) return inspectLinux(pid);
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;
    var info: BsdInfo = undefined;
    const size = proc_pidinfo(pid, 3, 0, &info, @sizeOf(@TypeOf(info)));
    if (size == 0) return switch (c.errno(@as(c_int, -1))) {
        .SRCH, .NOENT, .SUCCESS => error.ProcessGone,
        // Sandboxes and other users' processes deny libproc; sysctl does not.
        .PERM, .ACCES => sysctlIdentity(pid),
        else => error.ProcessInspectionFailed,
    };
    if (size != @sizeOf(@TypeOf(info))) return error.ProcessInspectionFailed;
    if (info.pid != pid or info.status == 5) return error.ProcessGone;
    return makeIdentity(info.uid, pid, info.start_tvsec, info.start_tvusec, info.pgid);
}

fn sysctlIdentity(pid: c_int) !Identity {
    const n = @import("native");
    var info: n.struct_kinfo_proc = undefined;
    var size: usize = @sizeOf(n.struct_kinfo_proc);
    var mib = [_]c_int{ n.CTL_KERN, n.KERN_PROC, n.KERN_PROC_PID, pid };
    if (n.sysctl(&mib, mib.len, &info, &size, null, 0) != 0) return error.ProcessInspectionFailed;
    if (size == 0 or info.kp_proc.p_pid != pid or info.kp_proc.p_stat == n.SZOMB) return error.ProcessGone;
    const started = info.kp_proc.p_un.__p_starttime;
    return makeIdentity(info.kp_eproc.e_ucred.cr_uid, pid, started.tv_sec, started.tv_usec, info.kp_eproc.e_pgid);
}

fn makeIdentity(owner: anytype, pid: c_int, seconds: anytype, micros: anytype, pgid: anytype) !Identity {
    const sec = std.math.cast(u64, seconds) orelse return error.InvalidProcessIdentity;
    const usec = std.math.cast(u64, micros) orelse return error.InvalidProcessIdentity;
    const total = std.math.add(u64, std.math.mul(u64, sec, 1_000_000) catch return error.InvalidProcessIdentity, usec) catch return error.InvalidProcessIdentity;
    const start = std.math.cast(i64, total) orelse return error.InvalidProcessIdentity;
    if (start <= 0) return error.InvalidProcessIdentity;
    return .{ .uid = owner, .pid = pid, .start = start, .pgid = std.math.cast(c_int, pgid) orelse return error.InvalidProcessIdentity };
}

fn inspectLinux(pid: c_int) !Identity {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintSentinel(&path_buf, "/proc/{d}/stat", .{pid}, 0);
    const fd = native.open(path, native.O_RDONLY | native.O_CLOEXEC | native.O_NOFOLLOW, @as(c_int, 0));
    if (fd < 0) return if (c.errno(@as(c_int, -1)) == .NOENT) error.ProcessGone else error.ProcessInspectionFailed;
    defer _ = c.close(fd);
    var stat: native.struct_stat = undefined;
    if (file_stat.fstat(fd, &stat) != 0) return error.ProcessInspectionFailed;
    var buffer: [4096]u8 = undefined;
    const n = c.read(fd, &buffer, buffer.len);
    if (n <= 0 or n == buffer.len) return error.ProcessGone;
    const bytes = buffer[0..@intCast(n)];
    // comm may contain spaces and parentheses; the final ')' precedes state.
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.ProcessInspectionFailed;
    var fields = std.mem.tokenizeScalar(u8, bytes[end + 1 ..], ' ');
    var group: c_int = 0;
    var start: i64 = 0;
    var index: usize = 3;
    while (fields.next()) |field| : (index += 1) {
        if (index == 3 and (std.mem.eql(u8, field, "Z") or std.mem.eql(u8, field, "X"))) return error.ProcessGone;
        if (index == 5) group = try std.fmt.parseInt(c_int, field, 10);
        if (index == 22) {
            start = try std.fmt.parseInt(i64, field, 10);
            break;
        }
    }
    if (start <= 0 or group <= 0) return error.InvalidProcessIdentity;
    return .{ .uid = stat.st_uid, .pid = pid, .start = start, .pgid = group };
}

pub fn matches(owner: anytype) bool {
    if (!std.mem.eql(u8, owner.kind, "process") or owner.pid <= 0 or owner.process_start <= 0) return false;
    const identity = inspect(owner.pid) catch return false;
    return identity.start == owner.process_start;
}

pub fn current() !Identity {
    return inspect(c.getpid());
}
pub fn uid() u32 {
    return c.geteuid();
}

/// Zig 0.17's Linux suspended spawn waits for exec's error pipe while its child
/// is stopped before exec. Use a native stop handshake on Linux; all allocation
/// and executable resolution happen before fork. Other platforms use std.Io.
pub fn spawnSuspended(a: std.mem.Allocator, io: std.Io, options: std.process.SpawnOptions) !std.process.Child {
    if (builtin.os.tag != .linux) return std.process.spawn(io, options);
    if (!options.start_suspended or options.pgid == null or options.pgid.? != 0 or options.argv.len == 0) return error.UnsupportedSpawnOptions;
    const env = options.environ_map orelse return error.UnsupportedSpawnOptions;
    const cwd = switch (options.cwd) {
        .inherit => try std.Io.Dir.cwd().realPathFileAlloc(io, ".", a),
        .dir => |dir| try dir.realPathFileAlloc(io, ".", a),
        .path => |path| try std.Io.Dir.cwd().realPathFileAlloc(io, path, a),
    };
    defer a.free(cwd);
    const directory = try a.dupeSentinel(u8, cwd, 0);
    defer a.free(directory);
    var executable: ?[:0]u8 = null;
    var denied = false;
    var paths = std.mem.splitScalar(u8, env.get("PATH") orelse "/usr/local/bin:/usr/bin:/bin", ':');
    while (true) {
        const prefix = if (std.mem.indexOfScalar(u8, options.argv[0], '/') != null) "" else paths.next() orelse break;
        const candidate = try std.fs.path.resolve(a, &.{ cwd, prefix, options.argv[0] });
        defer a.free(candidate);
        const path = try a.dupeSentinel(u8, candidate, 0);
        const accessible = native.access(path, native.X_OK) == 0;
        if (accessible) {
            const stat = std.Io.Dir.cwd().statFile(io, candidate, .{}) catch {
                a.free(path);
                break;
            };
            if (stat.kind == .file) {
                executable = path;
                break;
            }
        } else if (c.errno(@as(c_int, -1)) == .ACCES) denied = true;
        a.free(path);
        if (std.mem.indexOfScalar(u8, options.argv[0], '/') != null) break;
    }
    const program = executable orelse return if (denied) error.AccessDenied else error.FileNotFound;
    defer a.free(program);
    const argv = try a.allocSentinel(?[*:0]const u8, options.argv.len, null);
    defer a.free(argv);
    var allocated: usize = 0;
    defer for (argv[0..allocated]) |arg| a.free(std.mem.span(arg.?));
    for (options.argv, 0..) |arg, index| {
        argv[index] = (try a.dupeSentinel(u8, arg, 0)).ptr;
        allocated += 1;
    }
    const block = try env.createPosixBlock(a, .{});
    defer block.deinit(a);
    const null_fd = native.open("/dev/null", native.O_RDWR | native.O_CLOEXEC, @as(c_int, 0));
    if (null_fd < 0) return error.ChildSetupFailed;
    defer _ = c.close(null_fd);
    const stdio = [_]std.process.SpawnOptions.StdIo{ options.stdin, options.stdout, options.stderr };
    for (stdio) |mode| if (mode == .pipe) return error.UnsupportedSpawnOptions;
    const pid = native.fork();
    if (pid < 0) return error.SystemResources;
    if (pid == 0) {
        if (native.chdir(directory) != 0 or native.setpgid(0, 0) != 0) native._exit(126);
        for (stdio, 0..) |mode, index| {
            const target: c_int = @intCast(index);
            const fd = switch (mode) {
                .inherit => continue,
                .close => {
                    _ = c.close(target);
                    continue;
                },
                .ignore => null_fd,
                .file => |file| file.handle,
                .pipe => unreachable,
            };
            if (native.dup2(fd, target) < 0) native._exit(126);
        }
        if (native.kill(native.getpid(), native.SIGSTOP) != 0) native._exit(126);
        _ = native.execve(program, @ptrCast(argv.ptr), @ptrCast(block.slice.ptr));
        const message = "dotlocal: child execution failed\n";
        _ = c.write(2, message.ptr, message.len);
        native._exit(127);
    }
    var status: c_int = 0;
    while (native.waitpid(pid, &status, native.WUNTRACED) < 0) {
        if (c.errno(@as(c_int, -1)) == .INTR) continue;
        _ = native.kill(pid, native.SIGKILL);
        _ = native.waitpid(pid, &status, 0);
        return error.ChildSetupFailed;
    }
    if (!native.WIFSTOPPED(status)) return error.ChildSetupFailed;
    return .{ .id = pid, .thread_handle = {}, .stdin = null, .stdout = null, .stderr = null, .request_resource_usage_statistics = false };
}

pub fn signal(identity: Identity, sig: std.posix.SIG) !void {
    const live = try inspect(identity.pid);
    if (live.uid != identity.uid or live.start != identity.start or live.pgid != identity.pgid or live.pgid != identity.pid) return error.IdentityMismatch;
    try std.posix.kill(-live.pgid, sig);
}

/// Signal a single verified supervisor, including before it detaches its session.
pub fn signalProcess(identity: Identity, sig: std.posix.SIG) !void {
    const live = try inspect(identity.pid);
    if (live.uid != identity.uid or live.start != identity.start) return error.IdentityMismatch;
    try std.posix.kill(live.pid, sig);
}

/// std.Io.Stat intentionally omits Unix ownership; use fstat only for this
/// security boundary, after opening without following symlinks.
pub fn validateOwned(fd: c_int, mode: u16, directory: bool) !void {
    var info: native.struct_stat = undefined;
    if (file_stat.fstat(fd, &info) != 0) return error.FileInspectionFailed;
    const kind = info.st_mode & native.S_IFMT;
    if (kind != (if (directory) native.S_IFDIR else native.S_IFREG) or info.st_uid != uid() or info.st_mode & 0o7777 != mode or (!directory and info.st_nlink != 1)) return error.UnsafeStateFile;
}

/// User-edited files: a single-link regular file owned by the caller that
/// group and other cannot write. Readability is the owner's choice.
pub fn validateUserFile(fd: c_int) !void {
    var info: native.struct_stat = undefined;
    if (file_stat.fstat(fd, &info) != 0) return error.FileInspectionFailed;
    if (info.st_mode & native.S_IFMT != native.S_IFREG or info.st_uid != uid() or info.st_mode & 0o022 != 0 or info.st_nlink != 1) return error.UnsafeStateFile;
}

/// Install directories: owned by the caller and not group/other-writable,
/// so nobody else can swap the staged binary before it is renamed.
pub fn validateInstallDirectory(fd: c_int) !void {
    var info: native.struct_stat = undefined;
    if (file_stat.fstat(fd, &info) != 0) return error.FileInspectionFailed;
    if (info.st_mode & native.S_IFMT != native.S_IFDIR or info.st_uid != uid() or info.st_mode & 0o022 != 0) return error.UnsafeStateFile;
}

test "real current process identity" {
    const identity = try current();
    try std.testing.expect(identity.pid > 0);
    try std.testing.expect(identity.start > 0);
    try std.testing.expectEqual(uid(), identity.uid);
    try std.testing.expectError(error.InvalidProcessID, inspect(0));
}

test "denied libproc inspection falls back to sysctl with the same identity" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    // launchd is root-owned, so libproc denies an unprivileged caller.
    const launchd = try inspect(1);
    try std.testing.expectEqual(@as(u32, 0), launchd.uid);
    try std.testing.expect(launchd.start > 0);
    try std.testing.expectEqual(try current(), try sysctlIdentity(c.getpid()));
}

/// Discards child output on an independent CLOEXEC descriptor, so draining
/// survives Child.kill closing its owned pipe and later output cannot block it.
pub fn drainPipe(io: std.Io, pipe: std.Io.File) !std.Io.Future(void) {
    const fd = c.fcntl(pipe.handle, c.F.DUPFD_CLOEXEC, @as(c_int, 3));
    if (fd < 0) return error.PipeDuplicateFailed;
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    errdefer file.close(io);
    return io.concurrent(discard, .{ io, file });
}
fn discard(io: std.Io, file: std.Io.File) void {
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    _ = reader.interface.discardRemaining() catch {};
}

/// Writes every byte to a blocking descriptor, retrying partial and interrupted writes.
pub fn writeAll(fd: c_int, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (n < 0 and c.errno(n) == .INTR) continue;
        if (n <= 0) return error.WriteFailed;
        offset += @intCast(n);
    }
}

pub const Staging = struct { fd: c_int, name: [:0]const u8 };
pub const staging_suffix_len = 32;

/// Exclusively creates a 0600 staging file in `dir` named `prefix` plus a
/// random hex suffix, so concurrent writers and stale files never collide.
/// `name` must hold `prefix.len + staging_suffix_len + 1` bytes.
pub fn createStaging(io: std.Io, dir: c_int, prefix: []const u8, name: []u8) !Staging {
    if (name.len < prefix.len + staging_suffix_len + 1) return error.NameTooLong;
    var collisions: usize = 0;
    while (collisions < 8) {
        var random: [staging_suffix_len / 2]u8 = undefined;
        io.random(&random);
        const path = std.fmt.bufPrintSentinel(name, "{s}{s}", .{ prefix, std.fmt.bytesToHex(random, .lower) }, 0) catch unreachable;
        const fd = native.openat(dir, path, native.O_WRONLY | native.O_CREAT | native.O_EXCL | native.O_NOFOLLOW | native.O_CLOEXEC, @as(c_uint, 0o600));
        if (fd >= 0) return .{ .fd = fd, .name = path };
        switch (c.errno(fd)) {
            .INTR => {},
            .EXIST => collisions += 1,
            else => return error.StagingCreateFailed,
        }
    }
    return error.StagingCreateFailed;
}

test "drained real child output cannot fill its pipe" {
    const io = std.testing.io;
    // Far more than a pipe buffer; the child blocks forever without a drain.
    var child = try std.process.spawn(io, .{ .argv = &.{ "/bin/sh", "-c", "head -c 4194304 /dev/zero" }, .stdin = .ignore, .stdout = .pipe, .stderr = .ignore });
    var drain = drainPipe(io, child.stdout.?) catch |err| {
        child.kill(io);
        return err;
    };
    const term = try child.wait(io);
    drain.await(io);
    try std.testing.expect(term.success());
}

test "staging files are exclusive, private and uniquely named" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var first_name: [64]u8 = undefined;
    var second_name: [64]u8 = undefined;
    const first = try createStaging(io, tmp.dir.handle, ".stage-", &first_name);
    defer _ = c.close(first.fd);
    const second = try createStaging(io, tmp.dir.handle, ".stage-", &second_name);
    defer _ = c.close(second.fd);
    try std.testing.expect(!std.mem.eql(u8, first.name, second.name));
    try std.testing.expectEqual(".stage-".len + staging_suffix_len, first.name.len);
    try validateOwned(first.fd, 0o600, false);
    try writeAll(first.fd, "staged");
    const data = try tmp.dir.readFileAlloc(io, first.name, std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualStrings("staged", data);
    var short: [8]u8 = undefined;
    try std.testing.expectError(error.NameTooLong, createStaging(io, tmp.dir.handle, ".stage-", &short));
}
