//! Detached startup, terminal closure and identity-bound CLI stop with real
//! processes, a real pseudo-terminal, sockets and the management daemon.
const std = @import("std");
const builtin = @import("builtin");
const t = @import("test_support.zig");
const c = t.c;

extern "c" fn posix_openpt(flags: c_int) c_int;
extern "c" fn grantpt(fd: c_int) c_int;
extern "c" fn unlockpt(fd: c_int) c_int;
extern "c" fn ptsname(fd: c_int) ?[*:0]const u8;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
const tiocsctty: c_ulong = if (builtin.os.tag == .linux) 0x540E else 0x20007461;

pub fn run(init: std.process.Init, binary: []const u8, server: []const u8) !void {
    var f = try t.Fixture.init(init, binary, server, "http");
    defer f.cleanup();
    try f.start(&.{}, true);
    defer stopAll(&f);

    // The launch command exits and its controlling terminal closes.
    const launched = try terminalLaunch(&f, &.{ binary, "start", "alpha", server });
    try t.check(std.mem.indexOf(u8, launched, "Started alpha.local") != null and std.mem.indexOf(u8, launched, "Log: ") != null, launched);
    const alpha = try pid(&f, "alpha.local");
    const first = (try records(&f))[0];
    const supervisor = try recordPid(first, "supervisor");
    try t.check(c.getsid(alpha) == supervisor and c.getpgid(supervisor) == supervisor, "app did not detach its terminal session");
    try t.check(c.getpgid(alpha) == alpha, "app has no private process group");
    const log_path = std.mem.trim(u8, launched[std.mem.indexOf(u8, launched, "Log: ").? + 5 ..], " \r\n");
    try t.check(try mode(&f, log_path) == 0o600, "app log is not private");
    try t.check(try mode(&f, std.fs.path.dirname(log_path).?) == 0o700, "launch directory is not private");

    _ = try f.command(&.{ "start", "alpha", server }, 1);
    try t.check(try pid(&f, "alpha.local") == alpha, "duplicate startup replaced the live app");
    _ = try f.command(&.{ "run", "--background", "--name", "beta", server }, 0);
    const beta = try pid(&f, "beta.local");
    _ = try f.command(&.{ "stop", "alpha" }, 0);
    try gone(&f, alpha);
    try gone(&f, supervisor);
    try t.check(try pid(&f, "beta.local") == beta, "stopping alpha affected beta");
    try t.check((try f.call(.{ .operation = "status" })).status.?.running, "app stop shut down the shared proxy");
    try routes(&f, &.{"beta.local"});
    _ = try f.command(&.{ "stop", "alpha" }, 0);
    _ = try f.command(&.{ "stop", "beta.local" }, 0);
    try gone(&f, beta);
    try settled(&f);
    std.debug.print("PASS detached terminal lifetime, private log, duplicate rejection, isolated idempotent stop\n", .{});

    const missing = try std.fs.path.join(f.a, &.{ f.base, "missing-server" });
    for ([_][]const []const u8{ &.{missing}, &.{ server, "exit", "17" } }) |command| {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(f.a, &.{ "start", "failed" });
        try argv.appendSlice(f.a, command);
        _ = try f.command(argv.items, 1);
        try t.check((try records(&f)).len == 0 and (try routeNames(&f)).len == 0, "failed startup retained app state or routes");
    }

    // Project configuration starts in the background without argv.
    try write(&f, "dotlocal.json", try std.json.Stringify.valueAlloc(f.a, .{ .name = "project", .command = &[_][]const u8{server} }, .{}));
    _ = try f.command(&.{"start"}, 0);
    const project = try pid(&f, "project.local");
    _ = try f.command(&.{ "stop", "project" }, 0);
    try gone(&f, project);
    try std.Io.Dir.cwd().deleteFile(f.io, try std.fs.path.join(f.a, &.{ f.base, "dotlocal.json" }));
    std.debug.print("PASS failed background startups leave no state; project configuration startup\n", .{});

    try interruptedStartup(&f, server);

    // TERM-ignoring apps and grandchildren need bounded process-group escalation.
    _ = try f.command(&.{ "start", "stubborn", server, "stubborn" }, 0);
    const stubborn = try answer(&f, "stubborn.local");
    const grandchild: c_int = @intCast((try t.field(stubborn, "grandchild")).integer);
    try t.check(grandchild > 0, "stubborn fixture has no grandchild");
    const began = std.Io.Clock.awake.now(f.io);
    _ = try f.command(&.{ "stop", "stubborn" }, 0);
    try t.check(began.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 12_000, "shutdown exceeded its bound");
    try gone(&f, @intCast((try t.field(stubborn, "pid")).integer));
    try gone(&f, grandchild);
    try settled(&f);

    // A registered alias is not authority to terminate an external server.
    const upstream = try t.port(f.a);
    var external = try f.backend(upstream);
    defer external.cleanup();
    try f.alias("external", upstream);
    _ = try f.command(&.{ "stop", "external" }, 0);
    _ = try t.lib.process.inspect(external.identity.pid);
    try routes(&f, &.{"external.local"});
    _ = try f.command(&.{ "remove", "external", "--force" }, 0);
    std.debug.print("PASS interrupted startup cleanup, bounded TERM-ignoring group stop, aliases never stopped\n", .{});

    // A workspace keeps one shared supervision and shutdown scope.
    const script = try std.fmt.allocPrint(f.a, "'{s}'", .{server});
    try write(&f, "package.json", "{\"name\":\"suite\",\"workspaces\":[\"packages/*\"]}");
    for ([_][]const u8{ "api", "web" }) |name| try write(&f, try std.fmt.allocPrint(f.a, "packages/{s}/package.json", .{name}), try std.json.Stringify.valueAlloc(f.a, .{ .name = try std.fmt.allocPrint(f.a, "@suite/{s}", .{name}), .scripts = .{ .dev = script } }, .{}));
    const result = try f.command(&.{"start"}, 0);
    try t.check(std.mem.indexOf(u8, result.stdout, "Started api.suite.local") != null and std.mem.indexOf(u8, result.stdout, "Started web.suite.local") != null, "workspace startup returned before all registrations");
    const api = try pid(&f, "api.suite.local");
    const web = try pid(&f, "web.suite.local");
    const shared = try recordPid((try records(&f))[0], "supervisor");
    _ = try f.command(&.{ "stop", "api.suite.local" }, 0);
    try gone(&f, api);
    try gone(&f, web);
    try gone(&f, shared);
    try settled(&f);
    std.debug.print("PASS background workspace shares one supervisor and shutdown scope\n", .{});
}

/// Ctrl-C before TCP readiness cancels the supervisor and its pending app.
fn interruptedStartup(f: *t.Fixture, server: []const u8) !void {
    const errors = try std.Io.Dir.cwd().createFile(f.io, try std.fs.path.join(f.a, &.{ f.base, "interrupted.log" }), .{ .read = true });
    defer errors.close(f.io);
    var waiting = try std.process.spawn(f.io, .{ .argv = &.{ f.binary, "start", "waiting", server, "exit", "0", "60000" }, .environ_map = &f.env, .cwd = .{ .path = f.base }, .stdin = .ignore, .stdout = .{ .file = errors }, .stderr = .{ .file = errors } });
    defer if (waiting.id != null) {
        std.posix.kill(waiting.id.?, .KILL) catch {};
        _ = t.lib.runner.reap(f.io, &waiting, true) catch {};
    };
    var pending: ?std.json.Value = null;
    for (0..500) |_| {
        for (try records(f)) |record| if (std.mem.eql(u8, try t.text(try t.field(record, "endpoint"), "name"), "waiting.local")) {
            pending = record;
        };
        if (pending != null) break;
        try std.Io.sleep(f.io, .fromMilliseconds(20), .awake);
    }
    const record = pending orelse return error.PendingChildNeverRegistered;
    try std.posix.kill(waiting.id.?, .INT);
    var term: ?std.process.Child.Term = null;
    for (0..600) |_| {
        term = try t.lib.runner.reap(f.io, &waiting, false);
        if (term != null) break;
        try std.Io.sleep(f.io, .fromMilliseconds(20), .awake);
    }
    const stderr = try std.Io.Dir.cwd().readFileAlloc(f.io, try std.fs.path.join(f.a, &.{ f.base, "interrupted.log" }), f.a, .limited(1 << 20));
    try t.check(term != null and !term.?.success() and std.mem.indexOf(u8, stderr, "BackgroundStartCancelled") != null, "startup interruption did not cancel safely");
    try gone(f, try recordPid(record, "identity"));
    try gone(f, try recordPid(record, "supervisor"));
    try t.check((try records(f)).len == 0 and (try routeNames(f)).len == 0, "interrupted startup retained state");
}

/// Runs the launcher as a session leader whose controlling terminal is a new
/// pseudo-terminal, returns its output, and requires that nothing else holds
/// the terminal open once it exits.
fn terminalLaunch(f: *t.Fixture, argv: []const []const u8) ![]const u8 {
    const master = posix_openpt(c.O_RDWR | c.O_NOCTTY);
    if (master < 0 or grantpt(master) != 0 or unlockpt(master) != 0) return error.PseudoTerminalFailed;
    defer _ = c.close(master);
    const terminal = ptsname(master) orelse return error.PseudoTerminalFailed;
    const path = try f.a.dupeSentinel(u8, std.mem.span(terminal), 0);
    const args = try f.a.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, args) |arg, *slot| slot.* = (try f.a.dupeSentinel(u8, arg, 0)).ptr;
    const block = try f.env.createPosixBlock(f.a, .{});
    const directory = try f.a.dupeSentinel(u8, f.base, 0);
    const launcher = c.fork();
    if (launcher < 0) return error.ForkFailed;
    if (launcher == 0) {
        if (c.setsid() < 0 or c.chdir(directory) != 0) c._exit(126);
        const slave = c.open(path, c.O_RDWR | c.O_NOCTTY, @as(c_int, 0));
        if (slave < 0 or ioctl(slave, tiocsctty, @as(c_int, 0)) != 0) c._exit(126);
        for ([_]c_int{ 0, 1, 2 }) |fd| if (c.dup2(slave, fd) < 0) c._exit(126);
        if (slave > 2) _ = c.close(slave);
        _ = c.close(master);
        _ = c.execve(args[0].?, @ptrCast(args.ptr), @ptrCast(block.slice.ptr));
        c._exit(127);
    }
    // Holding a terminal descriptor until the launcher is reaped makes the
    // final end-of-file prove that no detached process kept the terminal.
    const held = c.open(path, c.O_RDWR | c.O_NOCTTY, @as(c_int, 0));
    if (held < 0) return error.PseudoTerminalFailed;
    var holding = true;
    defer if (holding) {
        _ = c.close(held);
    };
    var collected: std.ArrayList(u8) = .empty;
    var status: c_int = 0;
    const deadline = std.Io.Clock.awake.now(f.io).toNanoseconds() + 35 * std.time.ns_per_s;
    while (true) {
        if (holding and c.waitpid(launcher, &status, c.WNOHANG) == launcher) {
            _ = c.close(held);
            holding = false;
        }
        if (std.Io.Clock.awake.now(f.io).toNanoseconds() >= deadline) {
            if (holding) {
                _ = c.kill(launcher, c.SIGKILL);
                _ = c.waitpid(launcher, &status, 0);
            }
            std.debug.print("terminal output: {s}\n", .{collected.items});
            return error.TerminalLaunchTimedOut;
        }
        var poll_fd: c.struct_pollfd = .{ .fd = master, .events = c.POLLIN, .revents = 0 };
        if (c.poll(&poll_fd, 1, 100) <= 0) continue;
        var buffer: [4096]u8 = undefined;
        const n = c.read(master, &buffer, buffer.len);
        if (n > 0) {
            try collected.appendSlice(f.a, buffer[0..@intCast(n)]);
        } else if (!holding) break;
    }
    const output = collected.items;
    try t.check(c.WIFEXITED(status) and c.WEXITSTATUS(status) == 0, output);
    return output;
}

fn records(f: *t.Fixture) ![]std.json.Value {
    const path = try std.fs.path.join(f.a, &.{ f.env.get("DOTLOCAL_RUNNER_STATE").?, "runner.json" });
    const data = std.Io.Dir.cwd().readFileAlloc(f.io, path, f.a, .limited(1 << 20)) catch |err| {
        if (err == error.FileNotFound) return &.{};
        return err;
    };
    return (try t.field(try t.json(f.a, data), "records")).array.items;
}
fn recordPid(record: std.json.Value, key: []const u8) !c_int {
    return @intCast((try t.field(try t.field(record, key), "pid")).integer);
}
fn routeNames(f: *t.Fixture) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for ((try f.call(.{ .operation = "list" })).routes orelse &.{}) |route| try names.append(f.a, route.name);
    return names.items;
}
fn routes(f: *t.Fixture, expected: []const []const u8) !void {
    const actual = try routeNames(f);
    try t.check(actual.len == expected.len, "unexpected route count");
    for (actual, expected) |name, want| try t.equal(name, want);
}
/// A supervisor removes its records and routes before it exits.
fn settled(f: *t.Fixture) !void {
    try t.check((try records(f)).len == 0, "stopped app retained records");
    try t.check((try routeNames(f)).len == 0, "stopped app retained routes");
}
fn answer(f: *t.Fixture, host: []const u8) !std.json.Value {
    const response = try f.request(host, "/");
    if (!std.mem.startsWith(u8, response, "HTTP/1.1 200")) {
        std.debug.print("{s}: {s}\n", .{ host, response });
        return error.IntegrationFailed;
    }
    return t.json(f.a, t.body(response));
}
fn pid(f: *t.Fixture, host: []const u8) !c_int {
    return @intCast((try t.field(try answer(f, host), "pid")).integer);
}
fn gone(f: *t.Fixture, target: c_int) !void {
    for (0..250) |_| {
        _ = t.lib.process.inspect(target) catch |err| {
            if (err == error.ProcessGone) return;
            return err;
        };
        try std.Io.sleep(f.io, .fromMilliseconds(20), .awake);
    }
    std.debug.print("process {d} survived shutdown\n", .{target});
    return error.IntegrationFailed;
}
fn mode(f: *t.Fixture, path: []const u8) !c_uint {
    var stat: c.struct_stat = undefined;
    if (c.lstat(try f.a.dupeSentinel(u8, path, 0), &stat) != 0) return error.StatFailed;
    return @intCast(stat.st_mode & 0o777);
}
fn write(f: *t.Fixture, name: []const u8, data: []const u8) !void {
    const path = try std.fs.path.join(f.a, &.{ f.base, name });
    try std.Io.Dir.cwd().createDirPath(f.io, std.fs.path.dirname(path).?);
    try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = path, .data = data });
}
/// Leaves no detached app behind when a check fails midway.
fn stopAll(f: *t.Fixture) void {
    const remaining = records(f) catch return;
    for (remaining) |record| {
        const name = t.text(t.field(record, "endpoint") catch continue, "name") catch continue;
        _ = f.command(&.{ "stop", name }, 0) catch {};
    }
}
