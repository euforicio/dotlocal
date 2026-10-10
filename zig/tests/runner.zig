const std = @import("std");
const runner = @import("../src/runner.zig");
const config = runner.projectconfig;
const allocator = std.testing.allocator;
const io = std.testing.io;

fn statePath(tmp: std.testing.TmpDir) ![]u8 {
    const base = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "state" });
}

test "stop rejects an altered identity and stops only its tracked app" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var first = try runner.start(allocator, io, .{ .name = "first", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer first.deinit();
    var second = try runner.start(allocator, io, .{ .name = "second", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer second.deinit();
    var wrong = first.record;
    wrong.identity.start += 1;
    try std.testing.expectError(error.IdentityMismatch, first.manager.stopRecord(wrong, 100));
    try std.testing.expectEqual(runner.Status.active, try runner.classify(first.record));
    try first.manager.stopRecord(first.record, 100);
    try std.testing.expectEqual(@as(u8, 143), (try first.wait()).exitCode());
    try std.testing.expectEqual(runner.Status.active, try runner.classify(second.record));
    var records = try second.manager.records();
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 1), records.value.records.len);
    try std.testing.expectEqualStrings(second.record.endpoint.name, records.value.records[0].endpoint.name);
}

test "direct child exact exit and durable matching cleanup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "exact-exit", .argv = &.{ "/bin/sh", "-c", "exit 37" }, .state_directory = path, .proxy = false });
    defer child.deinit();
    var records = try child.manager.records();
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 1), records.value.records.len);
    const result = try child.wait();
    try std.testing.expectEqual(@as(u8, 37), result.exitCode());
    var after = try child.manager.records();
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 0), after.value.records.len);
    try std.testing.expectEqual(@as(usize, 0), try child.manager.prune());
}

test "group identity signals child and matching cleanup protects current record" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "signal", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer child.deinit();
    try std.testing.expectEqual(runner.Status.active, try runner.classify(child.record));
    try child.manager.removeMatching(child.record.endpoint.name, .{ .pid = child.record.identity.pid, .start = child.record.identity.start + 1 });
    var records = try child.manager.records();
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 1), records.value.records.len);
    try std.testing.expectError(error.AlreadyRunning, runner.start(allocator, io, .{ .name = "signal", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false }));
    try child.signal(.TERM);
    const result = try child.wait();
    try std.testing.expectEqual(@as(u8, 143), result.exitCode());
    try std.testing.expect(result.term == .signal);
    try std.testing.expectError(error.ProcessGone, child.signal(.TERM));
}

test "real loopback port reservation managed environment and caller environment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    const output = try tmp.dir.createFile(io, "environment", .{ .read = true });
    defer output.close(io);
    var base = std.process.Environ.Map.init(allocator);
    defer base.deinit();
    try base.put("INHERITED", "base");
    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("CONFIGURED", "value with spaces");
    var child = try runner.start(allocator, io, .{ .name = "environment", .argv = &.{"/usr/bin/env"}, .state_directory = path, .base_environment = &base, .environment = &env, .stdout = .{ .file = output } });
    defer child.deinit();
    try std.testing.expect(child.record.endpoint.port > 0);
    try std.testing.expectEqualStrings("127.0.0.1", child.record.endpoint.host);
    try std.testing.expectEqual(@as(u8, 0), (try child.wait()).exitCode());
    const data = try tmp.dir.readFileAlloc(io, "environment", allocator, .limited(32 * 1024));
    defer allocator.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "HOST=127.0.0.1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "DOTLOCAL_URL=https://environment.local\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "INHERITED=base\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "CONFIGURED=value with spaces\n") != null);
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var occupied = try address.listen(io, .{});
    defer occupied.deinit(io);
    if (runner.start(allocator, io, .{ .name = "occupied", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .app_port = occupied.socket.address.ip4.port })) |process| {
        var p = process;
        p.deinit();
        return error.ExpectedPortFailure;
    } else |_| {}
}

test "strict project files search and name precedence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"name\":\"Example\",\"command\":[\"/usr/bin/env\"],\"env\":{\"VALUE\":\"ok\"}}" });
    const dir = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(dir);
    const found = (try config.find(allocator, io, dir)).?;
    defer allocator.free(found);
    var loaded = try config.load(allocator, io, found);
    defer loaded.deinit();
    try std.testing.expectEqualStrings("example.local", loaded.value.name);
    try std.testing.expect(loaded.value.proxy);
    const name = try config.resolveName(allocator, io, "flag", loaded.value.name, dir);
    defer allocator.free(name);
    try std.testing.expectEqualStrings("flag.local", name);
    const inferred = try config.resolveName(allocator, io, "", "", dir);
    defer allocator.free(inferred);
    try std.testing.expect(inferred.len > 0);
    try tmp.dir.writeFile(io, .{ .sub_path = "duplicate.json", .data = "{\"command\":[\"true\"],\"env\":{\"A\":\"1\",\"A\":\"2\"}}" });
    const duplicate = try std.fs.path.join(allocator, &.{ dir, "duplicate.json" });
    defer allocator.free(duplicate);
    try std.testing.expectError(error.DuplicateField, config.load(allocator, io, duplicate));
    try tmp.dir.symLink(io, "dotlocal.json", "link.json", .{});
    const link = try std.fs.path.join(allocator, &.{ dir, "link.json" });
    defer allocator.free(link);
    if (config.load(allocator, io, link)) |parsed| {
        parsed.deinit();
        return error.ExpectedSymlinkFailure;
    } else |_| {}
}

test "private state rejects unsafe permissions and symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    try std.Io.Dir.cwd().createDir(io, path, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeStateFile, runner.Manager.open(allocator, io, path));
    const state_dir = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
    defer state_dir.close(io);
    try state_dir.setPermissions(io, .fromMode(0o700));
    try tmp.dir.writeFile(io, .{ .sub_path = "outside.json", .data = "{\"version\":1,\"records\":[]}" });
    try state_dir.symLink(io, "../outside.json", "runner.json", .{});
    if (runner.Manager.open(allocator, io, path)) |manager| {
        var m = manager;
        m.deinit();
        return error.ExpectedSymlinkFailure;
    } else |_| {}
}

test "stale record pointing at the system init process is pruned, not fatal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var manager = try runner.Manager.open(allocator, io, path);
    defer manager.deinit();
    // PID 1 belongs to system init, not the recorded child. In a Linux PID
    // namespace its process group may also be invisible to this namespace.
    const uid = std.c.geteuid();
    const data = try std.fmt.allocPrint(allocator, "{{\"version\":1,\"records\":[{{\"endpoint\":{{\"name\":\"stale.localhost\",\"proxy\":false}},\"identity\":{{\"pid\":1,\"start\":1}},\"process_group\":1,\"uid\":{d},\"supervisor\":{{\"pid\":1,\"start\":1}},\"supervisor_uid\":{d},\"working_directory\":\"/\"}}]}}", .{ uid, uid });
    defer allocator.free(data);
    try manager.directory.writeFile(io, .{ .sub_path = "runner.json", .data = data, .flags = .{ .permissions = .fromMode(0o600) } });
    {
        var state = try manager.records();
        defer state.deinit();
        try std.testing.expectEqual(runner.Status.stale, try runner.classify(state.value.records[0]));
    }
    try std.testing.expectEqual(@as(usize, 1), try manager.prune());
    try manager.directory.writeFile(io, .{ .sub_path = "runner.json", .data = data, .flags = .{ .permissions = .fromMode(0o600) } });
    var child = try runner.start(allocator, io, .{ .name = "stale", .argv = &.{"/usr/bin/true"}, .state_directory = path, .proxy = false });
    defer child.deinit();
    try std.testing.expectEqual(@as(u8, 0), (try child.wait()).exitCode());
}

test "live child whose recorded supervisor points at system init is orphaned" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "orphaned", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer child.deinit();
    try std.testing.expectEqual(runner.Status.active, try runner.classify(child.record));
    var orphaned = child.record;
    orphaned.supervisor = .{ .pid = 1, .start = 1 };
    try std.testing.expectEqual(runner.Status.orphaned, try runner.classify(orphaned));
    try std.testing.expectEqual(runner.Status.active, try runner.classify(child.record));
}

test "bypass execution propagates exit codes and signal terminations" {
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try std.testing.expectEqual(@as(u8, 7), try runner.direct(io, &.{ "/bin/sh", "-c", "exit 7" }, &environment, null));
    try std.testing.expectEqual(@as(u8, 143), try runner.direct(io, &.{ "/bin/sh", "-c", "kill -TERM $$" }, &environment, null));
}

test "deinit reaps a live child that ignores TERM without hanging" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "stubborn", .argv = &.{ "/bin/sh", "-c", "trap '' TERM; exec /bin/sleep 60" }, .state_directory = path, .proxy = false });
    const pid = child.record.identity.pid;
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    child.deinit();
    // Reaped: the PID is no longer this process's child.
    try std.testing.expectEqual(@as(std.posix.pid_t, -1), std.c.waitpid(pid, null, std.c.W.NOHANG));
}

fn sendTermToSupervisor() !void {
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    try std.posix.kill(std.c.getpid(), .TERM);
}

test "supervisor forwards TERM and escalates ignored signals after grace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "supervised", .argv = &.{ "/bin/sh", "-c", "trap '' TERM; exec /bin/sleep 60" }, .state_directory = path, .proxy = false });
    defer child.deinit();
    // Wait for the real child to install its TERM disposition before sending.
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    var forwarding = try runner.SignalForwarder.init();
    defer forwarding.deinit();
    var sender = try io.concurrent(sendTermToSupervisor, .{});
    defer sender.cancel(io) catch {};
    const result = try child.waitForwarded(&forwarding, 100);
    try sender.await(io);
    try std.testing.expectEqual(@as(u8, 137), result.exitCode());
}

test "takeover rejects unrelated ownership and endpoint before signaling" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "takeover", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path });
    defer child.deinit();
    var route = child.record.route();
    route.owner.process_start += 1;
    try std.testing.expectError(error.IdentityMismatch, child.manager.forceTakeover(route, 100));
    route = child.record.route();
    route.port = if (route.port == 65535) 65534 else route.port + 1;
    try std.testing.expectError(error.IdentityMismatch, child.manager.forceTakeover(route, 100));
    try std.testing.expectEqual(runner.Status.active, try runner.classify(child.record));
    try child.manager.forceTakeover(child.record.route(), 100);
    try std.testing.expectEqual(@as(u8, 143), (try child.wait()).exitCode());
}

test "custom profile origin survives runner state validation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "profile", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .tld = ".test", .public_url = "http://profile.test:1355" });
    defer child.deinit();
    try std.testing.expectEqualStrings("profile.test", child.record.endpoint.name);
    try std.testing.expectEqualStrings("http://profile.test:1355", child.record.endpoint.url);
    var state = try child.manager.records();
    defer state.deinit();
    try std.testing.expectEqualStrings("http://profile.test:1355", state.value.records[0].endpoint.url);
}

test "prune removes real exited child state and retains every live child" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var live = try runner.start(allocator, io, .{ .name = "z-live", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer live.deinit();
    var exited = try runner.start(allocator, io, .{ .name = "a-exited", .argv = &.{"/usr/bin/true"}, .state_directory = path, .proxy = false });
    defer exited.deinit();
    // Reap through the real process handle while retaining the durable record,
    // representing a crash between process reap and registry cleanup.
    _ = try exited.child.wait(io);
    try std.testing.expectEqual(runner.Status.stale, try runner.classify(exited.record));
    var before = try live.manager.records();
    defer before.deinit();
    try std.testing.expectEqualStrings("a-exited.local", before.value.records[0].endpoint.name);
    try std.testing.expectEqual(@as(usize, 1), try live.manager.prune());
    try std.testing.expectEqual(runner.Status.active, try runner.classify(live.record));
    var after = try live.manager.records();
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 1), after.value.records.len);
    try std.testing.expectEqualStrings("z-live.local", after.value.records[0].endpoint.name);
}

test "state directory rejects symlink in any parent component" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "real", .fromMode(0o700));
    try tmp.dir.symLink(io, "real", "redirect", .{ .is_directory = true });
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "redirect", "state" });
    defer allocator.free(path);
    if (runner.Manager.open(allocator, io, path)) |manager| {
        var m = manager;
        m.deinit();
        return error.ExpectedSymlinkFailure;
    } else |_| {}
    const real = try tmp.dir.openDir(io, "real", .{});
    defer real.close(io);
    try std.testing.expectError(error.FileNotFound, real.openDir(io, "state", .{}));
}

test "unmatched process start cannot authorize a signal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    var child = try runner.start(allocator, io, .{ .name = "identity", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false });
    defer child.deinit();
    const original = child.record.identity;
    child.record.identity.start += 1;
    try std.testing.expectError(error.IdentityMismatch, child.signal(.KILL));
    child.record.identity = original;
    try std.testing.expectEqual(runner.Status.active, try runner.classify(child.record));
}

test "default child environment inherits real process variables" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    const output = try tmp.dir.createFile(io, "inherited", .{ .read = true });
    defer output.close(io);
    var child = try runner.start(allocator, io, .{ .name = "inherited", .argv = &.{"/usr/bin/env"}, .state_directory = path, .proxy = false, .app_port = 0, .stdout = .{ .file = output } });
    defer child.deinit();
    try std.testing.expectEqual(@as(u8, 0), (try child.wait()).exitCode());
    const data = try tmp.dir.readFileAlloc(io, "inherited", allocator, .limited(1024 * 1024));
    defer allocator.free(data);
    const environ: std.process.Environ = .{ .block = .{ .slice = std.mem.span(std.c.environ) } };
    const home = environ.getPosix("HOME") orelse return error.ExpectedHome;
    const entry = try std.fmt.allocPrint(allocator, "HOME={s}\n", .{home});
    defer allocator.free(entry);
    try std.testing.expect(std.mem.indexOf(u8, data, entry) != null);
    try std.testing.expectError(error.PublicURLRequiresProxy, runner.start(allocator, io, .{ .name = "invalid", .argv = &.{"/usr/bin/env"}, .state_directory = path, .proxy = false, .public_url = "http://invalid.local" }));
}

test "optional package configuration defaults scripts and manager precedence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"name\":\"@scope/Useful_App\",\"packageManager\":\"bun@1.3.0\",\"scripts\":{\"dev\":\"vite dev\",\"preview\":\"vite preview\"},\"dotlocal\":{\"name\":\"Example\",\"script\":\"preview\",\"appPort\":4311,\"turbo\":false}}" });
    const found = (try config.find(a, io, root)).?;
    try std.testing.expectEqualStrings("package.json", std.fs.path.basename(found));
    const loaded = (try config.loadCurrent(a, io, root)).?;
    defer loaded.deinit();
    try std.testing.expectEqualStrings("example.local", loaded.value.name);
    try std.testing.expectEqualStrings("preview", loaded.value.script);
    try std.testing.expectEqual(@as(u16, 4311), loaded.value.appPort);
    try std.testing.expectEqual(@as(usize, 0), loaded.value.command.len);
    const command = (try config.resolveCommand(a, io, root, loaded.value.script)).?;
    try expectArgv(&.{ "bun", "run", "preview" }, command);
    try std.testing.expect(try config.resolveCommand(a, io, root, "missing") == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"command\":[\"./server\",\"serve\"],\"env\":{\"CUSTOM\":\"value\"}}" });
    const direct = (try config.loadCurrent(a, io, root)).?;
    defer direct.deinit();
    try std.testing.expectEqualStrings("./server", direct.value.command[0]);
    try std.testing.expectEqualStrings("value", direct.value.env.map.get("CUSTOM").?);
    try std.testing.expectEqualStrings("useful-app", try @import("../src/auto.zig").inferName(a, io, root));
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"script\":\" \"}" });
    try std.testing.expectError(error.InvalidConfig, config.loadCurrent(a, io, root));
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"appPort\":0}" });
    try std.testing.expectError(error.InvalidPort, config.loadCurrent(a, io, root));
}

test "workspace globs excludes package metadata and nearest apps override" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    try tmp.dir.createDirPath(io, "apps/web");
    try tmp.dir.createDirPath(io, "apps/api");
    try tmp.dir.createDirPath(io, "apps/excluded");
    try tmp.dir.createDirPath(io, "tools/task");
    try tmp.dir.writeFile(io, .{ .sub_path = "pnpm-workspace.yaml", .data = "packages:\n  - 'apps/*'\n  - \"tools/*\" # tools\n  - '!apps/excluded'\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "apps/web/package.json", .data = "{\"name\":\"@site/web\",\"scripts\":{\"dev\":\"vite dev\"}}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "apps/api/package.json", .data = "{\"name\":\"api\",\"scripts\":{\"dev\":\"./server serve\"}}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "apps/excluded/package.json", .data = "{\"name\":\"excluded\"}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "tools/task/package.json", .data = "{\"name\":\"task\",\"scripts\":{\"build\":\"tsc\"}}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"name\":\"ignored-top\",\"apps\":{\"apps\":{\"appPort\":8000},\"apps/web\":{\"name\":\"frontend\",\"script\":\"preview\"},\"tools/task\":{\"proxy\":false}}}" });
    const workspace = @import("../src/workspace.zig");
    const ws = (try workspace.discover(a, io, try std.fs.path.join(a, &.{ root, "apps/web" }))).?;
    try std.testing.expectEqualStrings(root, ws.root);
    try std.testing.expectEqual(@as(usize, 3), ws.packages.len);
    try std.testing.expectEqualStrings("api", ws.packages[0].name.?);
    try std.testing.expectEqualStrings("web", ws.packages[1].name.?);
    try std.testing.expectEqualStrings("site", ws.packages[1].scope.?);
    const loaded = (try config.loadCurrent(a, io, root)).?;
    defer loaded.deinit();
    const app = config.resolveAppConfig(loaded.value, root, ws.packages[1].cwd);
    try std.testing.expectEqualStrings("frontend", app.name);
    try std.testing.expectEqualStrings("preview", app.script);
    try std.testing.expectEqual(@as(u16, 8000), config.resolveAppConfig(loaded.value, root, ws.packages[0].cwd).appPort);
    try std.testing.expect(!config.resolveAppConfig(loaded.value, root, ws.packages[2].cwd).proxy);
    try std.testing.expectEqualStrings("", config.resolveAppConfig(loaded.value, root, root).name);
    try tmp.dir.writeFile(io, .{ .sub_path = "apps/web/dotlocal.json", .data = "{\"proxy\":false}" });
    const package_config = (try config.loadCurrent(a, io, ws.packages[1].cwd)).?;
    defer package_config.deinit();
    const merged = config.resolveEffectiveAppConfig(loaded.value, root, ws.packages[1].cwd, package_config.value);
    try std.testing.expectEqualStrings("frontend", merged.name);
    try std.testing.expectEqualStrings("preview", merged.script);
    try std.testing.expect(!merged.proxy);
    try std.testing.expect(merged.proxy_set);
    const flow = try workspace.parsePnpm(a, "packages: ['apps/*', \"tools/*\"]\n");
    try expectArgv(&.{ "apps/*", "tools/*" }, flow);
    try tmp.dir.writeFile(io, .{ .sub_path = "pnpm-workspace.yaml", .data = "packages: ['../*']\n" });
    try std.testing.expectError(error.UnsafeWorkspacePattern, workspace.discover(a, io, root));
}

test "framework injection preserves known ports build commands and shell compound scripts" {
    const framework = @import("../src/framework.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const vite = try framework.injectFlags(a, &.{ "npx", "--package", "vite", "vite", "dev", "--", "positional" }, 4567, false);
    try expectArgv(&.{ "npx", "--package", "vite", "vite", "dev", "--port", "4567", "--strictPort", "--host", "127.0.0.1", "--", "positional" }, vite);
    const build = &[_][]const u8{ "vite", "--mode", "dev", "build" };
    try expectArgv(build, try framework.injectFlags(a, build, 4567, false));
    const generic = &[_][]const u8{ "./server", "serve" };
    try expectArgv(generic, try framework.injectFlags(a, generic, 4567, false));
    try expectArgv(&.{ "vite", "dev", "--port=8000", "--host", "127.0.0.1" }, try framework.injectFlags(a, &.{ "vite", "dev", "--port=8000" }, 4567, false));
    try expectArgv(&.{ "expo", "start", "--port", "4567" }, try framework.injectFlags(a, &.{ "expo", "start" }, 4567, true));
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"scripts\":{\"dev\":\"vite dev\",\"compound\":\"vite dev&&node app.js\",\"comment\":\"vite dev # comment\",\"expo\":\"expo start\",\"separator\":\"vite dev -- positional\"}}" });
    try expectArgv(&.{ "npm", "run", "dev", "--", "--host=0.0.0.0", "--port", "4567", "--strictPort" }, try framework.injectScriptFlags(a, io, root, &.{ "npm", "run", "dev", "--", "--host=0.0.0.0" }, 4567, false));
    try expectArgv(&.{ "npm", "run", "dev", "--", "--port", "4567", "--strictPort", "--host", "127.0.0.1" }, try framework.injectScriptFlags(a, io, root, &.{ "npm", "run", "dev" }, 4567, false));
    for ([_][]const u8{ "compound", "comment", "separator" }) |script| {
        const argv = &[_][]const u8{ "pnpm", "run", script };
        try expectArgv(argv, try framework.injectScriptFlags(a, io, root, argv, 4567, false));
    }
    try std.testing.expectEqualStrings("expo", (try framework.resolveBasename(a, io, root, &.{ "bun", "run", "expo" })).?);
    try std.testing.expect(!framework.unsafeToAppend("vite --tag '/foo&bar' 2>&1"));
    try std.testing.expect(framework.unsafeToAppend("vite dev &> out.log"));
}

fn runGit(cwd: []const u8, args: []const []const u8) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "git", "-C", cwd });
    try argv.appendSlice(allocator, args);
    const result = try std.process.run(allocator, io, .{ .argv = argv.items });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expect(result.term.success());
}

test "real git linked worktree branch prefix excludes root branches and detached heads" {
    const auto = @import("../src/auto.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try tmp.dir.createDirPath(io, "repo");
    const repo = try tmp.dir.realPathFileAlloc(io, "repo", a);
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const work = try std.fs.path.join(a, &.{ root, "work" });
    try runGit(repo, &.{ "init", "-b", "main" });
    try runGit(repo, &.{ "-c", "user.name=dotlocal Tests", "-c", "user.email=tests@example.invalid", "commit", "--allow-empty", "-m", "initial" });
    try runGit(repo, &.{ "worktree", "add", "-b", "feature/My_Branch", work });
    try std.testing.expectEqualStrings("my-branch", (try auto.worktreePrefix(a, io, work)).?);
    try std.testing.expect(try auto.worktreePrefix(a, io, repo) == null);
    try runGit(repo, &.{ "checkout", "-b", "feature/root" });
    try std.testing.expect(try auto.worktreePrefix(a, io, repo) == null);
    try runGit(work, &.{ "checkout", "--detach" });
    try std.testing.expect(try auto.worktreePrefix(a, io, work) == null);
    const long = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const label = try auto.sanitize(a, long);
    try std.testing.expectEqual(@as(usize, 63), label.len);
    try std.testing.expect(!std.mem.eql(u8, label, try auto.sanitize(a, long ++ "B")));
}

fn expectArgv(expected: []const []const u8, actual: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right| try std.testing.expectEqualStrings(left, right);
}

test "project config owns map keys after source JSON storage is released" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal.json", .data = "{\"env\":{\"STABLE_KEY\":\"value\"},\"appPort\":4311.0,\"apps\":{\"apps/web\":{\"script\":\"preview\"}}}" });
    const loaded = (try config.loadCurrent(allocator, io, root)).?;
    defer loaded.deinit();
    try std.testing.expectEqualStrings("value", loaded.value.env.map.get("STABLE_KEY").?);
    try std.testing.expectEqualStrings("preview", loaded.value.apps.?.map.get("apps/web").?.script);
    try std.testing.expectEqual(@as(u16, 4311), loaded.value.appPort);
}

// TIOCSCTTY: Linux from its ioctl table; Darwin _IO('t', 97), absent from std.c.
const tiocsctty: c_int = if (@import("builtin").os.tag == .linux) @intCast(std.os.linux.T.IOCSCTTY) else 0x20007461;
extern "c" fn posix_openpt(flags: c_int) c_int;
extern "c" fn grantpt(fd: c_int) c_int;
extern "c" fn unlockpt(fd: c_int) c_int;
extern "c" fn ptsname(fd: c_int) ?[*:0]const u8;

/// Reads `master` until `needle` appears; false after `timeout_ms` of silence.
fn awaitTerminalOutput(master: c_int, needle: []const u8, timeout_ms: i32) !bool {
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(allocator);
    while (std.mem.indexOf(u8, seen.items, needle) == null) {
        var fds = [_]std.posix.pollfd{.{ .fd = master, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&fds, timeout_ms) == 0) return false;
        var buffer: [256]u8 = undefined;
        const n = std.c.read(master, &buffer, buffer.len);
        if (n <= 0) return false;
        try seen.appendSlice(allocator, buffer[0..@intCast(n)]);
    }
    return true;
}

/// Runs the real CLI as a session leader whose controlling terminal is a new
/// pty, as in a login shell. Returns the supervisor PID and the pty master.
fn spawnOnTerminal(a: std.mem.Allocator, home: []const u8, script: [:0]const u8) !?struct { pid: c_int, master: c_int } {
    const native = @import("native");
    const executable = std.Io.Dir.cwd().realPathFileAlloc(io, "zig-out/bin/dotlocal", a) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const master = posix_openpt(native.O_RDWR | native.O_NOCTTY);
    if (master < 0) return null;
    errdefer _ = std.c.close(master);
    if (grantpt(master) != 0 or unlockpt(master) != 0) return null;
    const slave = try a.dupeSentinel(u8, std.mem.span(ptsname(master) orelse return null), 0);
    const directory = try a.dupeSentinel(u8, home, 0);
    const argv = [_:null]?[*:0]const u8{ try a.dupeSentinel(u8, executable, 0), "run", "/bin/sh", "-c", script };
    const home_entry = try std.fmt.allocPrintSentinel(a, "HOME={s}", .{home}, 0);
    const envp = [_:null]?[*:0]const u8{ "PATH=/usr/bin:/bin", "DOTLOCAL=0", home_entry };
    const pid = native.fork();
    if (pid < 0) return error.SystemResources;
    if (pid == 0) {
        if (std.c.setsid() < 0 or native.chdir(directory) != 0) std.c._exit(126);
        const fd = native.open(slave, native.O_RDWR);
        if (fd < 0 or std.c.ioctl(fd, tiocsctty, @as(c_int, 0)) != 0) std.c._exit(126);
        for ([_]c_int{ 0, 1, 2 }) |target| if (std.c.dup2(fd, target) < 0) std.c._exit(126);
        _ = std.c.execve(argv[0].?, &argv, &envp);
        std.c._exit(127);
    }
    return .{ .pid = pid, .master = master };
}

/// Closes the master first: a session leader exiting with a stopped foreground
/// group otherwise waits on its terminal, and the reap below would never return.
fn killTerminalSession(pid: c_int, master: c_int) void {
    var status: c_int = 0;
    _ = std.c.kill(-pid, .KILL);
    _ = std.c.kill(pid, .KILL);
    _ = std.c.close(master);
    _ = std.c.waitpid(pid, &status, 0);
}

/// Waits for `pid` to change state; null if it does not within `timeout_ms`.
fn awaitStatus(pid: c_int, flags: c_int, timeout_ms: u32) !?c_int {
    var status: c_int = 0;
    var waited: u32 = 0;
    while (waited < timeout_ms) : (waited += 20) {
        const rc = std.c.waitpid(pid, &status, std.c.W.NOHANG | flags);
        if (rc == pid) return status;
        if (rc < 0 and std.c.errno(rc) != .INTR) return error.WaitFailed;
        try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    return null;
}

test "real CLI hands its controlling terminal to an interactive child and takes it back" {
    const native = @import("native");
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", a);
    // The child reads the terminal; a background group would stop on SIGTTIN.
    const session = (try spawnOnTerminal(a, home, "read line; echo \"got:$line\"; exit 5")) orelse return error.SkipZigTest;
    errdefer killTerminalSession(session.pid, session.master);
    // Wait for the supervisor to start the child before typing.
    try std.Io.sleep(io, .fromMilliseconds(300), .awake);
    _ = std.c.write(session.master, "hello\n", 6);
    try std.testing.expect(try awaitTerminalOutput(session.master, "got:hello", 10_000));
    const status = (try awaitStatus(session.pid, 0, 10_000)) orelse return error.Timeout;
    try std.testing.expect(native.WIFEXITED(status));
    try std.testing.expectEqual(@as(c_int, 5), native.WEXITSTATUS(status));
    _ = std.c.close(session.master);
}

test "real CLI passes Ctrl-Z through: the supervisor stops with its child and resumes it" {
    const native = @import("native");
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", a);
    const session = (try spawnOnTerminal(a, home, "echo ready; read line; echo \"got:$line\"; exit 6")) orelse return error.SkipZigTest;
    errdefer killTerminalSession(session.pid, session.master);
    try std.testing.expect(try awaitTerminalOutput(session.master, "ready", 10_000));
    // Ctrl-Z: the line discipline sends SIGTSTP to the child's foreground group.
    _ = std.c.write(session.master, "\x1a", 1);
    const stopped = (try awaitStatus(session.pid, std.c.W.UNTRACED, 10_000)) orelse return error.SupervisorDidNotStop;
    try std.testing.expect(native.WIFSTOPPED(stopped));
    // As a shell's `fg` would, continue the supervisor; it resumes the child.
    _ = std.c.kill(session.pid, .CONT);
    try std.Io.sleep(io, .fromMilliseconds(300), .awake);
    _ = std.c.write(session.master, "hello\n", 6);
    try std.testing.expect(try awaitTerminalOutput(session.master, "got:hello", 10_000));
    const status = (try awaitStatus(session.pid, 0, 10_000)) orelse return error.Timeout;
    try std.testing.expect(native.WIFEXITED(status));
    try std.testing.expectEqual(@as(c_int, 6), native.WEXITSTATUS(status));
    _ = std.c.close(session.master);
}

test "workspace supervisor stops siblings after a failure and cleans up on start error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try statePath(tmp);
    defer allocator.free(path);
    const client: @import("../src/client.zig").Client = .{ .allocator = allocator, .io = io, .socket_path = "/nonexistent/dotlocal.sock" };
    const started = std.Io.Clock.awake.now(io);
    const code = try runner.runMany(allocator, io, client, &.{
        .{ .name = "sibling", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false },
        .{ .name = "failing", .argv = &.{ "/bin/sh", "-c", "sleep 0.2; exit 3" }, .state_directory = path, .proxy = false },
    });
    try std.testing.expectEqual(@as(u8, 3), code);
    // TERM stops the sibling well before the 5s KILL grace.
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds() < 4000);
    try std.testing.expectError(error.FileNotFound, runner.runMany(allocator, io, client, &.{
        .{ .name = "live", .argv = &.{ "/bin/sleep", "60" }, .state_directory = path, .proxy = false },
        .{ .name = "missing", .argv = &.{"/nonexistent/dotlocal-command"}, .state_directory = path, .proxy = false },
    }));
    var manager = try runner.Manager.open(allocator, io, path);
    defer manager.deinit();
    var records = try manager.records();
    defer records.deinit();
    try std.testing.expectEqual(@as(usize, 0), records.value.records.len);
}

test "workspace globs support multiple stars and globstar without node_modules" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    for ([_][]const u8{ "packages/ui", "packages/nested/deep/lib", "packages/node_modules/dep", "packages/.cache/tool", "apps/site/web", "apps/admin/web", "apps/admin/api", "services/auth-svc-v1", "services/auth-v1" }) |dir| {
        try tmp.dir.createDirPath(io, dir);
        const manifest = try std.fs.path.join(a, &.{ dir, "package.json" });
        try tmp.dir.writeFile(io, .{ .sub_path = manifest, .data = "{}" });
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"workspaces\":[\"packages/**\",\"apps/*/web\",\"services/*-svc-*\",\"!packages/nested/**\"]}" });
    const workspace = @import("../src/workspace.zig");
    const ws = (try workspace.discover(a, io, root)).?;
    var relative: std.ArrayList([]const u8) = .empty;
    for (ws.packages) |package| try relative.append(a, package.cwd[root.len + 1 ..]);
    try expectArgv(&.{ "apps/admin/web", "apps/site/web", "packages/ui", "services/auth-svc-v1" }, relative.items);
}

test "workspace globstar counts only packages and stops at the depth limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    // More plain directories than the package cap must not count toward it.
    for (0..4100) |i| try tmp.dir.createDirPath(io, try std.fmt.allocPrint(a, "packages/plain-{d}", .{i}));
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a, "packages/deep");
    for (0..40) |level| {
        try deep.appendSlice(a, "/d");
        try tmp.dir.createDirPath(io, deep.items);
        if (level == 3 or level == 39) try tmp.dir.writeFile(io, .{ .sub_path = try std.fs.path.join(a, &.{ deep.items, "package.json" }), .data = "{}" });
    }
    for ([_][]const u8{ "packages/ui", "packages/plain-7/lib", "outside/pkg" }) |dir| {
        try tmp.dir.createDirPath(io, dir);
        try tmp.dir.writeFile(io, .{ .sub_path = try std.fs.path.join(a, &.{ dir, "package.json" }), .data = "{}" });
    }
    try tmp.dir.symLink(io, "../outside", "packages/linked", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"workspaces\":[\"packages/**\"]}" });
    const workspace = @import("../src/workspace.zig");
    const ws = (try workspace.discover(a, io, root)).?;
    var relative: std.ArrayList([]const u8) = .empty;
    for (ws.packages) |package| try relative.append(a, package.cwd[root.len + 1 ..]);
    // The level-39 package lies beyond the depth limit and the symlink is never followed.
    try expectArgv(&.{ "packages/deep/d/d/d/d", "packages/plain-7/lib", "packages/ui" }, relative.items);
}

test "pnpm workspace file marks the root and must be readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const workspace = @import("../src/workspace.zig");
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"workspaces\":[\"apps/*\"]}" });
    const oversized = try a.alloc(u8, 1024 * 1024 + 1);
    @memset(oversized, '#');
    try tmp.dir.writeFile(io, .{ .sub_path = "pnpm-workspace.yaml", .data = oversized });
    try std.testing.expectEqualStrings(root, (try workspace.findRoot(a, io, root)).?);
    try std.testing.expectError(error.WorkspaceFileTooLarge, workspace.discover(a, io, root));
    try tmp.dir.writeFile(io, .{ .sub_path = "pnpm-workspace.yaml", .data = "packages: ['apps/*']\n" });
    const file = try tmp.dir.openFile(io, "pnpm-workspace.yaml", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0));
    try std.testing.expectError(error.AccessDenied, workspace.discover(a, io, root));
}

fn resolveCommandOwned(a: std.mem.Allocator, root: []const u8) !void {
    const argv = (try config.resolveCommand(a, io, root, "")).?;
    defer {
        for (argv) |arg| a.free(arg);
        a.free(argv);
    }
    try expectArgv(&.{ "pnpm", "run", "dev" }, argv);
}

test "resolveCommand frees partial allocations on every failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{\"packageManager\":\"pnpm@10.0.0\",\"scripts\":{\"dev\":\"vite\"}}" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    try std.testing.checkAllAllocationFailures(allocator, resolveCommandOwned, .{root});
}
