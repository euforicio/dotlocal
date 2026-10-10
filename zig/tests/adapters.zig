const std = @import("std");
const adapters = @import("../src/service.zig");
const apple = adapters.applecontainer;
const hosts = adapters.hosts;
const lan = adapters.lan;
const mdns = adapters.mdns;
const tailscale = adapters.tailscale;
const service = adapters;
const c = @import("native");
const a = std.testing.allocator;
const io = std.testing.io;

test "hosts real-file atomic synchronization stale-plan and cleanup" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    try tmp.dir.writeFile(io, .{ .sub_path = "hosts", .data = "127.0.0.1 localhost\n" });
    const file = try tmp.dir.openFile(io, "hosts", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    const path = try tmp.dir.realPathFileAlloc(io, "hosts", a);
    defer a.free(path);
    const config: hosts.Config = .{ .path = path, .uid = c.geteuid(), .gid = c.getegid() };
    const p = try hosts.plan(a, io, config, &.{ "b.local", "A.local", "a.local" });
    defer p.deinit(a);
    try std.testing.expect(p.changed);
    try std.testing.expect(try hosts.apply(a, io, config, p));
    try std.testing.expectError(error.StalePlan, hosts.apply(a, io, config, p));
    const clean = try hosts.plan(a, io, config, &.{});
    defer clean.deinit(a);
    try std.testing.expect(try hosts.apply(a, io, config, clean));
    const final = try tmp.dir.readFileAlloc(io, "hosts", a, .limited(1024));
    defer a.free(final);
    try std.testing.expectEqualStrings("127.0.0.1 localhost\n", final);
}
test "hosts rejects unsafe input and malformed ownership blocks" {
    try std.testing.expectError(error.InvalidName, hosts.normalizeName(a, "app.local.evil"));
    try std.testing.expectError(error.MalformedManagedBlock, hosts.render(a, hosts.begin_marker ++ "\n", &.{}));
    try std.testing.expectError(error.MalformedManagedBlock, hosts.render(a, hosts.end_marker ++ "\n", &.{}));
}
test "launchd plist is accepted by Apple's actual parser" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const manifest = try service.plist(a, .{});
    defer a.free(manifest);
    try tmp.dir.writeFile(io, .{ .sub_path = "service.plist", .data = manifest });
    const path = try tmp.dir.realPathFileAlloc(io, "service.plist", a);
    defer a.free(path);
    const result = std.process.run(a, io, .{ .argv = &.{ "/usr/bin/plutil", "-lint", path }, .stdout_limit = .limited(1024), .stderr_limit = .limited(1024) }) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try std.testing.expect(result.term.success());
    try std.testing.expectError(error.InvalidServicePath, service.install(a, io, .{ .executable = "relative" }, "/bin/ls"));
    try std.testing.expectError(error.InvalidServicePath, service.uninstall(a, io, .{ .executable = "relative" }));
    if (c.geteuid() != 0) try std.testing.expectError(error.PrivilegeRequired, service.trust(a, io, "/nonexistent.pem"));
    _ = try service.loaded(a, io, .{});
}
test "LAN actual interfaces refuse loopback and arbitrary public addresses" {
    const addresses = try lan.eligible(a, io);
    defer {
        for (addresses) |v| v.deinit(a);
        a.free(addresses);
    }
    for (addresses) |v| {
        try std.testing.expect(apple.privateAddress(v.host));
        try std.testing.expect(v.index != 0);
    }
    try std.testing.expectError(error.InvalidLANAddress, lan.select(a, io, "127.0.0.1"));
    try std.testing.expectError(error.InvalidLANAddress, lan.select(a, io, "8.8.8.8"));
    try std.testing.expectError(error.InvalidLANAddress, mdns.check(a, io, .{ .host = "app.local", .address = "127.0.0.1", .port = 8443 }));
    try std.testing.expectError(error.InvalidName, mdns.start(a, io, .{ .host = "evil.local/", .address = "127.0.0.1", .port = 8443 }));
}
test "Apple resolver uses the installed runtime and real missing object" {
    try std.testing.expectError(error.InvalidContainerID, apple.resolve(a, io, "container", "-option", 80, "http"));
    _ = apple.resolve(a, io, "container", "dotlocal-zig-does-not-exist", 80, "http") catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        error.InspectionFailed => return,
        else => return err,
    };
    return error.TestUnexpectedResult;
}
test "Tailscale actual read-only capability check and safe allocation" {
    try std.testing.expectEqual(@as(u16, 8443), try tailscale.allocate(.funnel, &.{443}));
    try std.testing.expectError(error.NoPort, tailscale.allocate(.funnel, &.{ 443, 8443, 10000 }));
    var s = tailscale.check(a, io, "/usr/local/bin/tailscale", .serve) catch |err| switch (err) {
        error.FileNotFound, error.TailscaleCommandFailed, error.TailscaleUnavailable, error.HTTPSUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer s.deinit();
    var p = try tailscale.plan(a, s, .{ .name = "nested.check", .target = "http://127.0.0.1:13000" });
    defer p.deinit();
    try std.testing.expect(p.registration.port != 0);
    try std.testing.expectEqualStrings("nested.check", p.registration.name);
    try std.testing.expectError(error.InvalidPlan, tailscale.apply(a, io, "/different/cli", p));
    try std.testing.expectError(error.InvalidPlan, tailscale.clean(a, io, "/different/cli", p));
    try tailscale.clean(a, io, s.executable, p);
}

test "Tailscale plan rejects non-canonical proxy target ports" {
    var s: tailscale.Snapshot = .{ .arena = .init(a), .executable = "/usr/local/bin/tailscale", .version = "1.98.9", .dns_name = "host.tailnet.ts.net", .used_ports = &.{}, .funnel_ports = &.{}, .active = &.{} };
    defer s.deinit();
    for ([_][]const u8{ "http://127.0.0.1:+8080", "http://127.0.0.1:80_80", "http://127.0.0.1:08080", "http://127.0.0.1:", "http://127.0.0.1:0" }) |target| {
        try std.testing.expectError(error.InvalidTarget, tailscale.plan(a, s, .{ .name = "app", .target = target }));
    }
    var p = try tailscale.plan(a, s, .{ .name = "app", .target = "http://127.0.0.1:8080" });
    defer p.deinit();
    try std.testing.expectEqual(@as(u16, 443), p.registration.port);
}

test "LAN session validates upstream before creating exposure" {
    try std.testing.expectError(error.InvalidUpstream, lan.Session.init(a, io, "/tmp", "8.8.8.8", 80, "check", null, false));
    try std.testing.expect((try service.groupID(a, "staff")) != 0);
}

test "explicit live mDNS publisher owns and stops its actual child" {
    if (c.getenv("DOTLOCAL_ZIG_LAN_TEST") == null) return error.SkipZigTest;
    const address = lan.select(a, io, null) catch |err| switch (err) {
        error.NoEligibleLANAddress => return error.SkipZigTest,
        else => return err,
    };
    defer address.deinit(a);
    const name = try std.fmt.allocPrint(a, "dotlocal-zig-mdns-{d}.local", .{c.getpid()});
    defer a.free(name);
    var publisher = try mdns.start(a, io, .{ .host = name, .address = address.host, .port = 13001 });
    const publisher_pid = publisher.child.id.?;
    _ = try @import("../src/process.zig").inspect(publisher_pid);
    publisher.close(io);
    publisher.close(io);
    try std.testing.expect(publisher.closed);
    try std.testing.expectError(error.ProcessGone, @import("../src/process.zig").inspect(publisher_pid));
}

const net = @import("../src/net.zig");
fn sessionLoop(session: *lan.Session, stop: *std.atomic.Value(bool)) void {
    session.run(stop) catch |err| std.debug.print("session loop: {s}\n", .{@errorName(err)});
}
fn curl(args: []const []const u8) !std.process.RunResult {
    var bounded: std.ArrayList([]const u8) = .empty;
    defer bounded.deinit(a);
    try bounded.appendSlice(a, &.{ args[0], "--max-time", "3" });
    try bounded.appendSlice(a, args[1..]);
    return std.process.run(a, io, .{ .argv = bounded.items, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
}
test "explicit LAN HTTPS session serves real Zig child with trusted certificate and rejects unknown host" {
    if (c.getenv("DOTLOCAL_ZIG_LAN_TEST") == null) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "index.html", .data = "dotlocal native LAN integration\n" });
    var pathbuf: [4096]u8 = undefined;
    const pathlen = try tmp.dir.realPath(io, &pathbuf);
    const directory = pathbuf[0..pathlen];
    const reserved = try net.tcp(a, "127.0.0.1", 0, true);
    var sockaddr: c.struct_sockaddr_in = undefined;
    var len: c.socklen_t = @sizeOf(@TypeOf(sockaddr));
    if (c.getsockname(reserved, @ptrCast(&sockaddr), &len) != 0) {
        net.close(reserved);
        return error.SocketInspectionFailed;
    }
    const app_port = std.mem.bigToNative(u16, sockaddr.sin_port);
    net.close(reserved);
    const portarg = try std.fmt.allocPrint(a, "{d}", .{app_port});
    defer a.free(portarg);
    var env = try (std.process.Environ{ .block = .{ .slice = std.mem.span(std.c.environ) } }).createMap(a);
    defer env.deinit();
    try env.put("PORT", portarg);
    const fixture_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "zig-out/bin/dotlocal-fixture", a);
    defer a.free(fixture_path);
    var child = try std.process.spawn(io, .{ .argv = &.{ fixture_path, "file", directory }, .environ_map = &env, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    defer child.kill(io);
    const upstream = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/", .{app_port});
    defer a.free(upstream);
    var ready = false;
    for (0..30) |_| {
        const result = try curl(&.{ "/usr/bin/curl", "--noproxy", "*", "-fsS", "--max-time", "1", upstream });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        if (result.term.success()) {
            ready = true;
            break;
        }
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    }
    try std.testing.expect(ready);
    const name = try std.fmt.allocPrint(a, "dotlocal-zig-session-{d}", .{c.getpid()});
    defer a.free(name);
    const session = try lan.Session.init(a, io, directory, "127.0.0.1", app_port, name, null, true);
    defer session.deinit();
    var stop: std.atomic.Value(bool) = .init(false);
    const thread = try std.Thread.spawn(.{}, sessionLoop, .{ session, &stop });
    defer {
        stop.store(true, .release);
        thread.join();
    }
    const resolve = try std.fmt.allocPrint(a, "{s}:{d}:{s}", .{ session.name, session.port, session.address.host });
    defer a.free(resolve);
    const result = try curl(&.{ "/usr/bin/curl", "--http1.1", "--noproxy", "*", "-v", "--max-time", "3", "--resolve", resolve, "--cacert", session.ca_path.?, "-fsS", session.url });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (!result.term.success()) std.debug.print("curl {s}\n", .{result.stderr});
    try std.testing.expect(result.term.success());
    try std.testing.expectEqualStrings("dotlocal native LAN integration\n", result.stdout);
    const h2 = try curl(&.{ "/usr/bin/curl", "--http2", "--noproxy", "*", "--resolve", resolve, "--cacert", session.ca_path.?, "-fsS", "-w", "HTTP/%{http_version}", session.url });
    defer a.free(h2.stdout);
    defer a.free(h2.stderr);
    if (!h2.term.success()) std.debug.print("LAN h2 curl {s}\n", .{h2.stderr});
    try std.testing.expect(h2.term.success());
    try std.testing.expectEqualStrings("dotlocal native LAN integration\nHTTP/2", h2.stdout);
    const bad = try curl(&.{ "/usr/bin/curl", "--http1.1", "--noproxy", "*", "--resolve", resolve, "--cacert", session.ca_path.?, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Host: other.local", session.url });
    defer a.free(bad.stdout);
    defer a.free(bad.stderr);
    try std.testing.expect(bad.term.success());
    try std.testing.expectEqualStrings("404", bad.stdout);
    const wrong_resolve = try std.fmt.allocPrint(a, "other.local:{d}:{s}", .{ session.port, session.address.host });
    defer a.free(wrong_resolve);
    const wrong_url = try std.fmt.allocPrint(a, "https://other.local:{d}", .{session.port});
    defer a.free(wrong_url);
    const wrong = try curl(&.{ "/usr/bin/curl", "--noproxy", "*", "--resolve", wrong_resolve, "--cacert", session.ca_path.?, "-sS", wrong_url });
    defer a.free(wrong.stdout);
    defer a.free(wrong.stderr);
    try std.testing.expect(!wrong.term.success());
}
test "explicit installed Apple runtime validates real running metadata" {
    const nameptr = c.getenv("DOTLOCAL_ZIG_CONTAINER_TEST");
    if (nameptr == null) return error.SkipZigTest;
    const portptr = c.getenv("DOTLOCAL_ZIG_CONTAINER_PORT");
    const port = if (portptr != null) try std.fmt.parseInt(u16, std.mem.span(portptr), 10) else @as(u16, 80);
    const endpoint = try apple.resolve(a, io, "container", std.mem.span(nameptr), port, "http");
    defer endpoint.deinit(a);
    try std.testing.expect(apple.privateAddress(endpoint.host));
    try std.testing.expect(endpoint.port == port);
    const url = try std.fmt.allocPrint(a, "http://{s}:{d}/", .{ endpoint.host, port });
    defer a.free(url);
    const result = try curl(&.{ "/usr/bin/curl", "--noproxy", "*", "-fsS", url });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try std.testing.expect(result.term.success());
}

const process_identity = @import("../src/process.zig");
const ChangeJournal = struct {
    dir: std.Io.Dir,
    withdrawn: usize = 0,
    ready: usize = 0,
    identity: ?process_identity.Identity = null,
    fail_ready: bool = false,
    fn changed(session: *lan.Session, context: ?*anyopaque) !void {
        const self: *ChangeJournal = @ptrCast(@alignCast(context.?));
        if (session.publisher) |publisher| {
            self.ready += 1;
            if (self.fail_ready) return error.JournalUnavailable;
            self.identity = try process_identity.inspect(publisher.child.id.?);
        } else {
            self.withdrawn += 1;
            self.identity = null;
        }
        const bytes = try std.json.Stringify.valueAlloc(a, self.identity, .{});
        defer a.free(bytes);
        var atomic = try self.dir.createFileAtomic(io, "advertisement.json", .{ .permissions = .fromMode(0o600), .replace = true });
        defer atomic.deinit(io);
        try atomic.file.writePositionalAll(io, bytes, 0);
        try atomic.file.sync(io);
        try atomic.replace(io);
    }
};
test "explicit live LAN rebind preserves CA and journals exact advertising child" {
    if (c.getenv("DOTLOCAL_ZIG_LAN_TEST") == null) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var pathbuf: [4096]u8 = undefined;
    const pathlen = try tmp.dir.realPath(io, &pathbuf);
    const name = try std.fmt.allocPrint(a, "dotlocal-zig-rebind-{d}", .{c.getpid()});
    defer a.free(name);
    const address = try lan.select(a, io, null);
    defer address.deinit(a);
    const session = try lan.Session.init(a, io, pathbuf[0..pathlen], "127.0.0.1", 13001, name, address.host, true);
    defer session.deinit();
    var journal: ChangeJournal = .{ .dir = tmp.dir };
    session.on_changed = ChangeJournal.changed;
    session.change_context = &journal;
    const original_pid = session.publisher.?.child.id.?;
    const original_port = session.port;
    const original_context = session.tls;
    try std.testing.expect(!try session.refresh());
    try std.testing.expectEqual(@as(usize, 0), journal.withdrawn);
    session.publisher.?.close(io); // Terminate only the actual owned advertising child.
    try std.testing.expect(try session.refresh());
    try std.testing.expectEqual(@as(usize, 1), journal.withdrawn);
    try std.testing.expectEqual(@as(usize, 1), journal.ready);
    try std.testing.expect(journal.identity.?.pid != original_pid);
    try std.testing.expectEqual(original_port, session.port);
    try std.testing.expect(session.tls == original_context);
    const persisted = try tmp.dir.readFileAlloc(io, "advertisement.json", a, .limited(4096));
    defer a.free(persisted);
    const parsed = try std.json.parseFromSlice(process_identity.Identity, a, persisted, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(journal.identity.?.start, parsed.value.start);
    session.publisher.?.close(io);
    journal.fail_ready = true;
    try std.testing.expectError(error.JournalUnavailable, session.refresh());
    try std.testing.expect(session.publisher == null and session.listener == -1);
    const withdrawn = try tmp.dir.readFileAlloc(io, "advertisement.json", a, .limited(4096));
    defer a.free(withdrawn);
    try std.testing.expectEqualStrings("null", withdrawn);
}

const LANSocketProbe = struct {
    listener: c_int,
    accepted: std.atomic.Value(bool) = .init(false),
    stop: std.atomic.Value(bool) = .init(false),
    fn serve(self: *LANSocketProbe) void {
        var poll: c.struct_pollfd = .{ .fd = self.listener, .events = c.POLLIN, .revents = 0 };
        while (!self.stop.load(.acquire)) {
            if (c.poll(&poll, 1, 100) <= 0 or (poll.revents & c.POLLIN) == 0) continue;
            const fd = c.accept(self.listener, null, null);
            if (fd < 0) continue;
            self.accepted.store(true, .release);
            const stream: net.Stream = .{ .fd = fd };
            defer stream.deinit();
            stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok") catch {};
            return;
        }
    }
};
test "explicit real LAN socket poll accepts after dns-sd subprocess readiness" {
    if (c.getenv("DOTLOCAL_ZIG_LAN_TEST") == null) return error.SkipZigTest;
    const address = try lan.select(a, io, null);
    defer address.deinit(a);
    const fd = try net.tcp(a, address.host, 0, true);
    defer net.close(fd);
    var sockaddr: c.struct_sockaddr_in = undefined;
    var len: c.socklen_t = @sizeOf(@TypeOf(sockaddr));
    if (c.getsockname(fd, @ptrCast(&sockaddr), &len) != 0) return error.ListenerInspectionFailed;
    const port = std.mem.bigToNative(u16, sockaddr.sin_port);
    const host = try std.fmt.allocPrint(a, "dotlocal-zig-probe-{d}.local", .{c.getpid()});
    defer a.free(host);
    var publisher = try mdns.start(a, io, .{ .host = host, .address = address.host, .port = port, .scheme = "http" });
    defer publisher.close(io);
    var probe: LANSocketProbe = .{ .listener = fd };
    const thread = try std.Thread.spawn(.{}, LANSocketProbe.serve, .{&probe});
    defer {
        probe.stop.store(true, .release);
        thread.join();
    }
    const url = try std.fmt.allocPrint(a, "http://{s}:{d}/", .{ address.host, port });
    defer a.free(url);
    const result = try curl(&.{ "/usr/bin/curl", "--noproxy", "*", "--max-time", "3", "-fsS", url });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (!result.term.success()) std.debug.print("LAN raw probe accepted={} {s}\n", .{ probe.accepted.load(.acquire), result.stderr });
    try std.testing.expect(result.term.success());
    try std.testing.expect(probe.accepted.load(.acquire));
    try std.testing.expectEqualStrings("ok", result.stdout);
}

const ngrok = @import("../src/ngrok.zig");
test "ngrok installed CLI version capabilities and credentials preflight are read-only" {
    var checked = ngrok.check(a, io, "/opt/homebrew/bin/ngrok") catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer checked.deinit();
    try std.testing.expect(std.mem.startsWith(u8, checked.version, "ngrok version 3."));
    const help = try std.process.run(a, io, .{ .argv = &.{ checked.executable, "http", "--help" }, .stdout_limit = .limited(65536), .stderr_limit = .limited(65536) });
    defer a.free(help.stdout);
    defer a.free(help.stderr);
    try std.testing.expect(help.term.success());
    // Actual CLI documentation output cannot be mistaken for tunnel readiness.
    try std.testing.expect((try ngrok.extractURL(a, help.stdout)) == null);
    try std.testing.expectError(error.InvalidNgrokURL, ngrok.validateURL("https://ngrok.com"));
    try std.testing.expectError(error.InvalidNgrokURL, ngrok.validateURL("https://127.0.0.1"));
    try std.testing.expectError(error.InvalidNgrokURL, ngrok.validateURL("https://account@example.com"));
    try std.testing.expectError(error.InvalidNgrokURL, ngrok.validateURL("https://example.com/path"));
    try std.testing.expectError(error.InvalidNgrokTarget, ngrok.start(a, io, .{ .state_dir = "/private/tmp", .port = 0, .host_header = "app.local" }));
}

test "hosts explicit multiple full DNS suffix plan applies atomically to a real file" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    try tmp.dir.writeFile(io, .{ .sub_path = "hosts", .data = "127.0.0.1 localhost\n" });
    const path = try tmp.dir.realPathFileAlloc(io, "hosts", a);
    defer a.free(path);
    const config: hosts.Config = .{ .path = path, .uid = c.geteuid(), .gid = c.getegid(), .suffixes = &.{ ".local", ".test", ".dev.example.com" } };
    const planned = try hosts.plan(a, io, config, &.{ "API.local", "nested.web.dev.example.com" });
    defer planned.deinit(a);
    try std.testing.expect(try hosts.apply(a, io, config, planned));
    const actual = try tmp.dir.readFileAlloc(io, "hosts", a, .limited(65536));
    defer a.free(actual);
    for ([_][]const u8{ "api.local", "api.test", "api.dev.example.com", "nested.web.local", "nested.web.test", "nested.web.dev.example.com" }) |name| try std.testing.expect(std.mem.indexOf(u8, actual, name) != null);
    const unchanged = try hosts.plan(a, io, config, &.{ "api.test", "nested.web.local" });
    defer unchanged.deinit(a);
    try std.testing.expect(!unchanged.changed);
    try std.testing.expectError(error.InvalidPlan, hosts.apply(a, io, .{ .path = path, .uid = c.geteuid(), .gid = c.getegid() }, unchanged));
    try std.testing.expectError(error.InvalidName, hosts.plan(a, io, config, &.{"foreign.invalid"}));
    const nested = try hosts.renderWithSuffixes(a, "", &.{"app.dev.example.com"}, &.{ ".example.com", ".dev.example.com" });
    defer a.free(nested);
    try std.testing.expect(std.mem.indexOf(u8, nested, "app.dev.dev.example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, nested, "\tapp.example.com\n") == null);
    try std.testing.expectError(error.InvalidName, hosts.renderWithSuffixes(a, "", &.{"app.local.."}, &.{".local"}));
}

test "ngrok exact cleanup rejects a reused identity without signalling a real child" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const directory = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const state = try std.fs.path.join(a, &.{ directory, "state" });
    defer a.free(state);
    const runner = @import("../src/runner.zig");
    var child = try runner.start(a, io, .{ .name = "ngrok-ownership", .argv = &.{ "/bin/sleep", "30" }, .state_directory = state, .proxy = false });
    defer child.deinit();
    var identity = try process_identity.inspect(child.record.identity.pid);
    identity.start += 1;
    const policy = try std.fmt.allocPrint(a, "{s}/ngrok-policy-00000000000000000000000000000000.json", .{state});
    defer a.free(policy);
    try std.testing.expectError(error.NgrokIdentityConflict, ngrok.clean(a, io, state, .{ .identity = identity, .policy = policy }));
    const still = try process_identity.inspect(child.record.identity.pid);
    try std.testing.expectEqual(child.record.identity.start, still.start);
}

test "sharing preparation failure removes its real pending journal before child execution" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const state = try std.fs.path.join(a, &.{ root, "state" });
    defer a.free(state);
    const sharing = @import("../src/sharing.zig");
    var session: sharing.Session = .{ .allocator = a, .io = io, .state_dir = state, .tld = ".dev.example.com", .use_ngrok = true, .ngrok_cli = "/nonexistent/dotlocal-ngrok" };
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    const marker = try std.fs.path.join(a, &.{ root, "child-executed" });
    defer a.free(marker);
    const runner = @import("../src/runner.zig");
    try std.testing.expectError(error.FileNotFound, runner.start(a, io, .{ .name = "nested.app", .tld = session.tld, .argv = &.{ "/usr/bin/touch", marker }, .state_directory = state, .base_environment = &environment, .before_start = sharing.Session.prepare, .on_prepare_failure = sharing.Session.cancel, .hook_context = &session }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "child-executed", .{}));
    sharing.Session.cancel(&session); // Runner's failure callback is also idempotent.
    try std.testing.expect(session.pending == null and session.journal_arena == null and session.tunnel == null);
    const directory = try std.Io.Dir.openDirAbsolute(io, state, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| try std.testing.expect(!std.mem.startsWith(u8, entry.name, "pending-") and !std.mem.startsWith(u8, entry.name, "ngrok-policy-"));
}

test "explicit public ngrok tunnel forwards exact Host to a real child and cleans owned identity" {
    const enabled = c.getenv("DOTLOCAL_ZIG_NGROK_TEST") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(enabled), "RUN-PUBLIC-NGROK")) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const state = try std.fs.path.join(a, &.{ root, "state" });
    defer a.free(state);
    const runner = @import("../src/runner.zig");
    const fixture_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "zig-out/bin/dotlocal-fixture", a);
    defer a.free(fixture_path);
    var child = try runner.start(a, io, .{ .name = "ngrok-live", .argv = &.{fixture_path}, .state_directory = state, .proxy = true });
    defer child.deinit();
    const local_url = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}", .{child.record.endpoint.port});
    defer a.free(local_url);
    var ready = false;
    for (0..40) |_| {
        const result = try curl(&.{ "/usr/bin/curl", "--noproxy", "*", "-fsS", local_url });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        if (result.term.success()) {
            ready = true;
            break;
        }
        try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    }
    try std.testing.expect(ready);
    const tunnel = try ngrok.start(a, io, .{ .state_dir = state, .port = child.record.endpoint.port, .host_header = "ngrok-live.local" });
    defer tunnel.deinit();
    const identity = tunnel.registration.identity;
    const policy = try a.dupe(u8, tunnel.registration.policy);
    defer a.free(policy);
    const result = try std.process.run(a, io, .{ .argv = &.{ "/usr/bin/curl", "--noproxy", "*", "--max-time", "15", "-fsS", "-H", "ngrok-skip-browser-warning: true", tunnel.registration.url }, .stdout_limit = .limited(65536), .stderr_limit = .limited(65536), .timeout = .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } } });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try std.testing.expect(result.term.success());
    const echoed = try std.json.parseFromSlice(std.json.Value, a, result.stdout, .{});
    defer echoed.deinit();
    try std.testing.expectEqualStrings("ngrok-live.local", echoed.value.object.get("headers").?.object.get("host").?.string);
    try tunnel.close();
    try std.testing.expectError(error.ProcessGone, process_identity.inspect(identity.pid));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.openFileAbsolute(io, policy, .{}));
    try ngrok.clean(a, io, state, .{ .identity = identity, .policy = policy });
}
