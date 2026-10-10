const file_stat = @import("dotlocal").process.file_stat;
const std = @import("std");
const t = @import("test_support.zig");
const H2 = @import("h2_test.zig").Client;
const c = t.c;
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.ExpectedCliFixtureAndDemo;
    const binary = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[1], init.arena.allocator());
    const server = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[2], init.arena.allocator());
    const demo = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[3], init.arena.allocator());
    try demoPrivacy(init, binary, demo);
    try runtime(init, binary, server);
    try cli(init, binary, server);
    try transport(init, binary, server);
    try @import("background_test.zig").run(init, binary, server);
    std.debug.print("PASS native Zig integration suite\n", .{});
}
fn demoPrivacy(init: std.process.Init, binary: []const u8, demo: []const u8) !void {
    var f = try t.Fixture.init(init, binary, demo, "http");
    defer f.cleanup();
    try f.env.put("DOTLOCAL_DEMO_PRIVATE_TEST", "private-demo-check");
    try f.start(&.{}, true);
    var child = try f.child(&.{ "run", "--name", "demo", demo });
    defer child.cleanup();
    var response: []const u8 = "";
    for (0..300) |_| {
        response = f.request("demo.local", "/api/info") catch "";
        if (std.mem.startsWith(u8, response, "HTTP/1.1 200")) break;
        try std.Io.sleep(f.io, .fromMilliseconds(50), .awake);
    }
    try t.check(std.mem.startsWith(u8, response, "HTTP/1.1 200"), "native demo did not start");
    const info = try t.json(f.a, t.body(response));
    try t.check(info == .object and info.object.count() == 4, "demo exposed extra fields");
    for ([_][]const u8{ "public_url", "forwarded_host", "forwarded_proto", "proxy_hop" }) |key| _ = try t.field(info, key);
    try t.check(std.mem.indexOf(u8, response, "private-demo-check") == null, "demo exposed environment contents");
    for ([_][]const u8{ "/environment", "/ws", "/payload", "/slow-head" }) |path| try t.check(std.mem.startsWith(u8, try f.request("demo.local", path), "HTTP/1.1 404"), "demo exposed fixture endpoint");
    std.debug.print("PASS native demo exposes only public routing fields and rejects diagnostic endpoints\n", .{});
}
fn runtime(init: std.process.Init, binary: []const u8, server: []const u8) !void {
    var f = try t.Fixture.init(init, binary, server, "http");
    defer f.cleanup();
    const upstream = try t.port(f.a);
    var backend = try f.backend(upstream);
    defer backend.cleanup();
    try f.start(&.{ "--tld", ".test" }, true);
    try f.alias("app", upstream);
    var peers: [132]c_int = undefined;
    var count: usize = 0;
    defer for (peers[0..count]) |fd| t.net.close(fd);
    for (&peers) |*fd| {
        fd.* = try t.net.tcp(f.a, "127.0.0.1", f.port, false);
        count += 1;
    }
    const start = std.Io.Clock.awake.now(f.io);
    try t.check((try f.call(.{ .operation = "status" })).status.?.running, "management blocked by idle public peers");
    try t.check(start.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 5000, "management admission latency");
    const other = try f.command(&.{ "daemon", "--state-dir", f.state, "--management-socket", try std.fs.path.join(f.a, &.{ f.base, "other.sock" }), "--scheme", "http", "--listen", try std.fmt.allocPrint(f.a, "127.0.0.1:{d}", .{try t.port(f.a)}) }, 1);
    try t.check(std.mem.indexOf(u8, other.stderr, "StateInUse") != null, "second daemon admitted same state");
    for (peers[0..count]) |fd| t.net.close(fd);
    count = 0;
    try f.stop();
    const stopped = try t.json(f.a, (try f.command(&.{"status"}, 0)).stdout);
    try t.check(!(try t.field(try t.field(stopped, "status"), "running")).bool, "stopped status reports running");
    try f.start(&.{}, false);
    const profile_status = (try f.call(.{ .operation = "status" })).status.?;
    try t.equal(profile_status.tld, ".test");
    try t.equal(profile_status.scheme, "http");
    const ca = try std.fs.path.join(f.a, &.{ f.state, "pki", "ca.pem" });
    if (std.Io.Dir.cwd().statFile(f.io, ca, .{})) |_| return error.HttpProfileCreatedCA else |err| if (err != error.FileNotFound) return err;
    try t.equal((try f.call(.{ .operation = "list" })).routes.?[0].name, "app.test");
    try f.stop();
    const profile = try f.a.dupeSentinel(u8, try std.fs.path.join(f.a, &.{ f.state, "zig-profile.json" }), 0);
    if (c.chmod(profile, 0o644) != 0) return error.ChmodFailed;
    _ = try f.command(&.{ "daemon", "--state-dir", f.state, "--management-socket", f.socket }, 1);
    if (c.chmod(profile, 0o600) != 0) return error.ChmodFailed;
    std.debug.print("PASS idle public peers, exclusive state, persisted profile, unsafe permissions and graceful drain\n", .{});
}
fn app(f: *t.Fixture, args: []const []const u8, hosts: []const []const u8) ![]std.json.Value {
    var child = try f.child(args);
    defer child.cleanup();
    const answers = try f.a.alloc(std.json.Value, hosts.len);
    for (hosts, answers) |host, *answer| answer.* = try f.waitApp(&child, host);
    const term = try child.stop();
    try t.check(term.success() or (term == .exited and term.exited == 143), "runner SIGTERM exit differs");
    try t.check((try f.call(.{ .operation = "list" })).routes.?.len == 0, "owned routes survived child shutdown");
    for (answers) |answer| {
        const pid: c_int = @intCast((try t.field(answer, "pid")).integer);
        if (t.lib.process.inspect(pid)) |_| return error.AppSurvivedSupervisor else |_| {}
    }
    return answers;
}
fn write(f: *t.Fixture, name: []const u8, data: []const u8) !void {
    const path = try std.fs.path.join(f.a, &.{ f.base, name });
    try std.Io.Dir.cwd().createDirPath(f.io, std.fs.path.dirname(path).?);
    try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = path, .data = data });
}
fn cli(init: std.process.Init, binary: []const u8, server: []const u8) !void {
    var f = try t.Fixture.init(init, binary, server, "https");
    defer f.cleanup();
    try f.env.put("DOTLOCAL_STATE_DIR", f.state);
    try f.env.put("NODE_EXTRA_CA_CERTS", "/explicit/caller-ca.pem");
    try f.start(&.{}, true);
    const answer = (try app(&f, &.{ "demo", server, "--child-option", "unchanged" }, &.{"demo.local"}))[0];
    try t.equal(try t.text(answer, "ca"), "/explicit/caller-ca.pem");
    try t.equal(try t.text(answer, "vite"), ".local");
    const argv = (try t.field(answer, "argv")).array.items;
    try t.check(argv.len == 2, "generic argv length changed");
    try t.equal(argv[0].string, "--child-option");
    try t.equal(argv[1].string, "unchanged");
    const fixed = try t.port(f.a);
    _ = try app(&f, &.{ "--name", "reserved-name", "--app-port", try t.number(f.a, fixed), server, "fixed", try t.number(f.a, fixed) }, &.{"reserved-name.local"});
    _ = try f.command(&.{ "run", "--name", "exit-child", "--", server, "exit", "17" }, 17);
    try t.check((try f.call(.{ .operation = "list" })).routes.?.len == 0, "failed child retained routes");
    const script = try std.fmt.allocPrint(f.a, "'{s}'", .{server});
    try write(&f, "package.json", try std.json.Stringify.valueAlloc(f.a, .{ .name = "bare-package", .scripts = .{ .dev = script } }, .{}));
    _ = try app(&f, &.{}, &.{"bare-package.local"});
    _ = try app(&f, &.{ "--script", "dev" }, &.{"bare-package.local"});
    try write(&f, "package.json", "{\"name\":\"root-project\",\"workspaces\":[\"packages/*\"]}");
    try write(&f, "packages/api/package.json", try std.json.Stringify.valueAlloc(f.a, .{ .name = "@suite/api", .scripts = .{ .dev = script } }, .{}));
    try write(&f, "packages/web/package.json", try std.json.Stringify.valueAlloc(f.a, .{ .name = "@suite/Web_App", .scripts = .{ .dev = script } }, .{}));
    _ = try app(&f, &.{}, &.{ "api.suite.local", "web-app.suite.local" });
    _ = try app(&f, &.{ "run", "--name", "explicit-project" }, &.{ "api.explicit-project.local", "web-app.explicit-project.local" });
    try write(&f, "packages/api/package.json", try std.json.Stringify.valueAlloc(f.a, .{ .name = "@suite/api", .scripts = .{ .dev = try std.fmt.allocPrint(f.a, "'{s}' exit 17 1000", .{server}) } }, .{}));
    _ = try f.command(&.{}, 17);
    try t.check((try f.call(.{ .operation = "list" })).routes.?.len == 0, "failed workspace retained routes");
    try f.stop();
    std.debug.print("PASS native generic argv, injected/fixed ports, exact exits, explicit CA, npm scripts and workspace group cleanup\n", .{});
    var automatic = try t.Fixture.init(init, binary, server, "http");
    defer automatic.cleanup();
    try automatic.env.put("DOTLOCAL_STATE_DIR", automatic.state);
    try automatic.env.put("DOTLOCAL_PORT", try t.number(automatic.a, automatic.port));
    try automatic.env.put("DOTLOCAL_HTTPS", "0");
    for ([_][]const u8{ "0", "false", "skip" }) |value| {
        try automatic.env.put("DOTLOCAL", value);
        const result = try automatic.command(&.{ "run", "--name", "bypass", server, "environment" }, 0);
        try t.check((try t.field(try t.json(automatic.a, result.stdout), "url")) == .null, "bypass injected proxy metadata");
        _ = try automatic.command(&.{ "run", "--name", "bypass", server, "exit", "23" }, 23);
        var stat: c.struct_stat = undefined;
        try t.check(file_stat.lstat(try automatic.a.dupeSentinel(u8, automatic.state, 0), &stat) != 0 and t.net.errno() == c.ENOENT, "bypass created proxy state");
    }
    _ = automatic.env.swapRemove("DOTLOCAL");
    if (t.lib.process.uid() != 0) {
        var first_run = try automatic.env.clone(automatic.a);
        defer first_run.deinit();
        _ = first_run.swapRemove("DOTLOCAL_PORT");
        _ = first_run.swapRemove("DOTLOCAL_HTTPS");
        const failed = try std.process.run(automatic.a, automatic.io, .{ .argv = &.{ binary, "run", "--name", "uninitialized", server, "environment" }, .environ_map = &first_run, .cwd = .{ .path = automatic.base }, .timeout = .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } } });
        try t.check(!failed.term.success() and std.mem.indexOf(u8, failed.stdout, "proxy start") != null and std.mem.indexOf(u8, failed.stdout, "\"url\"") == null, "first run started an app without privileged proxy setup");
    }
    const result = try automatic.command(&.{ "run", "--name", "auto", server, "environment" }, 0);
    try t.equal(try t.text(try t.json(automatic.a, std.mem.trim(u8, result.stdout[(std.mem.indexOfScalar(u8, result.stdout, '{') orelse return error.MissingJson)..], "\n")), "url"), try std.fmt.allocPrint(automatic.a, "http://auto.local:{d}", .{automatic.port}));
    defer {
        if (automatic.call(.{ .operation = "status" })) |current| {
            if (current.status.?.running) _ = automatic.command(&.{ "proxy", "stop" }, 0) catch {};
        } else |_| {}
    }
    _ = try automatic.command(&.{ "proxy", "start", "--port", try t.number(automatic.a, automatic.port), "--no-tls" }, 0);
    try t.check((try automatic.call(.{ .operation = "status" })).status.?.running, "automatic user proxy absent");
    _ = try automatic.command(&.{ "proxy", "stop" }, 0);
    _ = try automatic.command(&.{ "proxy", "start", "-p", try t.number(automatic.a, automatic.port), "--no-tls", "--tld", "local", "--tld", "test" }, 0);
    try t.check((try automatic.call(.{ .operation = "status" })).status.?.tlds.?.len == 2, "repeated TLD profile flags lost");
    _ = automatic.env.swapRemove("DOTLOCAL_PORT");
    _ = automatic.env.swapRemove("DOTLOCAL_HTTPS");
    _ = try automatic.command(&.{ "proxy", "start" }, 0);
    _ = try automatic.command(&.{ "proxy", "stop" }, 0);
    const logpath = try std.fs.path.join(automatic.a, &.{ automatic.state, "proxy.log" });
    try std.Io.Dir.cwd().deleteFile(automatic.io, logpath);
    const victim = try std.fs.path.join(automatic.a, &.{ automatic.base, "victim" });
    try write(&automatic, "victim", "keep");
    try std.Io.Dir.cwd().symLink(automatic.io, victim, logpath, .{});
    _ = try automatic.command(&.{ "proxy", "start", "--no-tls" }, 1);
    try t.equal(try std.Io.Dir.cwd().readFileAlloc(automatic.io, victim, automatic.a, .limited(1024)), "keep");
    std.debug.print("PASS bypass forms, automatic user proxy, repeated profiles and log symlink rejection\n", .{});
}
fn transport(init: std.process.Init, binary: []const u8, server: []const u8) !void {
    var f = try t.Fixture.init(init, binary, server, "https");
    defer f.cleanup();
    const upstream = try t.port(f.a);
    var backend = try f.backend(upstream);
    defer backend.cleanup();
    const redirect = try t.port(f.a);
    const flags = &.{ "--tld", "local", "--tld", "test", "--tld", "dev.example.com", "--wildcard", "--dual-loopback", "--redirect-listen", try std.fmt.allocPrint(f.a, "127.0.0.1:{d}", .{redirect}) };
    try f.start(flags, true);
    try f.alias("app", upstream);
    try f.alias("api.myapp", upstream);
    for ([_][]const u8{ "api.myapp.local", "api.myapp.test", "api.myapp.dev.example.com", "tenant.api.myapp.test" }) |host| {
        const response = try f.raw(host, try std.fmt.allocPrint(f.a, "GET /echo HTTP/1.1\r\nHost: {s}:{d}\r\nX-dotlocal-Hops: 2\r\n\r\n", .{ host, f.port }));
        const headers = try t.field(try t.json(f.a, t.body(response)), "headers");
        try t.equal(try t.text(headers, "host"), try std.fmt.allocPrint(f.a, "{s}:{d}", .{ host, f.port }));
        try t.equal(try t.text(headers, "x-forwarded-host"), try t.text(headers, "host"));
        try t.equal(try t.text(headers, "x-dotlocal-hops"), "3");
    }
    const long = try std.fmt.allocPrint(f.a, "{s}.{s}.{s}.{s}", .{ try repeat(f.a, 'a', 63), try repeat(f.a, 'b', 63), try repeat(f.a, 'c', 63), try repeat(f.a, 'd', 55) });
    try f.alias(long, upstream);
    try status(try f.request(try std.mem.concat(f.a, u8, &.{ long, ".local" }), "/echo"), 200);
    const authority = try std.fmt.allocPrint(f.a, "app.local:{d}", .{f.port});
    const response = try f.raw("app.local", try std.fmt.allocPrint(f.a, "POST /echo HTTP/1.1\r\nHost: {s}\r\nContent-Length: 9\r\nX-Forwarded-For: forged\r\nX-Forwarded-Host: forged\r\nX-Forwarded-Proto: http\r\nForwarded: forged\r\nX-Real-IP: forged\r\n\r\nreal body", .{authority}));
    try status(response, 200);
    const echo = try t.json(f.a, t.body(response));
    try t.equal(try t.text(echo, "body"), "real body");
    const headers = try t.field(echo, "headers");
    try t.equal(try t.text(headers, "x-forwarded-for"), "127.0.0.1");
    try t.equal(try t.text(headers, "x-forwarded-proto"), "https");
    try t.equal(try t.text(headers, "x-forwarded-host"), authority);
    try t.check(!headers.object.contains("forwarded") and !headers.object.contains("x-real-ip"), "forged forwarding metadata retained");
    try status(try f.request("unknown.local", "/"), 404);
    try status(try f.request("app.local.evil", "/"), 400);
    if (f.tls("unknown.local", "http/1.1", "127.0.0.1")) |stream| {
        stream.deinit();
        return error.UnregisteredSniAccepted;
    } else |_| {}
    for ([_][]const u8{ "5", "invalid" }, [_]u16{ 508, 400 }) |hops, code| try status(try f.raw("app.local", try std.fmt.allocPrint(f.a, "GET /echo HTTP/1.1\r\nHost: {s}\r\nX-dotlocal-Hops: {s}\r\n\r\n", .{ authority, hops })), code);
    const location = try f.request("app.local", "/redirect");
    try status(location, 302);
    try t.check(std.mem.indexOf(u8, location, try std.fmt.allocPrint(f.a, "Location: https://{s}/target?q=1", .{authority})) != null, "Location leaked internal endpoint");
    try t.check(std.mem.endsWith(u8, try f.request("app.local", "/legacy"), "legacy body"), "HTTP/1.0 EOF framing stalled");
    try protocol(&f, authority);
    try websocket(&f);
    try http2(&f);
    try upstreamTLS(&f, upstream);
    const v6 = try f.tls("app.local", "http/1.1", "::1");
    defer v6.deinit();
    try v6.writeAll(try std.fmt.allocPrint(f.a, "GET /echo HTTP/1.1\r\nHost: {s}\r\n\r\n", .{authority}));
    const v6response = try t.net.readFrame(f.a, v6, 65536);
    try t.equal(try t.text(try t.field(try t.json(f.a, t.body(v6response)), "headers"), "x-forwarded-for"), "::1");
    const redirect_stream: t.net.Stream = .{ .fd = try t.net.tcp(f.a, "127.0.0.1", redirect, false) };
    defer redirect_stream.deinit();
    try redirect_stream.writeAll("GET /target?q=1 HTTP/1.1\r\nHost: app.local\r\n\r\n");
    try status(try t.net.readFrame(f.a, redirect_stream, 65536), 308);
    try management(&f);
    try shutdown(&f);
    try f.start(flags, true);
    try status(try f.request("tenant.api.myapp.dev.example.com", "/echo"), 200);
    const ca = try std.Io.Dir.cwd().readFileAlloc(f.io, try std.fs.path.join(f.a, &.{ f.state, "pki/ca.pem" }), f.a, .limited(65536));
    const routes = (try f.call(.{ .operation = "list" })).routes.?;
    for (routes) |route| _ = try f.command(&.{ "alias", "--remove", route.name }, 0);
    try f.stop();
    try f.start(&.{ "--tld", "changed.test", "--wildcard", "--reconcile-profile" }, true);
    try f.alias("app", upstream);
    try status(try f.request("app.changed.test", "/echo"), 200);
    try t.equal(try std.Io.Dir.cwd().readFileAlloc(f.io, try std.fs.path.join(f.a, &.{ f.state, "pki/ca.pem" }), f.a, .limited(65536)), ca);
    std.debug.print("PASS canonical forwarding, namespace aliases, wildcard TLS, 253-byte names, restart, IPv6, redirects and retained CA\n", .{});
}
fn status(response: []const u8, expected: u16) !void {
    if (response.len < 12 or try std.fmt.parseInt(u16, response[9..12], 10) != expected) {
        std.debug.print("unexpected response: {s}\n", .{response[0..@min(response.len, 1024)]});
        return error.UnexpectedStatus;
    }
}
fn repeat(a: t.A, byte: u8, n: usize) ![]u8 {
    const bytes = try a.alloc(u8, n);
    @memset(bytes, byte);
    return bytes;
}
fn protocol(f: *t.Fixture, authority: []const u8) !void {
    const request = try std.fmt.allocPrint(f.a, "POST /echo HTTP/1.1\r\nHost: {s}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, X-Forwarded-For\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: real-request-trailer\r\nX-Forwarded-For: forged-trailer\r\n\r\n", .{authority});
    const echo = try t.json(f.a, t.body(try f.raw("app.local", request)));
    try t.equal(try t.text(echo, "body"), "hello");
    const trailers = try t.field(echo, "trailers");
    try t.equal(try t.text(trailers, "x-checksum"), "real-request-trailer");
    try t.check(trailers.object.count() == 1, "forwarding trailer forged");
    try t.check(std.mem.endsWith(u8, try f.request("app.local", "/trailers"), "0\r\nX-Checksum: real-response-trailer\r\n\r\n"), "response trailer lost");
    const hints = try f.request("app.local", "/hints");
    try t.check(std.mem.indexOf(u8, hints, "HTTP/1.1 103") != null and std.mem.indexOf(u8, hints, "HTTP/1.1 102") != null and std.mem.indexOf(u8, hints, "HTTP/1.1 200") != null, "informational sequence differs");
    const stream = try f.tls("app.local", "http/1.1", "127.0.0.1");
    defer stream.deinit();
    try stream.writeAll(try std.fmt.allocPrint(f.a, "POST /echo HTTP/1.1\r\nHost: {s}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n", .{authority}));
    try status((try t.lib.proxy.readHead(f.a, stream)).raw, 100);
    try stream.writeAll("hello");
    try status((try t.lib.proxy.readHead(f.a, stream)).raw, 200);
    for ([_][]const u8{ "Content-Length: 1\r\nTransfer-Encoding: chunked", "Content-Length: +1", "Content-Length: 1\r\nContent-Length: 2", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked", "Transfer-Encoding: gzip, chunked", "Trailer: Content-Length", "X-Invalid : value", "X-Test: valid\r\n continued" }) |fields| try status(try f.raw("app.local", try std.fmt.allocPrint(f.a, "POST /echo HTTP/1.1\r\nHost: {s}\r\n{s}\r\n\r\n", .{ authority, fields })), 400);
    try status(try f.request("app.local", "/ambiguous-response"), 502);
    const started = std.Io.Clock.awake.now(f.io);
    try status(try f.raw("app.local", try std.fmt.allocPrint(f.a, "POST /early HTTP/1.1\r\nHost: {s}\r\nContent-Length: 8388608\r\n\r\n", .{authority})), 413);
    try t.check(started.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 1500, "early final response waited for upload");
    std.debug.print("PASS real HTTP/1 trailers, 1xx, continue, EOF bodies, malformed framing and early refusal\n", .{});
}
fn websocket(f: *t.Fixture) !void {
    const stream = try f.tls("app.local", "http/1.1", "127.0.0.1");
    defer stream.deinit();
    try stream.writeAll(try std.fmt.allocPrint(f.a, "GET /ws HTTP/1.1\r\nHost: app.local:{d}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", .{f.port})); // RFC 6455 public example nonce. gitleaks:allow
    const head = try t.lib.proxy.readHead(f.a, stream);
    try status(head.raw, 101);
    try t.equal(head.get("Sec-WebSocket-Accept").?, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    const payload = "real native websocket echo";
    const frame = try masked(f.a, payload);
    try stream.writeAll(frame);
    const response = try f.a.alloc(u8, payload.len + 2);
    try @import("server.zig").exact(stream, response);
    try t.equal(response[2..], payload);
    std.debug.print("PASS real TLS WebSocket upgrade and duplex echo\n", .{});
}
fn masked(a: t.A, payload: []const u8) ![]u8 {
    const prefix: usize = if (payload.len < 126) 2 else 10;
    const frame = try a.alloc(u8, prefix + 4 + payload.len);
    frame[0] = 0x82;
    frame[1] = 128 | @as(u8, if (prefix == 2) @intCast(payload.len) else 127);
    if (prefix == 10) std.mem.writeInt(u64, frame[2..10], payload.len, .big);
    @memcpy(frame[prefix..][0..4], "abcd");
    for (payload, 0..) |byte, i| frame[prefix + 4 + i] = byte ^ "abcd"[i % 4];
    return frame;
}
fn checked(f: *t.Fixture, args: []const []const u8) !void {
    const result = try std.process.run(f.a, f.io, .{ .argv = args, .cwd = .{ .path = f.base }, .stdout_limit = .limited(65536), .stderr_limit = .limited(65536), .timeout = .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } } });
    if (!result.term.success()) {
        std.debug.print("{s}: {s}\n", .{ args[0], result.stderr });
        return error.FixtureCommandFailed;
    }
}
fn upstreamTLS(f: *t.Fixture, original: u16) !void {
    try write(f, "leaf.ext", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n");
    const key = try std.fs.path.join(f.a, &.{ f.base, "leaf.key" });
    const cert = try std.fs.path.join(f.a, &.{ f.base, "leaf.pem" });
    const csr = try std.fs.path.join(f.a, &.{ f.base, "leaf.csr" });
    const ext = try std.fs.path.join(f.a, &.{ f.base, "leaf.ext" });
    try checked(f, &.{ "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1" });
    try checked(f, &.{ "openssl", "x509", "-req", "-in", csr, "-CA", try std.fs.path.join(f.a, &.{ f.state, "pki/ca.pem" }), "-CAkey", try std.fs.path.join(f.a, &.{ f.state, "pki/root.pem" }), "-set_serial", "42", "-days", "2", "-extfile", ext, "-out", cert });
    const zkey = try f.a.dupeSentinel(u8, key, 0);
    if (c.chmod(zkey, 0o600) != 0) return error.ChmodFailed;
    for ([_]bool{ false, true }) |h2| {
        const upstream = try t.port(f.a);
        var env = try f.env.clone(f.a);
        defer env.deinit();
        try env.put("PORT", try t.number(f.a, upstream));
        var backend = try t.Child.start(f.io, if (h2) &.{ f.server, "tls", cert, key, "h2" } else &.{ f.server, "tls", cert, key }, &env, f.base, f.log);
        defer backend.cleanup();
        _ = try f.command(&.{ "alias", "app", "--force", "--host", "127.0.0.1", "--port", try t.number(f.a, upstream), "--protocol", "https" }, 0);
        const result = try f.curl("app.local", "/count", "--http2", &.{ "--data-binary", "hello" });
        const answer = try t.json(f.a, result.stdout);
        try t.check((try t.field(answer, "bytes")).integer == 5, "verified TLS upstream body differs");
        if (h2) {
            try t.equal(try t.text(answer, "proto"), "HTTP/2.0");
            const upload_arg = try std.mem.concat(f.a, u8, &.{ "@", f.base, "/upload.bin" });
            const counted = try t.json(f.a, (try f.curl("app.local", "/count", "--http2", &.{ "--data-binary", upload_arg })).stdout);
            try t.check((try t.field(counted, "bytes")).integer == 11 * 1024 * 1024, "native H2 upstream upload flow differs");
            const large = try f.curl("app.local", "/large", "--http2", &.{});
            try t.check(large.stdout.len == 12 * 1024 * 1024, "native H2 upstream download flow differs");
            for (large.stdout) |byte| if (byte != 'z') return error.CorruptH2Download;
            const hints = try f.curl("app.local", "/hints", "--http2", &.{"--include"});
            try t.check(std.mem.indexOf(u8, hints.stdout, "HTTP/2 103") != null and std.mem.indexOf(u8, hints.stdout, "HTTP/2 102") != null and std.mem.indexOf(u8, hints.stdout, "x-checksum: real-h2-upstream-trailer") != null, "native H2 upstream 1xx/trailers differ");
            const early = try f.raw("app.local", try std.fmt.allocPrint(f.a, "POST /early HTTP/1.1\r\nHost: app.local:{d}\r\nContent-Length: 8388608\r\n\r\n", .{f.port}));
            try status(early, 413);
            try h2Trailers(f, true);
            try sse(f);
            try uploadIsolation(f);
        }
        try websocket(f);
        try rfc8441(f);
        const rejected = try f.curl("app.local", "/legacy", "--http1.1", &.{});
        if (!h2) try t.check(std.mem.endsWith(u8, rejected.stdout, "legacy body"), "TLS H1 EOF response differs");
    }
    _ = try f.command(&.{ "alias", "app", "--force", "--host", "127.0.0.1", "--port", try t.number(f.a, original), "--protocol", "http" }, 0);
    std.debug.print("PASS independent verified TLS HTTP/1 and HTTP/2 upstreams, large flow control, 1xx/trailers and secure WebSockets\n", .{});
}
fn http2(f: *t.Fixture) !void {
    const echoed = try f.curl("app.local", "/echo", "--http2", &.{ "--data-binary", "http2 post", "--write-out", "\n%{http_version}" });
    try t.check(std.mem.endsWith(u8, echoed.stdout, "\n2"), "HTTP/2 ALPN fell back");
    try t.equal(try t.text(try t.json(f.a, echoed.stdout[0 .. echoed.stdout.len - 2]), "body"), "http2 post");
    try t.equal((try f.curl("app.local", "/chunked", "--http2", &.{})).stdout, "hello world");
    for ([_][]const u8{ "/trailers", "/hints" }, [_][]const u8{ "x-checksum: real-response-trailer", "HTTP/2 103" }) |path, expected| {
        const result = try f.curl("app.local", path, "--http2", &.{"--include"});
        try t.check(std.mem.indexOf(u8, result.stdout, expected) != null, "HTTP/2 trailer or informational response differs");
    }
    const upload = try f.a.alloc(u8, 11 * 1024 * 1024);
    @memset(upload, 'x');
    try write(f, "upload.bin", upload);
    const upload_arg = try std.mem.concat(f.a, u8, &.{ "@", f.base, "/upload.bin" });
    const counted = try t.json(f.a, (try f.curl("app.local", "/count", "--http2", &.{ "--data-binary", upload_arg })).stdout);
    try t.check((try t.field(counted, "bytes")).integer == upload.len, "large HTTP/2 upload differs");
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(upload, &digest, .{});
    try t.equal(try t.text(counted, "sha256"), &std.fmt.bytesToHex(digest, .lower));
    const unknown = try t.json(f.a, (try f.curl("app.local", "/count", "--http2", &.{ "--request", "POST", "--upload-file", try std.fs.path.join(f.a, &.{ f.base, "upload.bin" }), "-H", "Content-Length:" })).stdout);
    try t.equal(try t.text(unknown, "sha256"), &std.fmt.bytesToHex(digest, .lower));
    const download = try f.curl("app.local", "/large", "--http2", &.{});
    try t.check(download.stdout.len == 77824 * 192, "large HTTP/2 download differs");
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    const start = std.Io.Clock.awake.now(f.io);
    try h2.request(1, "/slow-head", false);
    try h2.request(3, "/echo", false);
    _ = try h2.response(3, "200");
    try t.check(start.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 1500, "slow headers blocked sibling H2 stream");
    _ = try h2.response(1, "200");
    for (0..256) |index| {
        const id: u32 = @intCast(5 + index * 2);
        try h2.request(id, "/echo", false);
        try t.equal(try t.text(try t.json(f.a, try h2.response(id, "200")), "path"), "/echo");
    }
    try rfc8441(f);
    try h2Trailers(f, false);
    try sse(f);
    const head = try f.curl("app.local", "/head", "--http2", &.{"--head"});
    try t.check(std.mem.indexOf(u8, head.stdout, "content-length: 123") != null, "HEAD representation length lost");
    std.debug.print("PASS HTTP/2 POST, chunked bodies, trailers, 1xx, large upload/download, sibling isolation and 256 reused streams\n", .{});
}
fn h2Trailers(f: *t.Fixture, native: bool) !void {
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    const fields = [_]@import("h2_test.zig").Header{ .{ .name = ":method", .value = "POST" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = h2.authority }, .{ .name = ":path", .value = "/echo" }, .{ .name = "content-length", .value = "5" }, .{ .name = "trailer", .value = "x-input, x-forwarded-for" } };
    try h2.headers(1, 4, &fields);
    try h2.send(0, 0, 1, "hello");
    try h2.headers(1, 5, &.{ .{ .name = "x-input", .value = "real-h2-trailer" }, .{ .name = "x-forwarded-for", .value = "forged" } });
    const echo = try t.json(f.a, try h2.response(1, "200"));
    const trailers = try t.field(echo, "trailers");
    try t.equal(try t.text(echo, "body"), "hello");
    try t.equal(try t.text(trailers, "x-input"), "real-h2-trailer");
    try t.check(trailers.object.count() == 1, "HTTP/2 forged forwarding trailer retained");
    if (native) try t.equal(try t.text(echo, "proto"), "HTTP/2.0");
    var malformed = fields;
    malformed[4].value = "6";
    try h2.headers(3, 4, &malformed);
    try h2.send(0, 1, 3, "hello");
    while (true) {
        const frame = try h2.receive();
        if (frame.id != 3) continue;
        if (frame.kind == 3) break;
        if (frame.kind == 1) {
            try t.check(!std.mem.eql(u8, try t.text(frame.headers, ":status"), "200"), "HTTP/2 mismatched content length accepted");
            break;
        }
    }
    for ([_][]const u8{ "connection", "transfer-encoding" }, [_][]const u8{ "close", "chunked" }, [_]u32{ 5, 7 }) |name, value, id| {
        malformed = fields;
        malformed[4] = .{ .name = name, .value = value };
        try h2.headers(id, 5, &malformed);
        while (true) {
            const frame = try h2.receive();
            if (frame.id != id) continue;
            if (frame.kind == 3) break;
            if (frame.kind == 1) {
                try t.check(!std.mem.eql(u8, try t.text(frame.headers, ":status"), "200"), "HTTP/2 prohibited framing accepted");
                break;
            }
        }
    }
    try h2.headers(9, 5, &.{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = h2.authority } });
    _ = try h2.response(9, "405");
    try h2.headers(11, 5, &.{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = h2.authority }, .{ .name = ":path", .value = "/ws" }, .{ .name = ":protocol", .value = "other" } });
    _ = try h2.response(11, "501");
    try h2.headers(13, 5, &.{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = h2.authority }, .{ .name = ":path", .value = "/ws" }, .{ .name = ":protocol", .value = "websocket" }, .{ .name = "x-dotlocal-hops", .value = "5" } });
    _ = try h2.response(13, "508");
    std.debug.print("PASS H2 request trailers, forged trailer filtering, malformed framing and unsupported CONNECT\n", .{});
}
fn sse(f: *t.Fixture) !void {
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    const start = std.Io.Clock.awake.now(f.io);
    try h2.request(1, "/sse", false);
    var data: std.ArrayList(u8) = .empty;
    var first = false;
    while (true) {
        const frame = try h2.receive();
        try t.check(frame.kind != 3 and frame.kind != 7, "SSE reset");
        if (frame.id != 1) continue;
        if (frame.kind == 0) {
            try data.appendSlice(f.a, frame.data);
            if (!first and std.mem.indexOf(u8, data.items, "data: first\n") != null) {
                try t.check(start.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 1500, "SSE first event buffered");
                first = true;
            }
        }
        if ((frame.kind == 0 or frame.kind == 1) and frame.flags & 1 != 0) break;
    }
    try t.equal(data.items, "data: first\n\ndata: second\n\n");
    std.debug.print("PASS live HTTP/2 SSE arrives before delayed second event\n", .{});
}
fn shutdown(f: *t.Fixture) !void {
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    try h2.request(1, "/stall-head", false);
    try h2.request(3, "/ws-idle", true);
    while (true) {
        const frame = try h2.receive();
        if (frame.kind == 1 and frame.id == 3) break;
        try t.check(frame.kind != 3 and frame.kind != 7, "idle tunnel failed before shutdown");
    }
    const h1 = try f.tls("app.local", "http/1.1", "127.0.0.1");
    defer h1.deinit();
    try h1.writeAll(try std.fmt.allocPrint(f.a, "GET /stall-head HTTP/1.1\r\nHost: app.local:{d}\r\n\r\n", .{f.port}));
    try std.Io.sleep(f.io, .fromMilliseconds(100), .awake);
    const start = std.Io.Clock.awake.now(f.io);
    try f.stop();
    try t.check(start.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 3000, "shutdown blocked on upstream or tunnel");
    std.debug.print("PASS shutdown cancels stalled H1/H2 headers and idle RFC8441 tunnel within three seconds\n", .{});
}
fn uploadIsolation(f: *t.Fixture) !void {
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    try h2.headers(1, 4, &.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = h2.authority }, .{ .name = ":path", .value = "/stall-h2-upload" }, .{ .name = "content-length", .value = "1048576" } });
    var buffer: [16384]u8 = undefined;
    @memset(&buffer, 'x');
    var sent: usize = 0;
    while (sent < 192 * 1024) {
        while (@min(h2.window, h2.connection_window) > 0 and sent < 192 * 1024) {
            const n: usize = @intCast(@min(@as(i64, @intCast(buffer.len)), @min(h2.window, h2.connection_window)));
            try h2.send(0, 0, 1, buffer[0..n]);
            sent += n;
            h2.window -= @intCast(n);
            h2.connection_window -= @intCast(n);
        }
        var poll: c.struct_pollfd = .{ .fd = h2.stream.fd, .events = c.POLLIN, .revents = 0 };
        if (c.SSL_pending(h2.stream.ssl) == 0 and c.poll(&poll, 1, 300) == 0) break;
        const frame = try h2.receive();
        try t.check(frame.kind != 3 and frame.kind != 7, "stalled upload reset before sibling check");
        if (frame.kind == 8) {
            const n = std.mem.readInt(u32, frame.data[0..4], .big) & 0x7fffffff;
            if (frame.id == 0) h2.connection_window += n;
            if (frame.id == 1) h2.window += n;
        }
    }
    try t.check(sent > 65535, "stalled fixture did not reach upstream flow-control limit");
    const start = std.Io.Clock.awake.now(f.io);
    try h2.request(3, "/count", false);
    const response = try t.json(f.a, try h2.response(3, "200"));
    try t.equal(try t.text(response, "proto"), "HTTP/2.0");
    try t.check(start.durationTo(std.Io.Clock.awake.now(f.io)).toMilliseconds() < 1500, "exhausted upstream upload window blocked sibling");
    std.debug.print("PASS same-session sibling while upstream upload exhausts its HTTP/2 window\n", .{});
}
fn rfc8441(f: *t.Fixture) !void {
    var h2 = try H2.init(f, "app.local");
    defer h2.deinit();
    try h2.request(1, "/ws", true);
    while (true) {
        const frame = try h2.receive();
        try t.check(frame.kind != 3 and frame.kind != 7, "RFC8441 handshake reset");
        if (frame.kind == 1 and frame.id == 1) {
            try t.equal(try t.text(frame.headers, ":status"), "200");
            for ([_][]const u8{ "connection", "upgrade", "sec-websocket-accept", "content-length" }) |key| try t.check(!frame.headers.object.contains(key), "RFC8441 leaked HTTP/1 handshake field");
            break;
        }
    }
    try h2.request(3, "/echo", false);
    _ = try h2.response(3, "200");
    const payload = try f.a.alloc(u8, 120 * 1024);
    @memset(payload, 'w');
    const frame = try masked(f.a, payload);
    var off: usize = 0;
    var updates: usize = 0;
    var response: std.ArrayList(u8) = .empty;
    while (true) {
        while (off < frame.len and @min(h2.window, h2.connection_window) > 0) {
            const n: usize = @intCast(@min(16384, @min(@min(h2.window, h2.connection_window), @as(i64, @intCast(frame.len - off)))));
            try h2.send(0, 0, 1, frame[off .. off + n]);
            off += n;
            h2.window -= @intCast(n);
            h2.connection_window -= @intCast(n);
        }
        const received = try h2.receive();
        try t.check(received.kind != 3 and received.kind != 7, "RFC8441 flow reset");
        if (received.kind == 8) {
            const n = std.mem.readInt(u32, received.data[0..4], .big) & 0x7fffffff;
            if (received.id == 0) h2.connection_window += n;
            if (received.id == 1) {
                h2.window += n;
                updates += 1;
            }
        }
        if (received.kind == 0 and received.id == 1) try response.appendSlice(f.a, received.data);
        if (received.id == 1 and (received.kind == 0 or received.kind == 1) and received.flags & 1 != 0) break;
    }
    try t.check(off == frame.len and updates > 1 and response.items.len == payload.len + 10, "RFC8441 did not exercise flow control");
    try t.equal(response.items[10..], payload);
    try h2.send(0, 1, 1, "");
    for ([_][]const u8{ "/ws-invalid", "/ws-reject" }, [_][]const u8{ "502", "403" }, [_]u32{ 5, 7 }) |path, expected, id| {
        try h2.request(id, path, true);
        const body = try h2.response(id, expected);
        if (id == 7) try t.equal(body, "denied");
        try h2.send(0, 1, id, "");
    }
    try h2.request(9, "/ws-idle", true);
    while (true) {
        const received = try h2.receive();
        if (received.kind == 1 and received.id == 9) break;
    }
    try h2.send(3, 0, 9, "\x00\x00\x00\x08");
    try h2.request(11, "/echo", false);
    _ = try h2.response(11, "200");
    std.debug.print("PASS RFC8441 translated handshake, 120KiB duplex flow control, idle sibling, refusals and RST cleanup\n", .{});
}
fn management(f: *t.Fixture) !void {
    const route = (try f.call(.{ .operation = "list" })).routes.?[0];
    const request = try std.json.Stringify.valueAlloc(f.a, t.lib.protocol.Request{ .id = "wire", .operation = "add", .route = route, .match = "absent" }, .{});
    const response = try rawManagement(f, request);
    try t.equal(try t.text(try t.field(response, "error"), "code"), "route_conflict");
    const stale = try rawManagement(f, try std.json.Stringify.valueAlloc(f.a, t.lib.protocol.Request{ .id = "stale", .operation = "remove", .name = route.name, .match = "owner", .expected_owner = .{ .kind = "process", .pid = c.getpid(), .process_start = 1, .refresh = "never" } }, .{}));
    try t.equal(try t.text(try t.field(stale, "error"), "code"), "route_conflict");
    try t.check((try f.call(.{ .operation = "list" })).routes.?.len != 0, "stale owner removed a live route");
    var invalid = route;
    invalid.host = "8.8.8.8";
    const rejected = try rawManagement(f, try std.json.Stringify.valueAlloc(f.a, t.lib.protocol.Request{ .id = "wire", .operation = "add", .route = invalid }, .{}));
    try t.check(!(try t.field(rejected, "ok")).bool, "public upstream accepted");
    for ([_][]const u8{ "version", "scheme", "owner", "kind", "refresh" }) |key| {
        var wire = try t.json(f.a, try std.json.Stringify.valueAlloc(f.a, t.lib.protocol.Request{ .id = "wire", .operation = "add", .route = route }, .{}));
        if (std.mem.eql(u8, key, "version")) {
            _ = wire.object.swapRemove(key);
        } else if (std.mem.eql(u8, key, "scheme") or std.mem.eql(u8, key, "owner")) {
            _ = wire.object.getPtr("route").?.object.swapRemove(key);
        } else _ = wire.object.getPtr("route").?.object.getPtr("owner").?.object.swapRemove(key);
        const result = try rawManagement(f, try std.json.Stringify.valueAlloc(f.a, wire, .{}));
        try t.equal(try t.text(try t.field(result, "error"), "code"), "invalid_request");
    }
    std.debug.print("PASS real management CAS, public address and missing wire field rejection\n", .{});
}
fn rawManagement(f: *t.Fixture, bytes: []const u8) !std.json.Value {
    const stream: t.net.Stream = .{ .fd = try t.net.connectUnix(f.a, f.socket) };
    defer stream.deinit();
    try stream.writeAll(bytes);
    try stream.writeAll("\n");
    _ = c.shutdown(stream.fd, c.SHUT_WR);
    return t.json(f.a, try t.net.readFrame(f.a, stream, 1 << 20));
}
