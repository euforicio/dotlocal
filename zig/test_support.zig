//! Native integration helpers. Every process, listener and certificate is real.
const std = @import("std");
pub const lib = @import("dotlocal");
pub const net = lib.net;
pub const c = net.c;
pub const A = std.mem.Allocator;
pub fn check(ok: bool, message: []const u8) !void {
    if (!ok) {
        std.debug.print("FAIL {s}\n", .{message});
        return error.IntegrationFailed;
    }
}
pub fn port(a: A) !u16 {
    const fd = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(fd);
    var address: c.struct_sockaddr_in = undefined;
    var size: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(fd, @ptrCast(&address), &size) != 0) return error.SocketInspectionFailed;
    return std.mem.bigToNative(u16, address.sin_port);
}
pub fn number(a: A, n: anytype) ![]const u8 {
    return std.fmt.allocPrint(a, "{d}", .{n});
}
pub fn json(a: A, bytes: []const u8) !std.json.Value {
    return (try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always })).value;
}
pub fn field(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.ExpectedObject;
    return value.object.get(key) orelse error.MissingField;
}
pub fn text(value: std.json.Value, key: []const u8) ![]const u8 {
    const item = try field(value, key);
    if (item != .string) return error.ExpectedString;
    return item.string;
}
pub fn equal(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        std.debug.print("expected: {s}\nactual: {s}\n", .{ expected, actual });
        return error.IntegrationFailed;
    }
}
pub const Child = struct {
    child: std.process.Child,
    identity: lib.process.Identity,
    io: std.Io,
    pub fn start(io: std.Io, args: []const []const u8, env: *const std.process.Environ.Map, cwd: []const u8, log: std.Io.File) !Child {
        var child = try std.process.spawn(io, .{ .argv = args, .environ_map = env, .cwd = .{ .path = cwd }, .pgid = 0, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log } });
        errdefer child.kill(io);
        return .{ .child = child, .identity = try lib.process.inspect(child.id.?), .io = io };
    }
    pub fn stop(self: *Child) !std.process.Child.Term {
        if (self.child.id == null) return .{ .exited = 0 };
        lib.process.signal(self.identity, .TERM) catch |err| if (err != error.ProcessGone and err != error.FileNotFound) return err;
        for (0..160) |_| {
            _ = lib.process.inspect(self.identity.pid) catch break;
            try std.Io.sleep(self.io, .fromMilliseconds(50), .awake);
        }
        if (lib.process.inspect(self.identity.pid)) |_| {
            lib.process.signal(self.identity, .KILL) catch {};
            self.child.kill(self.io);
            return error.ChildDidNotDrain;
        } else |_| {}
        return self.child.wait(self.io);
    }
    pub fn cleanup(self: *Child) void {
        _ = self.stop() catch {
            lib.process.signal(self.identity, .KILL) catch {};
            self.child.kill(self.io);
        };
    }
};
pub const Fixture = struct {
    a: A,
    io: std.Io,
    binary: []const u8,
    server: []const u8,
    base: []const u8,
    state: []const u8,
    socket: []const u8,
    log: std.Io.File,
    env: std.process.Environ.Map,
    port: u16,
    scheme: []const u8,
    daemon: ?Child = null,
    pub fn init(context: std.process.Init, binary: []const u8, server: []const u8, scheme: []const u8) !Fixture {
        const a = context.arena.allocator();
        var nonce: [8]u8 = undefined;
        context.io.random(&nonce);
        const temporary_path = try std.fmt.allocPrint(a, "/tmp/dotlocal-native-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        try std.Io.Dir.cwd().createDirPath(context.io, temporary_path);
        const base = try std.Io.Dir.cwd().realPathFileAlloc(context.io, temporary_path, a);
        const z = try a.dupeSentinel(u8, base, 0);
        if (c.chmod(z, 0o700) != 0) return error.PermissionsFailed;
        const log = try std.Io.Dir.cwd().createFile(context.io, try std.fs.path.join(a, &.{ base, "process.log" }), .{});
        var env = try context.environ_map.clone(a);
        for ([_][]const u8{ "DOTLOCAL", "DOTLOCAL_PORT", "DOTLOCAL_HTTPS", "DOTLOCAL_STATE_DIR", "DOTLOCAL_TLD", "DOTLOCAL_URL", "DOTLOCAL_LAN", "DOTLOCAL_NGROK", "DOTLOCAL_TAILSCALE", "DOTLOCAL_FUNNEL", "PORT" }) |key| _ = env.swapRemove(key);
        const socket = try std.fs.path.join(a, &.{ base, "m.sock" });
        try env.put("DOTLOCAL_SOCKET", socket);
        try env.put("DOTLOCAL_RUNNER_STATE", try std.fs.path.join(a, &.{ base, "runners" }));
        return .{ .a = a, .io = context.io, .binary = binary, .server = server, .base = base, .state = try std.fs.path.join(a, &.{ base, "state" }), .socket = socket, .log = log, .env = env, .port = try port(a), .scheme = scheme };
    }
    pub fn cleanup(self: *Fixture) void {
        if (self.daemon) |*daemon| daemon.cleanup();
        self.log.close(self.io);
        self.env.deinit();
        std.Io.Dir.cwd().deleteTree(self.io, self.base) catch {};
    }
    pub fn start(self: *Fixture, flags: []const []const u8, explicit: bool) !void {
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(self.a, &.{ self.binary, "daemon", "--state-dir", self.state, "--management-socket", self.socket });
        if (explicit) try args.appendSlice(self.a, &.{ "--scheme", self.scheme, "--listen", try std.fmt.allocPrint(self.a, "127.0.0.1:{d}", .{self.port}) });
        try args.appendSlice(self.a, flags);
        self.daemon = try Child.start(self.io, args.items, &self.env, self.base, self.log);
        for (0..400) |_| {
            if (self.call(.{ .operation = "status" })) |response| {
                if (response.status.?.running) return;
            } else |_| {}
            _ = lib.process.inspect(self.daemon.?.identity.pid) catch {
                try self.diagnostics();
                return error.DaemonExited;
            };
            try std.Io.sleep(self.io, .fromMilliseconds(50), .awake);
        }
        try self.diagnostics();
        return error.DaemonNotReady;
    }
    pub fn diagnostics(self: *Fixture) !void {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(self.io, try std.fs.path.join(self.a, &.{ self.base, "process.log" }), self.a, .limited(1 << 20));
        std.debug.print("{s}\n", .{bytes});
    }
    pub fn stop(self: *Fixture) !void {
        if (self.daemon) |*daemon_child| try check((try daemon_child.stop()).success(), "daemon failed graceful shutdown");
        self.daemon = null;
    }
    pub fn call(self: *Fixture, message: lib.protocol.Request) !lib.protocol.Response {
        const client: lib.client.Client = .{ .allocator = self.a, .io = self.io, .socket_path = self.socket };
        return (try client.call(message)).value;
    }
    pub fn command(self: *Fixture, args: []const []const u8, expected: u8) !std.process.RunResult {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(self.a, self.binary);
        try argv.appendSlice(self.a, args);
        const result = try std.process.run(self.a, self.io, .{ .argv = argv.items, .environ_map = &self.env, .cwd = .{ .path = self.base }, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } } });
        if (result.term != .exited or result.term.exited != expected) {
            std.debug.print("command {s}: {f}\n{s}\n{s}\n", .{ args[0], result.term, result.stdout, result.stderr });
            try self.diagnostics();
            return error.UnexpectedExit;
        }
        return result;
    }
    pub fn child(self: *Fixture, args: []const []const u8) !Child {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(self.a, self.binary);
        try argv.appendSlice(self.a, args);
        return Child.start(self.io, argv.items, &self.env, self.base, self.log);
    }
    pub fn backend(self: *Fixture, fixed: u16) !Child {
        var env = try self.env.clone(self.a);
        defer env.deinit();
        try env.put("PORT", try number(self.a, fixed));
        return Child.start(self.io, &.{self.server}, &env, self.base, self.log);
    }
    pub fn alias(self: *Fixture, name: []const u8, upstream: u16) !void {
        _ = try self.command(&.{ "alias", name, "--host", "127.0.0.1", "--port", try number(self.a, upstream) }, 0);
    }
    pub fn tls(self: *Fixture, name: []const u8, alpn: []const u8, ip: []const u8) !net.Stream {
        const fd = try net.tcp(self.a, ip, self.port, false);
        errdefer net.close(fd);
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TLSFailed;
        defer c.SSL_CTX_free(ctx);
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        const ca = try self.a.dupeSentinel(u8, try std.fs.path.join(self.a, &.{ self.state, "pki", "ca.pem" }), 0);
        if (c.SSL_CTX_load_verify_locations(ctx, ca, null) != 1) return error.TLSFailed;
        const ssl = c.SSL_new(ctx) orelse return error.TLSFailed;
        errdefer c.SSL_free(ssl);
        const zname = try self.a.dupeSentinel(u8, name, 0);
        if (c.SSL_set_fd(ssl, fd) != 1 or c.SSL_set1_host(ssl, zname) != 1 or c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(@constCast(zname.ptr))) != 1) return error.TLSFailed;
        var wire: [256]u8 = undefined;
        wire[0] = @intCast(alpn.len);
        @memcpy(wire[1 .. alpn.len + 1], alpn);
        if (c.SSL_set_alpn_protos(ssl, &wire, @intCast(alpn.len + 1)) != 0 or c.SSL_connect(ssl) != 1) return error.TLSFailed;
        var selected: [*c]const u8 = null;
        var n: c_uint = 0;
        c.SSL_get0_alpn_selected(ssl, &selected, &n);
        try equal(selected[0..n], alpn);
        return .{ .fd = fd, .ssl = ssl };
    }
    pub fn raw(self: *Fixture, host: []const u8, bytes: []const u8) ![]u8 {
        const stream = if (std.mem.eql(u8, self.scheme, "https")) try self.tls(self.primaryHost(host), "http/1.1", "127.0.0.1") else net.Stream{ .fd = try net.tcp(self.a, "127.0.0.1", self.port, false) };
        defer stream.deinit();
        try stream.writeAll(bytes);
        return net.readFrame(self.a, stream, 32 * 1024 * 1024);
    }
    fn primaryHost(_: *Fixture, host: []const u8) []const u8 {
        return if (std.mem.eql(u8, host, "unknown.local") or std.mem.endsWith(u8, host, ".evil")) "app.local" else host;
    }
    pub fn request(self: *Fixture, host: []const u8, path: []const u8) ![]u8 {
        return self.raw(host, try std.fmt.allocPrint(self.a, "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n", .{ path, host, self.port }));
    }
    pub fn waitApp(self: *Fixture, child_process: *Child, host: []const u8) !std.json.Value {
        for (0..300) |_| {
            _ = lib.process.inspect(child_process.identity.pid) catch {
                try self.diagnostics();
                return error.AppExited;
            };
            if (self.request(host, "/")) |response| {
                if (std.mem.startsWith(u8, response, "HTTP/1.1 200")) return json(self.a, body(response));
            } else |_| {}
            try std.Io.sleep(self.io, .fromMilliseconds(50), .awake);
        }
        try self.diagnostics();
        return error.AppNotReady;
    }
    pub fn curl(self: *Fixture, host: []const u8, path: []const u8, protocol: []const u8, extra: []const []const u8) !std.process.RunResult {
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(self.a, &.{ "curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "15", protocol, "--resolve", try std.fmt.allocPrint(self.a, "{s}:{d}:127.0.0.1", .{ host, self.port }) });
        if (std.mem.eql(u8, self.scheme, "https")) try args.appendSlice(self.a, &.{ "--cacert", try std.fs.path.join(self.a, &.{ self.state, "pki", "ca.pem" }) });
        try args.appendSlice(self.a, extra);
        try args.append(self.a, try std.fmt.allocPrint(self.a, "{s}://{s}:{d}{s}", .{ self.scheme, host, self.port, path }));
        const result = try std.process.run(self.a, self.io, .{ .argv = args.items, .stdout_limit = .limited(32 * 1024 * 1024), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } } });
        if (!result.term.success()) {
            std.debug.print("curl {s}: {s}\n", .{ path, result.stderr });
            try self.diagnostics();
            return error.CurlFailed;
        }
        return result;
    }
};
pub fn body(response: []const u8) []const u8 {
    return response[(std.mem.indexOf(u8, response, "\r\n\r\n") orelse unreachable) + 4 ..];
}
