//! Streaming HTTP/1 proxy and upgrade tunnel. No environment proxy or runtime dependency.
const file_stat = @import("file_stat.zig");
const std = @import("std");
const net = @import("net.zig");
const protocol = @import("protocol.zig");
const profile = @import("profile.zig");
const c = net.c;
const A = std.mem.Allocator;
pub const Header = struct { name: []const u8, value: []const u8 };
pub const Head = struct {
    first: []const u8,
    headers: []Header,
    raw: []const u8,
    pub fn get(self: Head, name: []const u8) ?[]const u8 {
        for (self.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }
};
const max_head = 64 << 10;
/// libcrypto; native.h does not include openssl/err.h.
/// Header fields per head; hop-by-hop filtering is quadratic in this count.
const max_fields = 256;
/// Reads exactly one head. Socket streams are peeked so body bytes stay queued.
pub fn readHead(a: A, stream: anytype) !Head {
    const socket: ?net.Stream = switch (@TypeOf(stream)) {
        net.Stream => stream,
        Upstream => if (stream.http2 == null) stream.stream else null,
        else => null,
    };
    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(a);
    var buf: [4096]u8 = undefined;
    while (data.items.len < max_head) {
        const want = if (socket != null) @min(buf.len, max_head - data.items.len) else 1;
        const count = if (socket) |s| try s.peek(buf[0..want]) else try stream.read(buf[0..want]);
        if (count == 0) return error.EndOfStream;
        const old = data.items.len;
        try data.appendSlice(a, buf[0..count]);
        const found = std.mem.indexOfPos(u8, data.items, old -| 3, "\r\n\r\n");
        if (found) |index| data.shrinkRetainingCapacity(index + 4);
        if (socket) |s| {
            var taken: usize = 0;
            const take = data.items.len - old;
            while (taken < take) {
                const n = try s.read(buf[taken..take]);
                if (n == 0) return error.EndOfStream;
                taken += n;
            }
        }
        if (found != null) {
            const raw = try data.toOwnedSlice(a);
            errdefer a.free(raw);
            return try parseHead(a, raw);
        }
    }
    return error.HeadersTooLarge;
}
pub fn parseHead(a: A, raw: []const u8) !Head {
    if (!std.mem.endsWith(u8, raw, "\r\n\r\n")) return error.InvalidHead;
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    const first = lines.next() orelse return error.InvalidHead;
    var headers: std.ArrayList(Header) = .empty;
    errdefer headers.deinit(a);
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (headers.items.len == max_fields) return error.HeadersTooLarge;
        try headers.append(a, try parseHeader(line));
    }
    return .{ .first = first, .headers = try headers.toOwnedSlice(a), .raw = raw };
}
pub fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |b| if (!std.ascii.isAlphanumeric(b) and std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", b) == null) return false;
    return true;
}
pub fn parseHeader(line: []const u8) !Header {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHead;
    const name = line[0..colon];
    if (!validToken(name)) return error.InvalidHead;
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    for (value) |b| if (b < 32 and b != '\t' or b == 127) return error.InvalidHead;
    return .{ .name = name, .value = value };
}
pub const Framing = struct { length: ?u64 = null, chunked: bool = false };
pub fn requestLine(head: Head) !struct { method: []const u8, target: []const u8 } {
    var parts = std.mem.splitScalar(u8, head.first, ' ');
    const method = parts.next() orelse return error.InvalidRequest;
    const target = parts.next() orelse return error.InvalidRequest;
    const version = parts.next() orelse return error.InvalidRequest;
    if (parts.next() != null or !validToken(method) or target.len == 0 or (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0"))) return error.InvalidRequest;
    for (target) |ch| if (ch <= 32 or ch == 127) return error.InvalidRequest;
    return .{ .method = method, .target = target };
}
/// Reject ambiguous wire framing before forwarding any headers or body.
pub fn framing(head: Head) !Framing {
    var result: Framing = .{};
    for (head.headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            if (result.length != null or header.value.len == 0) return error.InvalidContentLength;
            for (header.value) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidContentLength;
            result.length = try std.fmt.parseInt(u64, header.value, 10);
        } else if (std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) {
            if (result.chunked or !std.ascii.eqlIgnoreCase(header.value, "chunked")) return error.InvalidTransferEncoding;
            result.chunked = true;
        }
    }
    if (result.chunked and result.length != null) return error.AmbiguousFraming;
    return result;
}
pub fn responseStatus(head: Head) !u16 {
    const first = head.first;
    if (first.len < 12 or (!std.mem.startsWith(u8, first, "HTTP/1.1 ") and !std.mem.startsWith(u8, first, "HTTP/1.0 ")) or (first.len > 12 and first[12] != ' ')) return error.InvalidResponse;
    for (first[9..12]) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidResponse;
    for (first[12..]) |ch| if (ch < 32 and ch != '\t' or ch == 127) return error.InvalidResponse;
    const status = try std.fmt.parseInt(u16, first[9..12], 10);
    if (status < 100 or status > 599) return error.InvalidResponse;
    _ = try framing(head);
    return status;
}
pub fn forwardingHeader(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "x-forwarded-") or std.ascii.eqlIgnoreCase(name, "forwarded") or std.ascii.eqlIgnoreCase(name, "x-real-ip") or std.ascii.eqlIgnoreCase(name, "x-dotlocal-proxy-hop") or std.ascii.eqlIgnoreCase(name, "x-dotlocal-hops");
}
/// A bounded hop counter permits ordinary app-to-app forwarding while rejecting loops.
pub fn proxyHops(value: ?[]const u8) !u8 {
    const text = value orelse return 0;
    const count = std.fmt.parseInt(u32, text, 10) catch return error.InvalidProxyHops;
    if (count >= 5) return error.ProxyLoop;
    return @intCast(count);
}
pub fn forbiddenTrailer(name: []const u8) bool {
    for ([_][]const u8{ "content-length", "transfer-encoding", "trailer", "host", "connection", "proxy-connection", "keep-alive", "upgrade", "te" }) |field| if (std.ascii.eqlIgnoreCase(name, field)) return true;
    return !validToken(name);
}
pub fn trailerNames(a: A, head: Head) ![]Header {
    var names: std.ArrayList(Header) = .empty;
    errdefer names.deinit(a);
    for (head.headers) |header| if (std.ascii.eqlIgnoreCase(header.name, "trailer")) {
        var it = std.mem.splitScalar(u8, header.value, ',');
        while (it.next()) |part| {
            const name = std.mem.trim(u8, part, " \t");
            if (forbiddenTrailer(name)) return error.InvalidTrailer;
            if (!hop(head, name) and !forwardingHeader(name) and !std.ascii.eqlIgnoreCase(name, "alt-svc")) try names.append(a, .{ .name = name, .value = "" });
        }
    };
    return names.toOwnedSlice(a);
}
pub fn writeTrailerNames(writer: *std.Io.Writer, names: []const Header) !void {
    if (names.len == 0) return;
    try writer.writeAll("Trailer: ");
    for (names, 0..) |name, i| {
        if (i != 0) try writer.writeAll(", ");
        try writer.writeAll(name.name);
    }
    try writer.writeAll("\r\n");
}
pub fn hop(head: Head, name: []const u8) bool {
    for ([_][]const u8{ "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade" }) |h| if (std.ascii.eqlIgnoreCase(h, name)) return true;
    for (head.headers) |header| if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
        var it = std.mem.splitScalar(u8, header.value, ',');
        while (it.next()) |token| if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), name)) return true;
    };
    return false;
}
pub fn respond(stream: net.Stream, status: u16, body: []const u8) !void {
    var buf: [512]u8 = undefined;
    const head = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} Error\r\nContent-Length: {d}\r\nConnection: close\r\nContent-Type: text/plain\r\nX-dotlocal: 1\r\n\r\n", .{ status, body.len });
    try stream.writeAll(head);
    try stream.writeAll(body);
}
pub const Upstream = struct {
    stream: net.Stream,
    ctx: ?*c.SSL_CTX = null,
    http2: ?*@import("upstream_http2.zig").Client = null,
    cancel: ?*Cancel = null,
    pub fn read(self: Upstream, bytes: []u8) !usize {
        if (self.http2) |client| return client.read(bytes);
        return self.stream.read(bytes);
    }
    /// HTTP/1 upstreams only; HTTP/2 responses are synthesized in memory.
    pub fn peek(self: Upstream, bytes: []u8) !usize {
        std.debug.assert(self.http2 == null);
        return self.stream.peek(bytes);
    }
    pub fn writeAll(self: Upstream, bytes: []const u8) !void {
        if (self.http2) |client| return client.writeAll(bytes);
        return self.stream.writeAll(bytes);
    }
    pub fn deinit(self: Upstream) void {
        if (self.http2) |client| client.deinit();
        if (self.cancel) |cancel| cancel.clear();
        self.stream.deinit();
        if (self.ctx) |ctx| c.SSL_CTX_free(ctx);
    }
};
pub const Cancel = struct {
    guard: std.atomic.Mutex = .unlocked,
    stopped: std.atomic.Value(bool) = .init(false),
    fd: c_int = -1,
    fn lock(self: *Cancel) void {
        while (!self.guard.tryLock()) std.atomic.spinLoopHint();
    }
    fn publish(self: *Cancel, fd: c_int) !void {
        self.lock();
        defer self.guard.unlock();
        if (self.stopped.load(.acquire)) return error.Canceled;
        self.fd = fd;
    }
    fn clear(self: *Cancel) void {
        self.lock();
        defer self.guard.unlock();
        self.fd = -1;
    }
    pub fn stop(self: *Cancel) void {
        self.stopped.store(true, .release);
        self.lock();
        defer self.guard.unlock();
        if (self.fd >= 0) _ = c.shutdown(self.fd, c.SHUT_RDWR);
    }
};
pub fn connect(a: A, route: protocol.Route, ca_path: ?[]const u8) !Upstream {
    return connectHttp(a, route, ca_path, false);
}
pub fn connectHttp(a: A, route: protocol.Route, ca_path: ?[]const u8, allow_http2: bool) !Upstream {
    return connectHttpWatched(a, route, ca_path, allow_http2, null);
}
fn connectSocket(a: A, route: protocol.Route, cancel: *Cancel) !c_int {
    const ipv6 = std.mem.indexOfScalar(u8, route.host, ':') != null;
    const family: c_int = if (ipv6) c.AF_INET6 else c.AF_INET;
    const fd = c.socket(family, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer net.close(fd);
    net.configure(fd, 30);
    try cancel.publish(fd);
    errdefer cancel.clear();
    const host = try a.dupeSentinel(u8, route.host, 0);
    var v4: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var v6: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
    const address: *const c.struct_sockaddr = if (ipv6) blk: {
        v6.sin6_family = c.AF_INET6;
        v6.sin6_port = std.mem.nativeToBig(u16, route.port);
        if (c.inet_pton(family, host, &v6.sin6_addr) != 1) return error.InvalidIP;
        break :blk @ptrCast(&v6);
    } else blk: {
        v4.sin_family = c.AF_INET;
        v4.sin_port = std.mem.nativeToBig(u16, route.port);
        if (c.inet_pton(family, host, &v4.sin_addr) != 1) return error.InvalidIP;
        break :blk @ptrCast(&v4);
    };
    const flags = c.fcntl(fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    const connected = c.connect(fd, address, if (ipv6) @sizeOf(@TypeOf(v6)) else @sizeOf(@TypeOf(v4)));
    if (connected < 0 and std.posix.errno(connected) != .INPROGRESS) return error.ConnectFailed;
    if (connected < 0) {
        var attempts: usize = 0;
        while (true) : (attempts += 1) {
            if (cancel.stopped.load(.acquire)) return error.Canceled;
            if (attempts >= 150) return error.ConnectTimeout;
            var poll: c.struct_pollfd = .{ .fd = fd, .events = c.POLLOUT, .revents = 0 };
            const ready = c.poll(&poll, 1, 200);
            if (ready < 0 and std.posix.errno(ready) == .INTR) continue;
            if (ready < 0) return error.ConnectFailed;
            if (ready == 0) continue;
            var err: c_int = 0;
            var len: c.socklen_t = @sizeOf(c_int);
            if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_ERROR, &err, &len) != 0 or err != 0) return error.ConnectFailed;
            break;
        }
    }
    if (c.fcntl(fd, c.F_SETFL, flags) < 0 or cancel.stopped.load(.acquire)) return error.Canceled;
    return fd;
}
pub fn connectHttpWatched(a: A, route: protocol.Route, ca_path: ?[]const u8, allow_http2: bool, cancel: ?*Cancel) !Upstream {
    const fd = if (cancel) |value| try connectSocket(a, route, value) else try net.tcp(a, route.host, route.port, false);
    errdefer net.close(fd);
    errdefer if (cancel) |value| value.clear();
    if (std.mem.eql(u8, route.scheme, "http")) return .{ .stream = .{ .fd = fd }, .cancel = cancel };
    const ctx = try clientContext(a, ca_path);
    errdefer c.SSL_CTX_free(ctx);
    const ssl = c.SSL_new(ctx) orelse return error.TLSFailed;
    errdefer c.SSL_free(ssl);
    const host = try a.dupeSentinel(u8, route.host, 0);
    if (allow_http2) {
        const protocols = "\x02h2\x08http/1.1";
        if (c.SSL_set_alpn_protos(ssl, protocols, protocols.len) != 0) return error.TLSFailed;
    }
    if (c.X509_VERIFY_PARAM_set1_ip_asc(c.SSL_get0_param(ssl), host) != 1 or c.SSL_set_fd(ssl, fd) != 1 or c.SSL_connect(ssl) != 1) return error.TLSFailed;
    const stream: net.Stream = .{ .fd = fd, .ssl = ssl };
    var selected: [*c]const u8 = null;
    var selected_len: c_uint = 0;
    c.SSL_get0_alpn_selected(ssl, &selected, &selected_len);
    const client = if (selected_len == 2 and std.mem.eql(u8, selected[0..selected_len], "h2")) try @import("upstream_http2.zig").Client.init(a, stream, try endpoint(a, route)) else null;
    return .{ .stream = stream, .ctx = ctx, .http2 = client, .cancel = cancel };
}
/// The verified upstream client context, shared while the CA file is unchanged.
/// Loading the system trust store per connection dominates HTTPS upstream setup.
/// Each caller owns one reference; replacing the cache never frees a live context.
const ClientContextCache = struct {
    guard: std.atomic.Mutex = .unlocked,
    ctx: ?*c.SSL_CTX = null,
    key: Key = .{},
    /// A CA path plus file identity, so a rewritten CA file is reloaded.
    const Key = struct {
        path: [1024]u8 = undefined,
        len: usize = 0,
        dev: @FieldType(c.struct_stat, "st_dev") = 0,
        ino: @FieldType(c.struct_stat, "st_ino") = 0,
        size: @FieldType(c.struct_stat, "st_size") = 0,
        mtime: c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = 0 },
        fn eql(x: *const Key, y: *const Key) bool {
            return std.mem.eql(u8, x.path[0..x.len], y.path[0..y.len]) and x.dev == y.dev and x.ino == y.ino and x.size == y.size and x.mtime.tv_sec == y.mtime.tv_sec and x.mtime.tv_nsec == y.mtime.tv_nsec;
        }
    };
    fn lock(self: *ClientContextCache) void {
        while (!self.guard.tryLock()) std.atomic.spinLoopHint();
    }
};
var client_contexts: ClientContextCache = .{};
fn clientContextKey(path_z: ?[:0]const u8) ?ClientContextCache.Key {
    var key: ClientContextCache.Key = .{};
    const path = path_z orelse return key;
    if (path.len > key.path.len) return null;
    var st: c.struct_stat = undefined;
    if (file_stat.stat(path, &st) != 0) return null;
    @memcpy(key.path[0..path.len], path);
    key.len = path.len;
    key.dev = st.st_dev;
    key.ino = st.st_ino;
    key.size = st.st_size;
    key.mtime = if (@import("builtin").os.tag == .macos) st.st_mtimespec else st.st_mtim;
    return key;
}
/// Returns a client context reference owned by the caller (release with SSL_CTX_free).
fn clientContext(a: A, ca_path: ?[]const u8) !*c.SSL_CTX {
    const path_z: ?[:0]const u8 = if (ca_path) |path| try a.dupeSentinel(u8, path, 0) else null;
    defer if (path_z) |z| a.free(z);
    const key = clientContextKey(path_z);
    if (key) |*wanted| {
        client_contexts.lock();
        defer client_contexts.guard.unlock();
        if (client_contexts.ctx) |cached| if (client_contexts.key.eql(wanted)) {
            if (c.SSL_CTX_up_ref(cached) != 1) return error.TLSFailed;
            return cached;
        };
    }
    // Build outside the lock: loading the trust store reads and parses files.
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TLSFailed;
    errdefer c.SSL_CTX_free(ctx);
    c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
    _ = c.SSL_CTX_set_default_verify_paths(ctx);
    if (path_z) |z| _ = c.SSL_CTX_load_verify_locations(ctx, z, null);
    // Ignored load failures must not leave errors for later SSL_get_error calls.
    c.ERR_clear_error();
    const wanted = key orelse return ctx;
    if (c.SSL_CTX_up_ref(ctx) != 1) return error.TLSFailed;
    client_contexts.lock();
    const old = client_contexts.ctx;
    client_contexts.ctx = ctx;
    client_contexts.key = wanted;
    client_contexts.guard.unlock();
    if (old) |previous| c.SSL_CTX_free(previous);
    return ctx;
}
pub fn endpoint(a: A, route: protocol.Route) ![]const u8 {
    return if (std.mem.indexOfScalar(u8, route.host, ':') != null) std.fmt.allocPrint(a, "[{s}]:{d}", .{ route.host, route.port }) else std.fmt.allocPrint(a, "{s}:{d}", .{ route.host, route.port });
}
pub fn rewriteLocation(a: A, value: []const u8, route: protocol.Route, public_url: []const u8) ![]const u8 {
    const ep = try endpoint(a, route);
    defer a.free(ep);
    const prefix = try std.fmt.allocPrint(a, "{s}://{s}", .{ route.scheme, ep });
    defer a.free(prefix);
    const relative = try std.fmt.allocPrint(a, "//{s}", .{ep});
    defer a.free(relative);
    const public_authority = public_url[std.mem.indexOf(u8, public_url, "://").? + 3 ..];
    const public_http = try std.fmt.allocPrint(a, "http://{s}", .{public_authority});
    defer a.free(public_http);
    for ([_][]const u8{ prefix, relative, public_http }) |p| if (std.mem.startsWith(u8, value, p) and (value.len == p.len or std.mem.indexOfScalar(u8, "/?#", value[p.len]) != null)) return std.fmt.allocPrint(a, "{s}{s}", .{ public_url, value[p.len..] });
    return value;
}
fn sendRequest(a: A, up: Upstream, head: Head, config: profile.Config, authority: []const u8, remote: []const u8) !void {
    const parsed = try requestLine(head);
    const url = try config.publicUrl(a, authority);
    const public_authority = url[(std.mem.indexOf(u8, url, "://").? + 3)..];
    const body_framing = try framing(head);
    const upgrade = head.get("upgrade");
    var out: std.Io.Writer.Allocating = .init(a);
    try out.writer.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\n", .{ parsed.method, parsed.target, public_authority });
    for (head.headers) |h| {
        if (hop(head, h.name) or std.ascii.eqlIgnoreCase(h.name, "host") or forwardingHeader(h.name) or std.ascii.eqlIgnoreCase(h.name, "expect")) continue;
        try out.writer.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try out.writer.print("X-Forwarded-For: {s}\r\nX-Forwarded-Host: {s}\r\nX-Forwarded-Proto: {s}\r\nX-dotlocal-Proxy-Hop: 1\r\nX-dotlocal-Hops: {d}\r\n", .{ remote, public_authority, config.scheme, (try proxyHops(head.get("x-dotlocal-hops"))) + 1 });
    if (body_framing.chunked) {
        try out.writer.writeAll("Transfer-Encoding: chunked\r\n");
        try writeTrailerNames(&out.writer, try trailerNames(a, head));
    }
    if (upgrade) |value| {
        if (!std.ascii.eqlIgnoreCase(value, "websocket")) return error.UnsupportedUpgrade;
        try out.writer.print("Connection: Upgrade\r\nUpgrade: {s}\r\n", .{value});
    } else try out.writer.writeAll("Connection: close\r\n");
    try out.writer.writeAll("\r\n");
    try up.writeAll(out.written());
}
pub fn serve(a: A, down: net.Stream, reg: anytype, config: profile.Config, ca_path: ?[]const u8, remote: []const u8, redirect: bool) !void {
    return serveWatched(a, down, reg, config, ca_path, remote, redirect, null);
}
pub fn serveWatched(a: A, down: net.Stream, reg: anytype, config: profile.Config, ca_path: ?[]const u8, remote: []const u8, redirect: bool, cancel: ?*Cancel) !void {
    const head = readHead(a, down) catch {
        try respond(down, 400, "invalid request\n");
        return;
    };
    const parsed = requestLine(head) catch {
        try respond(down, 400, "invalid request\n");
        return;
    };
    const body_framing = framing(head) catch {
        try respond(down, 400, "invalid request framing\n");
        return;
    };
    _ = trailerNames(a, head) catch {
        try respond(down, 400, "invalid trailers\n");
        return;
    };
    const expect = head.get("expect");
    if (expect) |value| if (!std.ascii.eqlIgnoreCase(value, "100-continue")) {
        try respond(down, 417, "expectation failed\n");
        return;
    };
    if (std.mem.eql(u8, parsed.method, "CONNECT")) {
        try respond(down, 405, "CONNECT is not supported\n");
        return;
    }
    if (!std.mem.startsWith(u8, parsed.target, "/") or std.mem.startsWith(u8, parsed.target, "//")) {
        try respond(down, 400, "invalid request target\n");
        return;
    }
    _ = proxyHops(head.get("x-dotlocal-hops")) catch |err| {
        try respond(down, if (err == error.ProxyLoop) 508 else 400, "invalid proxy hops\n");
        return;
    };
    if (head.get("x-dotlocal-hops") == null and head.get("x-dotlocal-proxy-hop") != null) {
        try respond(down, 508, "proxy loop\n");
        return;
    }
    var hosts: usize = 0;
    for (head.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "host")) {
        hosts += 1;
    };
    if (hosts != 1) {
        try respond(down, 400, "invalid host\n");
        return;
    }
    const host = head.get("host").?;
    const route = (reg.resolve(a, host) catch {
        try respond(down, 400, "invalid host\n");
        return;
    }) orelse {
        try respond(down, 404, "unknown host\n");
        return;
    };
    if (redirect) {
        var out: std.Io.Writer.Allocating = .init(a);
        try out.writer.print("HTTP/1.1 308 Permanent Redirect\r\nLocation: {s}{s}\r\nContent-Length: 0\r\nConnection: close\r\nX-dotlocal: 1\r\n\r\n", .{ try config.publicUrl(a, host), parsed.target });
        try down.writeAll(out.written());
        return;
    }
    const up = connectHttpWatched(a, route, ca_path, head.get("upgrade") == null, cancel) catch {
        try respond(down, 502, "bad gateway\n");
        return;
    };
    defer up.deinit();
    try sendRequest(a, up, head, config, host, remote);
    if (expect != null) {
        try down.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
    }
    var upload: UploadReader = .{ .allocator = a, .down = down, .up = up, .continued = expect != null };
    const copied = if (body_framing.chunked) copyChunkedHeaders(a, &upload, up, false, head) else if (body_framing.length) |len| copyExact(&upload, up, len) else {};
    copied catch |err| {
        if (err != error.EarlyResponse) {
            try respond(down, if (err == error.InvalidChunk or err == error.InvalidTrailer or err == error.InvalidHead) 400 else 502, "invalid request body or upstream\n");
            return;
        }
    };
    if (upload.response != null) if (up.http2) |client| try client.stopUpload();
    var response: Head = undefined;
    var status: u16 = 0;
    var informational: usize = 0;
    while (true) {
        response = upload.response orelse (readHead(a, up) catch {
            try respond(down, 502, "invalid upstream response\n");
            return;
        });
        upload.response = null;
        status = responseStatus(response) catch {
            try respond(down, 502, "invalid upstream response\n");
            return;
        };
        if (status >= 200 or status == 101) break;
        informational += 1;
        if (informational > 10) return error.TooManyInformationalResponses;
        if (status != 100 or expect == null) try writeInformational(a, down, response);
    }
    const response_framing = try framing(response);
    const names = trailerNames(a, response) catch {
        try respond(down, 502, "invalid upstream trailers\n");
        return;
    };
    var out: std.Io.Writer.Allocating = .init(a);
    try out.writer.print("{s}\r\n", .{response.first});
    const switching = status == 101;
    if (switching and (head.get("upgrade") == null or response.get("upgrade") == null or !std.ascii.eqlIgnoreCase(response.get("upgrade").?, "websocket"))) {
        try respond(down, 502, "invalid upstream upgrade\n");
        return;
    }
    for (response.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-dotlocal") or std.ascii.eqlIgnoreCase(h.name, "alt-svc") or (hop(response, h.name) and !std.ascii.eqlIgnoreCase(h.name, "transfer-encoding") and !(switching and std.ascii.eqlIgnoreCase(h.name, "upgrade")))) continue;
        const value = if (std.ascii.eqlIgnoreCase(h.name, "location")) try rewriteLocation(a, h.value, route, try config.publicUrl(a, host)) else h.value;
        try out.writer.print("{s}: {s}\r\n", .{ h.name, value });
    }
    try out.writer.writeAll("X-dotlocal: 1\r\n");
    if (response_framing.chunked) try writeTrailerNames(&out.writer, names);
    try out.writer.writeAll(if (switching) "Connection: Upgrade\r\n\r\n" else "Connection: close\r\n\r\n");
    try down.writeAll(out.written());
    if (switching) {
        relay(.{ down, up.stream }, up.cancel, 30_000);
        _ = c.shutdown(down.fd, c.SHUT_RDWR);
        _ = c.shutdown(up.stream.fd, c.SHUT_RDWR);
        return;
    }
    if (std.mem.eql(u8, parsed.method, "HEAD") or status == 204 or status == 304) return;
    if (response_framing.chunked) try copyChunkedHeaders(a, up, down, false, response) else if (response_framing.length) |len| try copyExact(up, down, len) else try copyUntilEOF(up, down);
}
/// Watch the upstream while reading an upload, including clients waiting on a final response.
const UploadReader = struct {
    allocator: A,
    down: net.Stream,
    up: Upstream,
    response: ?Head = null,
    continued: bool,
    informational: usize = 0,
    partial_head: std.ArrayList(u8) = .empty,
    up_events: c_short = c.POLLIN,
    fn receiveHead(self: *UploadReader) !?Head {
        const fd = self.up.stream.fd;
        const old_flags = c.fcntl(fd, c.F_GETFL);
        if (old_flags < 0 or c.fcntl(fd, c.F_SETFL, old_flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
        defer _ = c.fcntl(fd, c.F_SETFL, old_flags);
        if (self.up.http2) |client| {
            if (client.head_offset >= client.head_out.items.len) client.receiveReady() catch |err| {
                if (err == error.WouldBlock) {
                    self.up_events = client.poll_events;
                    return null;
                }
                return err;
            };
            if (client.head_offset < client.head_out.items.len) return try readHead(self.allocator, self.up);
            return null;
        }
        while (self.partial_head.items.len < max_head) {
            // Peek, then consume only through the head so response body bytes stay queued.
            var buf: [4096]u8 = undefined;
            const old = self.partial_head.items.len;
            const want: c_int = @intCast(@min(buf.len, max_head - old));
            const count = if (self.up.stream.ssl) |ssl| c.SSL_peek(ssl, &buf, want) else c.recv(fd, &buf, @intCast(want), c.MSG_PEEK);
            if (count <= 0) {
                if (self.up.stream.ssl) |ssl| switch (c.SSL_get_error(ssl, @intCast(count))) {
                    c.SSL_ERROR_WANT_READ => {
                        self.up_events = c.POLLIN;
                        return null;
                    },
                    c.SSL_ERROR_WANT_WRITE => {
                        self.up_events = c.POLLOUT;
                        return null;
                    },
                    else => return error.UpstreamClosed,
                };
                if (count < 0 and std.posix.errno(count) == .AGAIN) return null;
                return error.UpstreamClosed;
            }
            try self.partial_head.appendSlice(self.allocator, buf[0..@intCast(count)]);
            const found = std.mem.indexOfPos(u8, self.partial_head.items, old -| 3, "\r\n\r\n");
            if (found) |index| self.partial_head.shrinkRetainingCapacity(index + 4);
            // Peeked bytes are already buffered, so consuming them does not block.
            var taken: usize = 0;
            const take = self.partial_head.items.len - old;
            while (taken < take) {
                const n = self.up.stream.read(buf[taken..take]) catch return error.UpstreamClosed;
                if (n == 0) return error.UpstreamClosed;
                taken += n;
            }
            if (found != null) return try parseHead(self.allocator, try self.partial_head.toOwnedSlice(self.allocator));
        }
        return error.HeadersTooLarge;
    }
    pub fn read(self: *UploadReader, bytes: []u8) !usize {
        return self.next(bytes, false);
    }
    /// Like `read`, but leaves the downstream bytes queued.
    pub fn peek(self: *UploadReader, bytes: []u8) !usize {
        return self.next(bytes, true);
    }
    fn next(self: *UploadReader, bytes: []u8, comptime peeking: bool) !usize {
        while (true) {
            const client_head = if (self.up.http2) |client| client.head_offset < client.head_out.items.len else false;
            const up_pending = if (self.up.stream.ssl) |ssl| c.SSL_pending(ssl) > 0 else false;
            const down_pending = if (self.down.ssl) |ssl| c.SSL_pending(ssl) > 0 else false;
            var polls = [_]c.struct_pollfd{ .{ .fd = self.up.stream.fd, .events = self.up_events, .revents = 0 }, .{ .fd = self.down.fd, .events = c.POLLIN, .revents = 0 } };
            const ready = c.poll(&polls, polls.len, if (client_head or up_pending or down_pending) 0 else 30000);
            if (ready < 0) {
                if (std.posix.errno(ready) == .INTR) continue;
                return error.PollFailed;
            }
            if (client_head or up_pending or polls[0].revents != 0) {
                if (try self.receiveHead()) |head| {
                    const status = try responseStatus(head);
                    if (status >= 200 or status == 101) {
                        self.response = head;
                        return error.EarlyResponse;
                    }
                    self.informational += 1;
                    if (self.informational > 10) return error.TooManyInformationalResponses;
                    if (status != 100 or !self.continued) try writeInformational(self.allocator, self.down, head);
                    continue;
                }
            }
            if (down_pending or polls[1].revents != 0) return if (peeking) self.down.peek(bytes) else self.down.read(bytes);
            if (ready == 0) return error.UploadTimeout;
        }
    }
};
pub fn writeInformational(a: A, down: net.Stream, head: Head) !void {
    var out: std.Io.Writer.Allocating = .init(a);
    try out.writer.print("{s}\r\n", .{head.first});
    for (head.headers) |header| if (!hop(head, header.name) and !std.ascii.eqlIgnoreCase(header.name, "content-length") and !std.ascii.eqlIgnoreCase(header.name, "alt-svc")) {
        try out.writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    };
    try out.writer.writeAll("\r\n");
    try down.writeAll(out.written());
}
/// Copies both directions of an upgraded connection on one thread: an OpenSSL
/// object must never be read and written concurrently. Sockets are made
/// non-blocking and each direction keeps one pending buffer, so a peer that
/// stops reading only stalls its own direction. Each EOF half-closes the peer;
/// the tunnel ends when both directions finish, on cancel, or after `idle_ms`
/// without progress.
fn relay(ends: [2]net.Stream, cancel: ?*Cancel, idle_ms: c_int) void {
    for (ends) |end| _ = c.fcntl(end.fd, c.F_SETFL, c.fcntl(end.fd, c.F_GETFL) | c.O_NONBLOCK);
    var flows: [2]Flow = .{ .{}, .{} };
    while (flows[0].active() or flows[1].active()) {
        if (cancel) |value| if (value.stopped.load(.acquire)) return;
        var polls: [2]c.struct_pollfd = undefined;
        var buffered = false;
        for (ends, &polls, 0..) |end, *poll, i| {
            const out = &flows[i];
            const in = &flows[1 - i];
            var events: c_short = 0;
            if (out.open and out.empty()) {
                events |= out.read_wants;
                buffered = buffered or (if (end.ssl) |ssl| c.SSL_has_pending(ssl) == 1 else false);
            }
            if (!in.empty()) events |= in.write_wants;
            // A negative fd is ignored, so a finished end cannot spin poll at EOF.
            poll.* = .{ .fd = if (events == 0) -1 else end.fd, .events = events, .revents = 0 };
        }
        const ready = c.poll(&polls, polls.len, if (buffered) 0 else idle_ms);
        if (ready < 0 and std.posix.errno(ready) == .INTR) continue;
        if (ready < 0 or (ready == 0 and !buffered)) return;
        for (&flows, 0..) |*flow, i| flow.step(ends[i], ends[1 - i]);
    }
}
/// One direction of `relay`. Retries reuse the same buffer slice, as OpenSSL
/// requires after SSL_ERROR_WANT_WRITE.
const Flow = struct {
    buf: [16384]u8 = undefined,
    lo: usize = 0,
    hi: usize = 0,
    open: bool = true,
    read_wants: c_short = c.POLLIN,
    write_wants: c_short = c.POLLOUT,

    fn empty(f: *const Flow) bool {
        return f.lo == f.hi;
    }
    fn active(f: *const Flow) bool {
        return f.open or !f.empty();
    }
    fn step(f: *Flow, from: net.Stream, to: net.Stream) void {
        if (!f.empty()) switch (io(to, f.buf[f.lo..f.hi], .write)) {
            .done => |n| f.lo += n,
            .wants => |events| f.write_wants = events,
            .closed => return f.finish(to, false),
        };
        if (f.open and f.empty()) switch (io(from, &f.buf, .read)) {
            .done => |n| {
                f.lo = 0;
                f.hi = n;
            },
            .wants => |events| f.read_wants = events,
            .closed => f.finish(to, true),
        };
    }
    /// A clean source EOF ends a TLS destination with close_notify before the
    /// TCP half-close; a failed destination only gets the TCP half-close.
    fn finish(f: *Flow, to: net.Stream, clean: bool) void {
        f.open = false;
        f.lo = 0;
        f.hi = 0;
        if (clean) if (to.ssl) |ssl| if (c.SSL_is_init_finished(ssl) == 1 and c.SSL_get_shutdown(ssl) & c.SSL_SENT_SHUTDOWN == 0) {
            // Non-blocking: a full socket buffer drops the alert instead of stalling.
            _ = c.SSL_shutdown(ssl);
            // Keep this thread's error queue clean for later SSL_get_error calls.
            c.ERR_clear_error();
        };
        _ = c.shutdown(to.fd, c.SHUT_WR);
    }
    const Result = union(enum) { done: usize, wants: c_short, closed };
    /// One non-blocking read or write; EOF and hard errors both close the direction.
    fn io(stream: net.Stream, bytes: []u8, comptime op: enum { read, write }) Result {
        const len: c_int = @intCast(@min(bytes.len, std.math.maxInt(c_int)));
        if (stream.ssl) |ssl| {
            const n = switch (op) {
                .read => c.SSL_read(ssl, bytes.ptr, len),
                .write => c.SSL_write(ssl, bytes.ptr, len),
            };
            if (n > 0) return .{ .done = @intCast(n) };
            return switch (c.SSL_get_error(ssl, n)) {
                c.SSL_ERROR_WANT_READ => .{ .wants = c.POLLIN },
                c.SSL_ERROR_WANT_WRITE => .{ .wants = c.POLLOUT },
                else => .closed,
            };
        }
        const n = switch (op) {
            .read => c.recv(stream.fd, bytes.ptr, bytes.len, 0),
            .write => c.send(stream.fd, bytes.ptr, bytes.len, 0),
        };
        if (n > 0) return .{ .done = @intCast(n) };
        if (n < 0) switch (std.posix.errno(n)) {
            .AGAIN, .INTR => return .{ .wants = if (op == .read) c.POLLIN else c.POLLOUT },
            else => {},
        };
        return .closed;
    }
};
fn pump(from: anytype, to: net.Stream) void {
    copyUntilEOF(from, to) catch {};
    _ = c.shutdown(to.fd, c.SHUT_WR);
}
fn copyUntilEOF(from: anytype, to: net.Stream) !void {
    var buf: [32768]u8 = undefined;
    while (true) {
        const n = try from.read(&buf);
        if (n == 0) break;
        try to.writeAll(buf[0..n]);
    }
}
pub fn copyExact(from: anytype, to: anytype, count: u64) !void {
    var remaining = count;
    var buf: [32768]u8 = undefined;
    while (remaining > 0) {
        const n = try from.read(buf[0..@intCast(@min(buf.len, remaining))]);
        if (n == 0) return error.UnexpectedEOF;
        try to.writeAll(buf[0..n]);
        remaining -= n;
    }
}
/// Reads one CRLF-terminated line. Socket sources are peeked and only the line
/// is consumed, so following body bytes stay queued without per-byte reads.
fn readLine(stream: anytype, buf: []u8) ![]const u8 {
    const peekable = switch (@TypeOf(stream)) {
        net.Stream, *UploadReader => true,
        Upstream => stream.http2 == null,
        else => false,
    };
    var len: usize = 0;
    while (len < buf.len) {
        const rest = buf[len..];
        if (!peekable) {
            if (try stream.read(rest[0..1]) == 0) return error.UnexpectedEOF;
            len += 1;
        } else {
            const count = try stream.peek(rest);
            if (count == 0) return error.UnexpectedEOF;
            const take = if (std.mem.indexOfScalar(u8, rest[0..count], '\n')) |index| index + 1 else count;
            var taken: usize = 0;
            while (taken < take) {
                const n = try stream.read(rest[taken..take]);
                if (n == 0) return error.UnexpectedEOF;
                taken += n;
            }
            len += take;
        }
        if (std.mem.endsWith(u8, buf[0..len], "\r\n")) return buf[0..len];
    }
    return error.LineTooLong;
}
pub fn copyChunked(a: A, from: net.Stream, to: net.Stream, decode: bool) !void {
    return copyChunkedHeaders(a, from, to, decode, .{ .first = "", .raw = "", .headers = &.{} });
}
pub fn chunkSize(line: []const u8) !u64 {
    const end = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    if (end == 0) return error.InvalidChunk;
    for (line[0..end]) |ch| if (!std.ascii.isHex(ch)) return error.InvalidChunk;
    for (line[end..]) |ch| if (ch < 32 or ch == 127) return error.InvalidChunk;
    return std.fmt.parseInt(u64, line[0..end], 16);
}
fn copyChunkedHeaders(a: A, from: anytype, to: anytype, decode: bool, head: Head) !void {
    var line_buf: [8192]u8 = undefined;
    while (true) {
        const chunk = try readLine(from, &line_buf);
        const count = try chunkSize(chunk[0 .. chunk.len - 2]);
        if (count == 0) {
            var trailers: std.Io.Writer.Allocating = .init(a);
            defer trailers.deinit();
            var trailer_bytes: usize = 0;
            while (true) {
                const trailer = try readLine(from, &line_buf);
                trailer_bytes += trailer.len;
                if (trailer_bytes > 65536) return error.HeadersTooLarge;
                if (trailer.len == 2) break;
                const header = try parseHeader(trailer[0 .. trailer.len - 2]);
                if (forbiddenTrailer(header.name)) return error.InvalidTrailer;
                if (hop(head, header.name) or forwardingHeader(header.name) or std.ascii.eqlIgnoreCase(header.name, "alt-svc")) continue;
                try trailers.writer.print("{s}: {s}\r\n", .{ header.name, header.value });
            }
            if (!decode) {
                try to.writeAll("0\r\n");
                try to.writeAll(trailers.written());
                try to.writeAll("\r\n");
            }
            return;
        }
        if (!decode) try to.writeAll(chunk);
        try copyExact(from, to, count);
        var end: [2]u8 = undefined;
        var off: usize = 0;
        while (off < 2) {
            const n = try from.read(end[off..]);
            if (n == 0) return error.UnexpectedEOF;
            off += n;
        }
        if (!std.mem.eql(u8, &end, "\r\n")) return error.InvalidChunk;
        if (!decode) try to.writeAll(&end);
    }
}

test "header and trailer errors release allocator storage, including socket EOF" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidHead, parseHead(a, "GET / HTTP/1.1\r\nGood: value\r\nBad : value\r\n\r\n"));
    const fields = [_]Header{.{ .name = "Trailer", .value = "X-Checksum, Content-Length" }};
    try std.testing.expectError(error.InvalidTrailer, trailerNames(a, .{ .first = "", .raw = "", .headers = @constCast(&fields) }));
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    defer for (sockets) |fd| net.close(fd);
    const from: net.Stream = .{ .fd = sockets[0] };
    const to: net.Stream = .{ .fd = sockets[1] };
    try to.writeAll("GET / HTTP/1.1\r\nPartial: value");
    _ = c.shutdown(sockets[1], c.SHUT_WR);
    try std.testing.expectError(error.EndOfStream, readHead(a, from));
}

test "socket heads are peeked so following body bytes stay queued" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    defer for (sockets) |fd| net.close(fd);
    const from: net.Stream = .{ .fd = sockets[0] };
    const to: net.Stream = .{ .fd = sockets[1] };
    try to.writeAll("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
    _ = c.shutdown(sockets[1], c.SHUT_WR);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue", (try readHead(a, from)).first);
    const final = try readHead(a, from);
    try std.testing.expectEqualStrings("4", final.get("content-length").?);
    var body: [8]u8 = undefined;
    try std.testing.expectEqualStrings("body", body[0..try from.read(&body)]);
    var fields: std.Io.Writer.Allocating = .init(a);
    try fields.writer.writeAll("GET / HTTP/1.1\r\n");
    for (0..max_fields + 1) |_| try fields.writer.writeAll("a:\r\n");
    try fields.writer.writeAll("\r\n");
    try std.testing.expectError(error.HeadersTooLarge, parseHead(a, fields.written()));
}

test "upgrade relay copies both directions and propagates each half-close" {
    var client: [2]c_int = undefined;
    var server: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &client) != 0) return error.SocketFailed;
    defer for (client) |fd| net.close(fd);
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &server) != 0) return error.SocketFailed;
    defer for (server) |fd| net.close(fd);
    for (client ++ server) |fd| net.configure(fd, 5);
    var cancel: Cancel = .{};
    const thread = try std.Thread.spawn(.{}, relay, .{ [2]net.Stream{ .{ .fd = client[1] }, .{ .fd = server[0] } }, &cancel, 5000 });
    defer thread.join();
    const down: net.Stream = .{ .fd = client[0] };
    const up: net.Stream = .{ .fd = server[1] };
    var buf: [16]u8 = undefined;
    try down.writeAll("ping");
    try std.testing.expectEqualStrings("ping", buf[0..try up.read(&buf)]);
    _ = c.shutdown(client[0], c.SHUT_WR);
    try std.testing.expectEqual(@as(usize, 0), try up.read(&buf));
    // The other direction stays open after the client half-closes.
    try up.writeAll("pong");
    try std.testing.expectEqualStrings("pong", buf[0..try down.read(&buf)]);
    _ = c.shutdown(server[1], c.SHUT_WR);
    try std.testing.expectEqual(@as(usize, 0), try down.read(&buf));
}

test "upgrade relay keeps flowing to a client while the upstream writes before it reads" {
    var client: [2]c_int = undefined;
    var server: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &client) != 0) return error.SocketFailed;
    defer for (client) |fd| net.close(fd);
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &server) != 0) return error.SocketFailed;
    defer for (server) |fd| net.close(fd);
    for (client ++ server) |fd| net.configure(fd, 5);
    var cancel: Cancel = .{};
    const thread = try std.Thread.spawn(.{}, relay, .{ [2]net.Stream{ .{ .fd = client[1] }, .{ .fd = server[0] } }, &cancel, 5000 });
    defer thread.join();
    // Both sides send far more than the socket buffers hold. The client reads
    // and writes concurrently; the upstream only reads after it finished
    // writing, so a relay blocked on writing upstream would deadlock.
    const size = 4 << 20;
    const Peer = struct {
        fn send(fd: c_int) void {
            const chunk: [65536]u8 = @splat('x');
            for (0..size / chunk.len) |_| (net.Stream{ .fd = fd }).writeAll(&chunk) catch return;
            _ = c.shutdown(fd, c.SHUT_WR);
        }
        fn drain(fd: c_int, received: *usize) void {
            var buf: [65536]u8 = undefined;
            while (true) {
                const n = (net.Stream{ .fd = fd }).read(&buf) catch return;
                if (n == 0) return;
                received.* += n;
            }
        }
        fn upstream(fd: c_int, received: *usize) void {
            send(fd);
            drain(fd, received);
        }
    };
    var got: [2]usize = .{ 0, 0 };
    const up = try std.Thread.spawn(.{}, Peer.upstream, .{ server[1], &got[1] });
    const down = try std.Thread.spawn(.{}, Peer.send, .{client[0]});
    Peer.drain(client[0], &got[0]);
    down.join();
    up.join();
    try std.testing.expectEqual(@as(usize, size), got[0]);
    try std.testing.expectEqual(@as(usize, size), got[1]);
}

test "upstream TLS client contexts are shared until the CA file changes" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = "first" });
    const base = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    const path = try std.fs.path.join(a, &.{ base, "ca.pem" });
    defer a.free(path);
    const first = try clientContext(a, path);
    defer c.SSL_CTX_free(first);
    const again = try clientContext(a, path);
    defer c.SSL_CTX_free(again);
    try std.testing.expectEqual(first, again);
    try std.testing.expectEqual(@as(c_int, c.SSL_VERIFY_PEER), c.SSL_CTX_get_verify_mode(again));
    // A rewritten CA file must be reloaded; the old context stays valid for its holders.
    try tmp.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = "second CA" });
    const changed = try clientContext(a, path);
    defer c.SSL_CTX_free(changed);
    try std.testing.expect(changed != first);
    try std.testing.expectEqual(@as(c_int, c.SSL_VERIFY_PEER), c.SSL_CTX_get_verify_mode(first));
}

test "chunk lines and early response heads consume only their own bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var source: [2]c_int = undefined;
    var sink: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &source) != 0) return error.SocketFailed;
    defer for (source) |fd| net.close(fd);
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sink) != 0) return error.SocketFailed;
    defer for (sink) |fd| net.close(fd);
    for (source ++ sink) |fd| net.configure(fd, 5);
    const framed = "4;ext=1\r\nbody\r\n0\r\nX-Sum: 1\r\n\r\n";
    try (net.Stream{ .fd = source[1] }).writeAll(framed ++ "NEXT");
    try copyChunked(a, .{ .fd = source[0] }, .{ .fd = sink[0] }, false);
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(framed, buf[0..try (net.Stream{ .fd = sink[1] }).read(&buf)]);
    try std.testing.expectEqualStrings("NEXT", buf[0..try (net.Stream{ .fd = source[0] }).read(&buf)]);

    // An upstream answering mid-upload: each head is consumed alone and the body stays queued.
    try (net.Stream{ .fd = source[1] }).writeAll("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 413 Too Large\r\nContent-Length: 4\r\n\r\nnope");
    var upload: UploadReader = .{ .allocator = a, .down = .{ .fd = sink[0] }, .up = .{ .stream = .{ .fd = source[0] } }, .continued = true };
    try std.testing.expectError(error.EarlyResponse, upload.read(&buf));
    try std.testing.expectEqualStrings("HTTP/1.1 413 Too Large", upload.response.?.first);
    try std.testing.expectEqualStrings("nope", buf[0..try (net.Stream{ .fd = source[0] }).read(&buf)]);
}

test "upgrade relay ends a TLS side with close_notify before its TCP half-close" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const base = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    const directory = try std.fs.path.join(a, &.{ base, "authority" });
    defer a.free(directory);
    var authority = try @import("pki.zig").Authority.initWithOptions(a, io, directory, .{ .allowed_suffix = ".local" });
    defer authority.deinit();
    const server_ctx = try authority.serverContext("relay.local");
    defer c.SSL_CTX_free(server_ctx);
    const client_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TLSFailed;
    defer c.SSL_CTX_free(client_ctx);
    var client: [2]c_int = undefined;
    var server: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &client) != 0) return error.SocketFailed;
    defer for (client) |fd| net.close(fd);
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &server) != 0) return error.SocketFailed;
    defer for (server) |fd| net.close(fd);
    for (client ++ server) |fd| net.configure(fd, 5);
    const upstream = c.SSL_new(server_ctx) orelse return error.TLSFailed;
    defer c.SSL_free(upstream);
    const tunnel = c.SSL_new(client_ctx) orelse return error.TLSFailed;
    defer c.SSL_free(tunnel);
    if (c.SSL_set_fd(upstream, server[1]) != 1 or c.SSL_set_fd(tunnel, server[0]) != 1) return error.TLSFailed;
    const Accept = struct {
        fn run(ssl: *c.SSL, ok: *bool) void {
            ok.* = c.SSL_accept(ssl) == 1;
        }
    };
    var accepted = false;
    const handshake = try std.Thread.spawn(.{}, Accept.run, .{ upstream, &accepted });
    const connected = c.SSL_connect(tunnel) == 1;
    handshake.join();
    try std.testing.expect(connected and accepted);
    var cancel: Cancel = .{};
    const thread = try std.Thread.spawn(.{}, relay, .{ [2]net.Stream{ .{ .fd = client[1] }, .{ .fd = server[0], .ssl = tunnel } }, &cancel, 5000 });
    defer thread.join();
    try (net.Stream{ .fd = client[0] }).writeAll("ping");
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 4), c.SSL_read(upstream, &buf, buf.len));
    try std.testing.expectEqualStrings("ping", buf[0..4]);
    _ = c.shutdown(client[0], c.SHUT_WR);
    // A raw TCP half-close reports SSL_ERROR_SYSCALL/SSL here instead of a clean TLS end.
    const end = c.SSL_read(upstream, &buf, buf.len);
    try std.testing.expectEqual(@as(c_int, 0), end);
    try std.testing.expectEqual(@as(c_int, c.SSL_ERROR_ZERO_RETURN), c.SSL_get_error(upstream, end));
    _ = c.SSL_shutdown(upstream);
    _ = c.shutdown(server[1], c.SHUT_WR);
    try std.testing.expectEqual(@as(usize, 0), try (net.Stream{ .fd = client[0] }).read(&buf));
}

test {
    _ = @import("upstream_http2.zig");
}
