//! A small real HTTP server shared by the demo and native integration fixtures.
const std = @import("std");
const net = @import("dotlocal").net;
const c = net.c;
const proxy = @import("dotlocal").proxy;
const A = std.mem.Allocator;
pub const Options = struct { page: []const u8 = "dotlocal native server\n", demo: bool = false, fixed_port: ?u16 = null, grandchild: ?c_int = null, static_root: ?[]const u8 = null };
const Context = struct { io: std.Io, env: *const std.process.Environ.Map, options: Options, args: []const []const u8, tls: ?*c.SSL_CTX = null };

pub fn run(init: std.process.Init, options: Options) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    const port = options.fixed_port orelse try std.fmt.parseInt(u16, init.environ_map.get("PORT") orelse "0", 10);
    const listener = try net.tcp(a, init.environ_map.get("HOST") orelse "127.0.0.1", port, true);
    defer net.close(listener);
    var address: c.struct_sockaddr_in = undefined;
    var len: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(listener, @ptrCast(&address), &len) != 0) return error.SocketInspectionFailed;
    var buffer: [512]u8 = undefined;
    var out = std.Io.File.stdout().writer(init.io, &buffer);
    try out.interface.print("127.0.0.1:{d}\n", .{std.mem.bigToNative(u16, address.sin_port)});
    try out.interface.flush();
    var context: Context = .{ .io = init.io, .env = init.environ_map, .options = options, .args = args[1..] };
    if (args.len >= 4 and std.mem.eql(u8, args[1], "tls")) {
        context.tls = try @import("dotlocal").pki.fileContext(a, args[2], args[3]);
        if (args.len >= 5 and std.mem.eql(u8, args[4], "h2")) c.SSL_CTX_set_alpn_select_cb(context.tls, selectAlpn, null);
    }
    defer if (context.tls) |ctx| c.SSL_CTX_free(ctx);
    while (true) {
        const fd = c.accept(listener, null, null);
        if (fd < 0) continue;
        net.configure(fd, 10);
        const thread = std.Thread.spawn(.{ .stack_size = 512 * 1024 }, connection, .{ context, fd }) catch |err| {
            net.close(fd);
            return err;
        };
        thread.detach();
    }
}
fn connection(context: Context, fd: c_int) void {
    var stream: net.Stream = .{ .fd = fd };
    defer stream.deinit();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    if (context.tls) |ctx| {
        stream.ssl = c.SSL_new(ctx) orelse return;
        if (c.SSL_set_fd(stream.ssl, fd) != 1 or c.SSL_accept(stream.ssl) != 1) return;
        var selected: [*c]const u8 = null;
        var length: c_uint = 0;
        c.SSL_get0_alpn_selected(stream.ssl, &selected, &length);
        if (length == 2 and std.mem.eql(u8, selected[0..length], "h2")) {
            @import("server_h2.zig").serve(arena.allocator(), context.io, stream) catch |err| std.debug.print("H2 server: {s}\n", .{@errorName(err)});
            return;
        }
    }
    handle(arena.allocator(), context, stream) catch |err| {
        if (err != error.EndOfStream and err != error.ReadFailed and err != error.WriteFailed) std.debug.print("server: {s}\n", .{@errorName(err)});
    };
}
fn selectAlpn(_: ?*c.SSL, out: [*c][*c]const u8, outlen: [*c]u8, input: [*c]const u8, length: c_uint, _: ?*anyopaque) callconv(.c) c_int {
    var pos: usize = 0;
    while (pos < length) {
        const n = input[pos];
        pos += 1;
        if (pos + n > length) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        if (std.mem.eql(u8, input[pos .. pos + n], "h2")) {
            out.* = input + pos;
            outlen.* = n;
            return c.SSL_TLSEXT_ERR_OK;
        }
        pos += n;
    }
    return c.SSL_TLSEXT_ERR_NOACK;
}
fn line(stream: net.Stream, buffer: []u8) ![]const u8 {
    var n: usize = 0;
    while (n < buffer.len) {
        if (try stream.read(buffer[n .. n + 1]) == 0) return error.EndOfStream;
        n += 1;
        if (std.mem.endsWith(u8, buffer[0..n], "\r\n")) return buffer[0 .. n - 2];
    }
    return error.LineTooLong;
}
pub fn exact(stream: net.Stream, bytes: []u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = try stream.read(bytes[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}
fn respond(stream: net.Stream, status: u16, content_type: []const u8, body: []const u8, head_only: bool) !void {
    var buffer: [512]u8 = undefined;
    try stream.writeAll(try std.fmt.bufPrint(&buffer, "HTTP/1.1 {d} Response\r\nContent-Length: {d}\r\nContent-Type: {s}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", .{ status, body.len, content_type }));
    if (!head_only) try stream.writeAll(body);
}
fn handle(a: A, context: Context, stream: net.Stream) !void {
    const head = try proxy.readHead(a, stream);
    const req = try proxy.requestLine(head);
    const path = req.target[0 .. std.mem.indexOfScalar(u8, req.target, '?') orelse req.target.len];
    const head_only = std.mem.eql(u8, req.method, "HEAD");
    if (context.options.static_root) |root| return static(a, context.io, stream, root, req.method, path);
    if (!context.options.demo and head_only) return stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 123\r\nConnection: close\r\n\r\n");
    if (!context.options.demo and std.mem.eql(u8, path, "/slow-head")) try std.Io.sleep(context.io, .fromSeconds(2), .awake);
    if (!context.options.demo and std.mem.eql(u8, path, "/stall-head")) {
        var byte: [1]u8 = undefined;
        while (try stream.read(&byte) != 0) {}
        return;
    }
    if (!context.options.demo and std.mem.eql(u8, path, "/early")) return respond(stream, 413, "text/plain", "", false);
    var body: std.ArrayList(u8) = .empty;
    var trailers: std.json.ObjectMap = .empty;
    if (head.get("Expect")) |value| if (std.ascii.eqlIgnoreCase(value, "100-continue")) try stream.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
    const framing = try proxy.framing(head);
    if (framing.chunked) {
        var buffer: [8192]u8 = undefined;
        while (true) {
            const size = try proxy.chunkSize(try line(stream, &buffer));
            if (size == 0) break;
            if (body.items.len + size > 32 * 1024 * 1024) return error.BodyTooLarge;
            const old = body.items.len;
            try body.resize(a, old + @as(usize, @intCast(size)));
            try exact(stream, body.items[old..]);
            if ((try line(stream, &buffer)).len != 0) return error.InvalidChunk;
        }
        while (true) {
            const row = try line(stream, &buffer);
            if (row.len == 0) break;
            const field = try proxy.parseHeader(row);
            try trailers.put(a, try std.ascii.allocLowerString(a, field.name), .{ .string = try a.dupe(u8, field.value) });
        }
    } else if (framing.length) |size| {
        if (size > 32 * 1024 * 1024) return error.BodyTooLarge;
        try body.resize(a, @intCast(size));
        try exact(stream, body.items);
    }
    if (context.options.demo) {
        if (std.mem.eql(u8, path, "/")) return respond(stream, 200, "text/html; charset=utf-8", context.options.page, head_only);
        if (!std.mem.eql(u8, path, "/api/info")) return respond(stream, 404, "text/plain", "Not found\n", head_only);
        const info_body = try std.json.Stringify.valueAlloc(a, .{ .public_url = context.env.get("DOTLOCAL_URL"), .forwarded_host = head.get("X-Forwarded-Host"), .forwarded_proto = head.get("X-Forwarded-Proto"), .proxy_hop = head.get("X-dotlocal-Proxy-Hop") }, .{});
        return respond(stream, 200, "application/json", info_body, head_only);
    }
    if (std.mem.eql(u8, path, "/hints")) return stream.writeAll("HTTP/1.1 103 Early Hints\r\nLink: </asset.css>; rel=preload\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    if (std.mem.eql(u8, path, "/ambiguous-response")) return stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    if (std.mem.eql(u8, path, "/legacy")) return stream.writeAll("HTTP/1.0 200 OK\r\n\r\nlegacy body");
    if (std.mem.eql(u8, path, "/trailers")) return stream.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: real-response-trailer\r\n\r\n");
    if (std.mem.eql(u8, path, "/chunked")) return stream.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    if (std.mem.eql(u8, path, "/sse")) {
        try stream.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n");
        try std.Io.sleep(context.io, .fromSeconds(2), .awake);
        return stream.writeAll("e\r\ndata: second\n\n\r\n0\r\n\r\n");
    }
    if (std.mem.eql(u8, path, "/large") or std.mem.eql(u8, path, "/payload")) {
        var chunk: [77824]u8 = undefined;
        for (0..4096) |i| @memcpy(chunk[i * 19 ..][0..19], "dotlocal-real-file\n");
        const count: usize = if (std.mem.eql(u8, path, "/large")) 192 else 1;
        var buffer: [256]u8 = undefined;
        try stream.writeAll(try std.fmt.bufPrint(&buffer, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{chunk.len * count}));
        for (0..count) |_| try stream.writeAll(&chunk);
        return;
    }
    if (std.mem.startsWith(u8, path, "/ws")) return websocket(a, stream, head, path);
    if (std.mem.eql(u8, path, "/redirect")) {
        try stream.writeAll(try std.fmt.allocPrint(a, "HTTP/1.1 302 Found\r\nLocation: http://{s}/target?q=1\r\nContent-Length: 0\r\n\r\n", .{head.get("Host") orelse ""}));
        return;
    }
    var headers: std.json.ObjectMap = .empty;
    for (head.headers) |field| try headers.put(a, try std.ascii.allocLowerString(a, field.name), .{ .string = field.value });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body.items, &digest, .{});
    const data = try std.json.Stringify.valueAlloc(a, .{ .path = path, .body = if (std.mem.eql(u8, path, "/count")) "" else body.items, .headers = std.json.Value{ .object = headers }, .trailers = std.json.Value{ .object = trailers }, .bytes = body.items.len, .sha256 = std.fmt.bytesToHex(digest, .lower), .pid = c.getpid(), .grandchild = context.options.grandchild, .argv = context.args, .url = context.env.get("DOTLOCAL_URL"), .ca = context.env.get("NODE_EXTRA_CA_CERTS"), .host = context.env.get("HOST"), .vite = context.env.get("__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS") }, .{});
    try respond(stream, 200, "application/json", data, head_only);
}
/// Read-only files beneath `root`; any other method or path shape is refused.
fn static(a: A, io: std.Io, stream: net.Stream, root: []const u8, method: []const u8, path: []const u8) !void {
    const head_only = std.mem.eql(u8, method, "HEAD");
    if (!head_only and !std.mem.eql(u8, method, "GET")) return respond(stream, 405, "text/plain", "", false);
    var parts = std.mem.splitScalar(u8, path, '/');
    if (parts.next().?.len != 0 or path.len < 2) return respond(stream, 404, "text/plain", "", head_only);
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..") or std.mem.indexOfAny(u8, part, "\\%") != null) return respond(stream, 404, "text/plain", "", head_only);
    }
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    const bytes = dir.readFileAlloc(io, path[1..], a, .limited(128 << 20)) catch return respond(stream, 404, "text/plain", "", head_only);
    try respond(stream, 200, "application/octet-stream", bytes, head_only);
}
fn websocket(a: A, stream: net.Stream, head: proxy.Head, path: []const u8) !void {
    if (std.mem.eql(u8, path, "/ws-reject")) return respond(stream, 403, "text/plain", "denied", false);
    const key = head.get("Sec-WebSocket-Key") orelse return error.MissingWebSocketKey;
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(try std.mem.concat(a, u8, &.{ key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" }), &digest, .{}); // RFC 6455 public handshake GUID. gitleaks:allow
    var encoded: [28]u8 = undefined;
    const accept = if (std.mem.eql(u8, path, "/ws-invalid")) "invalid" else std.base64.standard.Encoder.encode(&encoded, &digest);
    try stream.writeAll(try std.fmt.allocPrint(a, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n{s}\r\n", .{ accept, if (head.get("Sec-WebSocket-Protocol")) |v| try std.fmt.allocPrint(a, "Sec-WebSocket-Protocol: {s}\r\n", .{v}) else "" }));
    if (std.mem.eql(u8, path, "/ws-invalid")) return;
    if (std.mem.eql(u8, path, "/ws-idle")) {
        var buffer: [4096]u8 = undefined;
        while (try stream.read(&buffer) != 0) {}
        return;
    }
    var first: [2]u8 = undefined;
    try exact(stream, &first);
    if (first[1] & 128 == 0) return error.UnmaskedWebSocketFrame;
    var length: u64 = first[1] & 127;
    var extra: [8]u8 = undefined;
    const n: usize = if (length == 126) 2 else if (length == 127) 8 else 0;
    if (n != 0) {
        try exact(stream, extra[0..n]);
        length = if (n == 2) std.mem.readInt(u16, extra[0..2], .big) else std.mem.readInt(u64, &extra, .big);
    }
    if (length > 1024 * 1024) return error.WebSocketTooLarge;
    var mask: [4]u8 = undefined;
    try exact(stream, &mask);
    const data = try a.alloc(u8, @intCast(length));
    try exact(stream, data);
    for (data, 0..) |*byte, i| byte.* ^= mask[i % 4];
    first[1] &= 127;
    try stream.writeAll(&first);
    try stream.writeAll(extra[0..n]);
    try stream.writeAll(data);
}
