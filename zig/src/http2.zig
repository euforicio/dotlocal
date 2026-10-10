//! HTTP/2 framing and flow control use nghttp2. Each stream has bounded storage.
const std = @import("std");
const net = @import("net.zig");
const proxy = @import("proxy.zig");
const registry = @import("registry.zig");
const routes = @import("routes.zig");
const profile = @import("profile.zig");
const c = net.c;
const A = std.mem.Allocator;
const max_headers = 64 << 10;
const max_streams = 8;
const Informational = struct { status: u16, headers: []const proxy.Header };
const StreamState = struct {
    arena: std.heap.ArenaAllocator,
    worker_arena: std.heap.ArenaAllocator,
    worker: ?std.Thread = null,
    upload_pipe: [2]c_int = .{ -1, -1 },
    tunnel_pipe: [2]c_int = .{ -1, -1 },
    websocket: bool = false,
    tunnel_live: std.atomic.Value(bool) = .init(false),
    worker_done: std.atomic.Value(bool) = .init(false),
    cancel: proxy.Cancel = .{},
    consumed: std.atomic.Value(usize) = .init(0),
    /// Event-loop only: upload bytes queued to the worker but not yet returned to flow control.
    unconsumed: usize = 0,
    upload_done: std.atomic.Value(bool) = .init(false),
    ready: std.atomic.Value(bool) = .init(false),
    infos: [10]Informational = undefined,
    info_count: std.atomic.Value(usize) = .init(0),
    info_sent: usize = 0,
    response_status: u16 = 502,
    response_fields: []const proxy.Header = &.{},
    response_body: []const u8 = "bad gateway\n",
    headers: std.ArrayList(proxy.Header) = .empty,
    request_trailers: std.ArrayList(proxy.Header) = .empty,
    response_trailers: std.ArrayList(proxy.Header) = .empty,
    response_head: ?proxy.Head = null,
    header_bytes: usize = 0,
    response: []const u8 = "",
    offset: usize = 0,
    completed: bool = false,
    pending_upstream: ?proxy.Upstream = null,
    route: ?registry.protocol.Route = null,
    authority: []const u8 = "",
    started: bool = false,
    upload_remaining: ?u64 = null,
    upload_chunked: bool = false,
    upstream: ?proxy.Upstream = null,
    remaining: ?u64 = null,
    chunked: bool = false,
    chunk_remaining: u64 = 0,
    chunk_stage: enum { size, data, crlf, trailers, done } = .size,
    line_buf: [8192]u8 = undefined,
    line_len: usize = 0,
    trailer_bytes: usize = 0,
    deferred: bool = false,
    poll_events: c_short = c.POLLIN,
    fn deinit(self: *StreamState) void {
        self.cancel.stop();
        if (self.upload_pipe[0] >= 0) _ = c.shutdown(self.upload_pipe[0], c.SHUT_RDWR);
        if (self.upload_pipe[1] >= 0) _ = c.shutdown(self.upload_pipe[1], c.SHUT_RDWR);
        for (self.tunnel_pipe) |fd| {
            if (fd >= 0) _ = c.shutdown(fd, c.SHUT_RDWR);
        }
        if (self.worker) |thread| thread.join();
        for (self.upload_pipe) |fd| if (fd >= 0) net.close(fd);
        for (self.tunnel_pipe) |fd| if (fd >= 0) net.close(fd);
        if (self.pending_upstream) |up| up.deinit();
        if (self.upstream) |up| up.deinit();
        self.arena.deinit();
        self.worker_arena.deinit();
    }
    fn allocator(self: *StreamState) A {
        return self.arena.allocator();
    }
    /// Event-loop only: true while the stream waits on its upstream rather
    /// than on the client: the response head is not yet produced, body bytes
    /// are not yet available, or an RFC 8441 tunnel is still live. A stream
    /// stalled only on client flow control does not hold the connection.
    fn awaitingUpstream(self: *StreamState) bool {
        if (self.deferred and self.upstream != null) return true;
        if (self.worker == null or self.worker_done.load(.acquire)) return false;
        return !self.ready.load(.acquire) or self.tunnel_live.load(.acquire);
    }
    fn get(self: *StreamState, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| if (std.mem.eql(u8, header.name, name)) return header.value;
        return null;
    }
};
const Connection = struct {
    allocator: A,
    io: std.Io,
    stream: net.Stream,
    source: union(enum) { registry: *registry.Registry, table: *const routes.Table },
    config: profile.Config,
    ca_path: ?[]const u8,
    remote: []const u8,
    streams: std.AutoHashMapUnmanaged(i32, *StreamState) = .empty,
    wake: [2]c_int = .{ -1, -1 },
    fn notify(self: *Connection) void {
        _ = c.send(self.wake[1], "x", 1, 0);
    }
    fn resolve(self: *Connection, allocator: A, authority: []const u8) !?registry.protocol.Route {
        return switch (self.source) {
            .registry => |reg| reg.resolve(allocator, authority),
            .table => |table| table.resolve(allocator, authority),
        };
    }
};
fn context(user: ?*anyopaque) *Connection {
    return @ptrCast(@alignCast(user.?));
}
fn beginHeaders(session: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
    const conn = context(user);
    if (frame.*.headers.cat != c.NGHTTP2_HCAT_REQUEST) return 0;
    const id = frame.*.hd.stream_id;
    if (conn.streams.contains(id)) return 0;
    if (conn.streams.count() >= max_streams) {
        _ = c.nghttp2_submit_rst_stream(session, 0, id, c.NGHTTP2_REFUSED_STREAM);
        return 0;
    }
    const state = conn.allocator.create(StreamState) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    state.* = .{ .arena = std.heap.ArenaAllocator.init(conn.allocator), .worker_arena = std.heap.ArenaAllocator.init(conn.allocator) };
    conn.streams.put(conn.allocator, id, state) catch {
        conn.allocator.destroy(state);
        return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    };
    return 0;
}
fn headerCallback(session: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, name: [*c]const u8, namelen: usize, value: [*c]const u8, valuelen: usize, _: u8, user: ?*anyopaque) callconv(.c) c_int {
    const conn = context(user);
    const state = conn.streams.get(frame.*.hd.stream_id) orelse return 0;
    if (state.completed) return 0;
    state.header_bytes += namelen + valuelen;
    if (state.header_bytes > max_headers or state.headers.items.len + state.request_trailers.items.len >= 128) {
        _ = c.nghttp2_submit_rst_stream(session, 0, frame.*.hd.stream_id, c.NGHTTP2_ENHANCE_YOUR_CALM);
        return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    const a = state.allocator();
    const n = a.dupe(u8, name[0..namelen]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    const v = a.dupe(u8, value[0..valuelen]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    const target = if (frame.*.headers.cat == c.NGHTTP2_HCAT_REQUEST) &state.headers else &state.request_trailers;
    if (target == &state.request_trailers and (state.websocket or proxy.forbiddenTrailer(n))) return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    target.append(a, .{ .name = n, .value = v }) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}
fn dataCallback(session: ?*c.nghttp2_session, _: u8, id: i32, bytes: [*c]const u8, len: usize, user: ?*anyopaque) callconv(.c) c_int {
    const conn = context(user);
    // Refused streams still received this DATA against the connection window.
    const state = conn.streams.get(id) orelse {
        _ = c.nghttp2_session_consume(session, id, len);
        return 0;
    };
    if (len == 0) return 0;
    if ((state.completed or state.ready.load(.acquire)) and !state.tunnel_live.load(.acquire)) {
        _ = c.nghttp2_session_consume(session, id, len);
        return 0;
    }
    var offset: usize = 0;
    while (offset < len) {
        const count = c.send(state.upload_pipe[1], bytes + offset, len - offset, 0);
        if (count <= 0) {
            _ = c.nghttp2_session_consume(session, id, len - offset);
            if (!state.ready.load(.acquire) or state.tunnel_live.load(.acquire)) _ = c.nghttp2_submit_rst_stream(session, 0, id, c.NGHTTP2_INTERNAL_ERROR);
            break;
        }
        offset += @intCast(count);
        state.unconsumed += @intCast(count);
    }
    return 0;
}
fn forwardUpload(state: *StreamState, bytes: []const u8) !void {
    const stream = state.pending_upstream orelse return error.InvalidRequest;
    if (state.upload_remaining) |*remaining| {
        if (bytes.len > remaining.*) return error.InvalidContentLength;
        remaining.* -= bytes.len;
    }
    if (state.upload_chunked) {
        var header: [32]u8 = undefined;
        try stream.writeAll(try std.fmt.bufPrint(&header, "{x}\r\n", .{bytes.len}));
        try stream.writeAll(bytes);
        try stream.writeAll("\r\n");
    } else try stream.writeAll(bytes);
}
fn readResponse(session: ?*c.nghttp2_session, id: i32, buf: [*c]u8, len: usize, flags: [*c]u32, source: [*c]c.nghttp2_data_source, _: ?*anyopaque) callconv(.c) isize {
    const state: *StreamState = @ptrCast(@alignCast(source.*.ptr.?));
    if (state.upstream != null or state.tunnel_live.load(.acquire)) {
        const count = readLive(state, buf[0..len]) catch |err| {
            if (err == error.WouldBlock) {
                state.deferred = true;
                return c.NGHTTP2_ERR_DEFERRED;
            }
            return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        };
        if (count == 0 or (state.remaining != null and state.remaining.? == 0) or state.chunk_stage == .done) {
            flags.* |= c.NGHTTP2_DATA_FLAG_EOF;
            if (state.response_trailers.items.len != 0) {
                flags.* |= c.NGHTTP2_DATA_FLAG_NO_END_STREAM;
                const fields = state.allocator().alloc(c.nghttp2_nv, state.response_trailers.items.len) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
                for (state.response_trailers.items, 0..) |header, i| fields[i] = nv(header.name, header.value);
                if (c.nghttp2_submit_trailer(session, id, fields.ptr, fields.len) != 0) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }
        return @intCast(count);
    }
    const count = @min(len, state.response.len - state.offset);
    @memcpy(buf[0..count], state.response[state.offset .. state.offset + count]);
    state.offset += count;
    if (state.offset == state.response.len) flags.* |= c.NGHTTP2_DATA_FLAG_EOF;
    return @intCast(count);
}
fn streamClose(session: ?*c.nghttp2_session, id: i32, _: u32, user: ?*anyopaque) callconv(.c) c_int {
    const conn = context(user);
    const entry = conn.streams.fetchRemove(id) orelse return 0;
    // Undrained upload bytes die with the stream, but still count against the connection window.
    if (entry.value.unconsumed != 0) _ = c.nghttp2_session_consume_connection(session, entry.value.unconsumed);
    entry.value.deinit();
    conn.allocator.destroy(entry.value);
    return 0;
}
fn frameCallback(session: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
    const conn = context(user);
    const state = conn.streams.get(frame.*.hd.stream_id) orelse return 0;
    const id = frame.*.hd.stream_id;
    if (frame.*.hd.type == c.NGHTTP2_HEADERS and !state.started) {
        state.started = true;
        prepareRequest(conn, session, id, state) catch {
            state.completed = true;
            submit(session, id, state, 502, &.{}, "bad gateway\n") catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        };
        if (state.worker == null) state.completed = true;
    }
    if ((frame.*.hd.type == c.NGHTTP2_HEADERS or frame.*.hd.type == c.NGHTTP2_DATA) and frame.*.hd.flags & c.NGHTTP2_FLAG_END_STREAM != 0 and (!state.completed or state.websocket)) {
        state.upload_done.store(true, .release);
        if (state.upload_pipe[1] >= 0) _ = c.shutdown(state.upload_pipe[1], c.SHUT_WR);
    }
    return 0;
}
fn nv(name: []const u8, value: []const u8) c.nghttp2_nv {
    return .{ .name = @constCast(name.ptr), .value = @constCast(value.ptr), .namelen = name.len, .valuelen = value.len, .flags = c.NGHTTP2_NV_FLAG_NONE };
}
fn submit(session: ?*c.nghttp2_session, id: i32, state: *StreamState, status: u16, headers: []const proxy.Header, body: []const u8) !void {
    const a = state.allocator();
    state.response = body;
    var has_length = false;
    for (headers) |header| if (std.mem.eql(u8, header.name, "content-length")) {
        has_length = true;
    };
    const live = state.upstream != null or state.tunnel_live.load(.acquire);
    const add_length = !has_length and !live and status != 204 and status != 304;
    const fields = try a.alloc(c.nghttp2_nv, headers.len + 2 + @intFromBool(add_length));
    fields[0] = nv(":status", try std.fmt.allocPrint(a, "{d}", .{status}));
    fields[1] = nv("x-dotlocal", "1");
    for (headers, 0..) |header, i| fields[i + 2] = nv(header.name, header.value);
    if (add_length) fields[fields.len - 1] = nv("content-length", try std.fmt.allocPrint(a, "{d}", .{body.len}));
    var provider: c.nghttp2_data_provider2 = .{ .source = .{ .ptr = state }, .read_callback = readResponse };
    if (c.nghttp2_submit_response2(session, id, fields.ptr, fields.len, if (body.len == 0 and !live) null else &provider) != 0) return error.Http2SubmitFailed;
}
fn prepareRequest(conn: *Connection, session: ?*c.nghttp2_session, id: i32, state: *StreamState) !void {
    const a = state.allocator();
    const method = state.get(":method") orelse return submit(session, id, state, 400, &.{}, "missing method\n");
    if (!proxy.validToken(method)) return submit(session, id, state, 400, &.{}, "invalid method\n");
    if (std.mem.eql(u8, method, "CONNECT")) {
        const protocol = state.get(":protocol") orelse return submit(session, id, state, 405, &.{}, "CONNECT is not supported\n");
        if (!std.mem.eql(u8, protocol, "websocket")) return submit(session, id, state, 501, &.{}, "CONNECT supports WebSockets only\n");
        state.websocket = true;
    }
    const path = state.get(":path") orelse return submit(session, id, state, 400, &.{}, "missing path\n");
    if (!std.mem.startsWith(u8, path, "/") or std.mem.startsWith(u8, path, "//")) return submit(session, id, state, 400, &.{}, "invalid path\n");
    for (path) |ch| if (ch <= 32 or ch == 127) return submit(session, id, state, 400, &.{}, "invalid path\n");
    const authority = state.get(":authority") orelse return submit(session, id, state, 400, &.{}, "missing authority\n");
    const request_head: proxy.Head = .{ .first = "", .raw = "", .headers = state.headers.items };
    const request_framing = proxy.framing(request_head) catch return submit(session, id, state, 400, &.{}, "invalid request framing\n");
    if (request_framing.chunked) return submit(session, id, state, 400, &.{}, "invalid HTTP2 transfer encoding\n");
    _ = proxy.trailerNames(a, request_head) catch return submit(session, id, state, 400, &.{}, "invalid trailers\n");
    if (state.get("expect")) |expect| if (!std.ascii.eqlIgnoreCase(expect, "100-continue")) return submit(session, id, state, 417, &.{}, "expectation failed\n");
    _ = proxy.proxyHops(state.get("x-dotlocal-hops")) catch |err| return submit(session, id, state, if (err == error.ProxyLoop) 508 else 400, &.{}, "invalid proxy hops\n");
    if (state.get("x-dotlocal-hops") == null and state.get("x-dotlocal-proxy-hop") != null) return submit(session, id, state, 508, &.{}, "proxy loop\n");
    const route = (conn.resolve(a, authority) catch return submit(session, id, state, 400, &.{}, "invalid authority\n")) orelse return submit(session, id, state, 404, &.{}, "unknown host\n");
    state.route = route;
    state.authority = authority;
    if (state.websocket and request_framing.length != null and request_framing.length.? != 0) return submit(session, id, state, 400, &.{}, "invalid WebSocket framing\n");
    state.upload_remaining = if (state.websocket) null else request_framing.length;
    if (state.get("expect") != null) try submitInformational(session, id, a, 100, &.{});
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &state.upload_pipe) != 0) return error.SocketFailed;
    for (state.upload_pipe) |fd| net.configure(fd, 30);
    const send_buffer: c_int = 131072;
    if (c.setsockopt(state.upload_pipe[1], c.SOL_SOCKET, c.SO_SNDBUF, &send_buffer, @sizeOf(c_int)) != 0) return error.SocketFailed;
    const flags = c.fcntl(state.upload_pipe[1], c.F_GETFL);
    if (flags < 0 or c.fcntl(state.upload_pipe[1], c.F_SETFL, flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    if (state.websocket) {
        if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &state.tunnel_pipe) != 0) return error.SocketFailed;
        for (state.tunnel_pipe) |fd| {
            net.configure(fd, 30);
            const old = c.fcntl(fd, c.F_GETFL);
            if (old < 0 or c.fcntl(fd, c.F_SETFL, old | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
        }
        const bound: c_int = 32768;
        if (c.setsockopt(state.tunnel_pipe[1], c.SOL_SOCKET, c.SO_SNDBUF, &bound, @sizeOf(c_int)) != 0) return error.SocketFailed;
    }
    state.worker = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, exchangeWorker, .{ conn, state });
}
fn exchangeWorker(conn: *Connection, state: *StreamState) void {
    defer {
        state.ready.store(true, .release);
        _ = c.shutdown(state.upload_pipe[0], c.SHUT_RD);
        if (state.tunnel_pipe[1] >= 0) _ = c.shutdown(state.tunnel_pipe[1], c.SHUT_WR);
        state.worker_done.store(true, .release);
        conn.notify();
    }
    (if (state.websocket) exchangeWebSocket(conn, state) else exchangeUpstream(conn, state)) catch {
        if (state.pending_upstream) |up| up.deinit();
        state.pending_upstream = null;
    };
}
fn exchangeUpstream(conn: *Connection, state: *StreamState) !void {
    const a = state.worker_arena.allocator();
    const method = state.get(":method").?;
    const path = state.get(":path").?;
    const authority = state.authority;
    const route = state.route.?;
    const head: proxy.Head = .{ .first = "", .raw = "", .headers = state.headers.items };
    const names = try proxy.trailerNames(a, head);
    const public_url = try conn.config.publicUrl(a, authority);
    const public_authority = public_url[std.mem.indexOf(u8, public_url, "://").? + 3 ..];
    const up = try proxy.connectHttpWatched(a, route, conn.ca_path, true, &state.cancel);
    var transferred = false;
    defer if (!transferred) up.deinit();
    var request: std.Io.Writer.Allocating = .init(a);
    try request.writer.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\n", .{ method, path, public_authority });
    for (state.headers.items) |header| {
        if (header.name[0] == ':' or proxy.hop(head, header.name) or proxy.forwardingHeader(header.name) or std.mem.eql(u8, header.name, "host") or std.mem.eql(u8, header.name, "content-length") or std.mem.eql(u8, header.name, "expect")) continue;
        try request.writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    // HTTP/2 permits trailing HEADERS without a declaration in the initial block.
    state.upload_chunked = true;
    try request.writer.writeAll("Transfer-Encoding: chunked\r\n");
    try proxy.writeTrailerNames(&request.writer, names);
    try request.writer.print("Connection: close\r\nX-Forwarded-For: {s}\r\nX-Forwarded-Host: {s}\r\nX-Forwarded-Proto: {s}\r\nX-dotlocal-Proxy-Hop: 1\r\nX-dotlocal-Hops: {d}\r\n\r\n", .{ conn.remote, public_authority, conn.config.scheme, (try proxy.proxyHops(state.get("x-dotlocal-hops"))) + 1 });
    try up.writeAll(request.written());
    state.pending_upstream = up;
    transferred = true;
    var bytes: [16384]u8 = undefined;
    while (true) {
        if (state.cancel.stopped.load(.acquire)) return error.Canceled;
        const count = c.recv(state.upload_pipe[0], &bytes, bytes.len, 0);
        if (count < 0) return error.ReadFailed;
        if (count == 0) {
            if (!state.upload_done.load(.acquire)) return error.Canceled;
            break;
        }
        _ = state.consumed.fetchAdd(@intCast(count), .release);
        conn.notify();
        forwardUpload(state, bytes[0..@intCast(count)]) catch |err| {
            if (err == error.EarlyResponse) break;
            return err;
        };
    }
    try finishResponse(conn, state);
}

// WebSocket tunnels keep all upstream TLS operations on one bounded worker.
// Socketpairs decouple its two directions from nghttp2 callbacks and windows.
fn exchangeWebSocket(conn: *Connection, state: *StreamState) !void {
    const a = state.worker_arena.allocator();
    const up = try proxy.connectHttpWatched(a, state.route.?, conn.ca_path, false, &state.cancel);
    var transferred = false;
    defer if (!transferred) up.deinit();
    var random: [16]u8 = undefined;
    // RFC 6455 only needs a fresh nonce; the std CSPRNG is portable across libcs.
    conn.io.random(&random);
    var key_buffer: [24]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&key_buffer, &random);
    const url = try conn.config.publicUrl(a, state.authority);
    const authority = url[std.mem.indexOf(u8, url, "://").? + 3 ..];
    const head: proxy.Head = .{ .first = "", .raw = "", .headers = state.headers.items };
    var request: std.Io.Writer.Allocating = .init(a);
    try request.writer.print("GET {s} HTTP/1.1\r\nHost: {s}\r\n", .{ state.get(":path").?, authority });
    for (state.headers.items) |header| {
        if (header.name[0] == ':' or proxy.hop(head, header.name) or proxy.forwardingHeader(header.name) or std.mem.eql(u8, header.name, "host") or std.mem.eql(u8, header.name, "content-length") or std.mem.eql(u8, header.name, "expect") or std.mem.eql(u8, header.name, "sec-websocket-key")) continue;
        try request.writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try request.writer.print("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {s}\r\n", .{key});
    if (state.get("sec-websocket-version") == null) try request.writer.writeAll("Sec-WebSocket-Version: 13\r\n");
    try request.writer.print("X-Forwarded-For: {s}\r\nX-Forwarded-Host: {s}\r\nX-Forwarded-Proto: {s}\r\nX-dotlocal-Proxy-Hop: 1\r\nX-dotlocal-Hops: {d}\r\n\r\n", .{ conn.remote, authority, conn.config.scheme, (try proxy.proxyHops(state.get("x-dotlocal-hops"))) + 1 });
    try up.writeAll(request.written());
    var response: proxy.Head = undefined;
    var status: u16 = 0;
    while (true) {
        response = try proxy.readHead(a, up);
        status = try proxy.responseStatus(response);
        if (status == 101 or status >= 200) break;
        const index = state.info_count.load(.monotonic);
        if (index >= state.infos.len) return error.TooManyInformationalResponses;
        var fields: std.ArrayList(proxy.Header) = .empty;
        for (response.headers) |header| if (!proxy.hop(response, header.name) and !std.ascii.eqlIgnoreCase(header.name, "content-length") and !std.ascii.eqlIgnoreCase(header.name, "alt-svc")) try fields.append(a, header);
        state.infos[index] = .{ .status = status, .headers = fields.items };
        state.info_count.store(index + 1, .release);
        conn.notify();
    }
    if (status != 101) {
        transferred = try publishResponse(conn, state, up, response, status);
        return;
    }
    if (!std.ascii.eqlIgnoreCase(response.get("upgrade") orelse "", "websocket")) return error.InvalidUpgrade;
    var connection = std.mem.splitScalar(u8, response.get("connection") orelse "", ',');
    var upgrade = false;
    while (connection.next()) |token| if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "upgrade")) {
        upgrade = true;
    };
    if (!upgrade) return error.InvalidUpgrade;
    var accepts: usize = 0;
    for (response.headers) |header| if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-accept")) {
        accepts += 1;
    };
    // SHA-1 is mandated by RFC 6455's handshake, not used for a security digest.
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(try std.fmt.allocPrint(a, "{s}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", .{key}), &digest, .{});
    var expected: [28]u8 = undefined;
    const accept = std.base64.standard.Encoder.encode(&expected, &digest);
    if (accepts != 1 or !std.mem.eql(u8, response.get("sec-websocket-accept") orelse "", accept)) return error.InvalidUpgrade;
    const framing = try proxy.framing(response);
    if (framing.chunked or (framing.length != null and framing.length.? != 0)) return error.InvalidUpgrade;
    var fields: std.ArrayList(proxy.Header) = .empty;
    for (response.headers) |header| {
        if (proxy.hop(response, header.name) or std.ascii.eqlIgnoreCase(header.name, "sec-websocket-accept") or std.ascii.eqlIgnoreCase(header.name, "content-length") or std.ascii.eqlIgnoreCase(header.name, "x-dotlocal") or std.ascii.eqlIgnoreCase(header.name, "alt-svc")) continue;
        try fields.append(a, .{ .name = try std.ascii.allocLowerString(a, header.name), .value = header.value });
    }
    const flags = c.fcntl(up.stream.fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(up.stream.fd, c.F_SETFL, flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    state.response_status = 200;
    state.response_fields = fields.items;
    state.response_body = "";
    state.tunnel_live.store(true, .release);
    state.ready.store(true, .release);
    conn.notify();
    try tunnel(conn, state, up.stream);
}

fn tunnelRead(stream: net.Stream, bytes: []u8, events: *c_short) !usize {
    const count = if (stream.ssl) |ssl| c.SSL_read(ssl, bytes.ptr, @intCast(bytes.len)) else c.recv(stream.fd, bytes.ptr, bytes.len, 0);
    if (count > 0) return @intCast(count);
    if (stream.ssl) |ssl| switch (c.SSL_get_error(ssl, @intCast(count))) {
        c.SSL_ERROR_ZERO_RETURN => return 0,
        c.SSL_ERROR_WANT_READ => {
            events.* = c.POLLIN;
            return error.WouldBlock;
        },
        c.SSL_ERROR_WANT_WRITE => {
            events.* = c.POLLOUT;
            return error.WouldBlock;
        },
        else => return error.ReadFailed,
    };
    if (count == 0) return 0;
    if (std.posix.errno(count) == .AGAIN or std.posix.errno(count) == .INTR) {
        events.* = c.POLLIN;
        return error.WouldBlock;
    }
    return error.ReadFailed;
}
fn tunnelWrite(stream: net.Stream, bytes: []const u8, events: *c_short) !usize {
    const count = if (stream.ssl) |ssl| c.SSL_write(ssl, bytes.ptr, @intCast(bytes.len)) else c.send(stream.fd, bytes.ptr, bytes.len, 0);
    if (count > 0) return @intCast(count);
    if (stream.ssl) |ssl| switch (c.SSL_get_error(ssl, @intCast(count))) {
        c.SSL_ERROR_WANT_READ => {
            events.* = c.POLLIN;
            return error.WouldBlock;
        },
        c.SSL_ERROR_WANT_WRITE => {
            events.* = c.POLLOUT;
            return error.WouldBlock;
        },
        else => return error.WriteFailed,
    };
    if (std.posix.errno(count) == .AGAIN or std.posix.errno(count) == .INTR) {
        events.* = c.POLLOUT;
        return error.WouldBlock;
    }
    return error.WriteFailed;
}
fn tunnel(conn: *Connection, state: *StreamState, stream: net.Stream) !void {
    var upload: [16384]u8 = undefined;
    var download: [16384]u8 = undefined;
    var upload_count: usize = 0;
    var upload_offset: usize = 0;
    var download_count: usize = 0;
    var download_offset: usize = 0;
    var upload_eof = false;
    var download_eof = false;
    var half_closed = false;
    var read_events: c_short = c.POLLIN;
    var write_events: c_short = c.POLLOUT;
    const upload_flags = c.fcntl(state.upload_pipe[0], c.F_GETFL);
    if (upload_flags < 0 or c.fcntl(state.upload_pipe[0], c.F_SETFL, upload_flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    while (!state.cancel.stopped.load(.acquire)) {
        var progress = false;
        if (upload_count == 0 and !upload_eof) {
            const count = c.recv(state.upload_pipe[0], &upload, upload.len, 0);
            if (count > 0) {
                upload_count = @intCast(count);
                upload_offset = 0;
                progress = true;
            } else if (count == 0) {
                upload_eof = true;
                progress = true;
            } else if (std.posix.errno(count) != .AGAIN and std.posix.errno(count) != .INTR) return error.ReadFailed;
        }
        if (upload_count > 0) {
            const count = tunnelWrite(stream, upload[upload_offset..][0..upload_count], &write_events) catch |err| if (err == error.WouldBlock) 0 else return err;
            if (count > 0) {
                upload_offset += count;
                upload_count -= count;
                _ = state.consumed.fetchAdd(count, .release);
                conn.notify();
                progress = true;
            }
        }
        if (upload_eof and upload_count == 0 and !half_closed) {
            _ = c.shutdown(stream.fd, c.SHUT_WR);
            half_closed = true;
        }
        if (download_count == 0 and !download_eof) {
            const count = tunnelRead(stream, &download, &read_events) catch |err| if (err == error.WouldBlock) null else return err;
            if (count) |n| {
                download_count = n;
                download_offset = 0;
                download_eof = n == 0;
                progress = true;
            }
        }
        if (download_count > 0) {
            const count = c.send(state.tunnel_pipe[1], download[download_offset..].ptr, download_count, 0);
            if (count > 0) {
                download_offset += @intCast(count);
                download_count -= @intCast(count);
                progress = true;
            } else if (std.posix.errno(count) != .AGAIN and std.posix.errno(count) != .INTR) return error.WriteFailed;
        }
        if (download_eof and download_count == 0) return;
        if (progress) continue;
        var polls = [_]c.struct_pollfd{
            .{ .fd = stream.fd, .events = (if (download_count == 0 and !download_eof) read_events else @as(c_short, 0)) | (if (upload_count > 0) write_events else @as(c_short, 0)), .revents = 0 },
            .{ .fd = state.upload_pipe[0], .events = if (upload_count == 0 and !upload_eof) c.POLLIN else 0, .revents = 0 },
            .{ .fd = state.tunnel_pipe[1], .events = if (download_count > 0) c.POLLOUT else 0, .revents = 0 },
        };
        // POLLHUP/POLLERR are reported even for zero events; a closed side with
        // nothing to wait on must leave the set or poll returns at once and spins.
        for (&polls) |*poll| if (poll.events == 0) {
            poll.fd = -1;
        };
        const pending = download_count == 0 and if (stream.ssl) |ssl| c.SSL_pending(ssl) > 0 else false;
        const ready = c.poll(&polls, polls.len, if (pending) 0 else 1000);
        if (ready < 0 and std.posix.errno(ready) != .INTR) return error.PollFailed;
    }
    return error.Canceled;
}

fn submitInformational(session: ?*c.nghttp2_session, id: i32, a: A, status: u16, headers: []const proxy.Header) !void {
    const fields = try a.alloc(c.nghttp2_nv, headers.len + 1);
    fields[0] = nv(":status", try std.fmt.allocPrint(a, "{d}", .{status}));
    for (headers, 0..) |header, i| fields[i + 1] = nv(try std.ascii.allocLowerString(a, header.name), header.value);
    if (c.nghttp2_submit_headers(session, 0, id, null, fields.ptr, fields.len, null) < 0) return error.Http2SubmitFailed;
}
fn finishResponse(conn: *Connection, state: *StreamState) !void {
    const a = state.worker_arena.allocator();
    const up = state.pending_upstream orelse return error.InvalidRequest;
    state.pending_upstream = null;
    var transferred = false;
    defer if (!transferred) up.deinit();
    const early = if (up.http2) |client| client.final_received else false;
    if (!early) if (state.upload_remaining) |remaining| {
        if (remaining != 0) return error.InvalidContentLength;
    };
    if (state.upload_chunked and !early) {
        try up.writeAll("0\r\n");
        const request_head: proxy.Head = .{ .first = "", .raw = "", .headers = state.headers.items };
        for (state.request_trailers.items) |header| {
            if (proxy.hop(request_head, header.name) or proxy.forwardingHeader(header.name) or std.ascii.eqlIgnoreCase(header.name, "alt-svc")) continue;
            try up.writeAll(try std.fmt.allocPrint(a, "{s}: {s}\r\n", .{ header.name, header.value }));
        }
        try up.writeAll("\r\n");
    }
    var head: proxy.Head = undefined;
    var status: u16 = 0;
    var informational: usize = 0;
    while (true) {
        head = try proxy.readHead(a, up);
        status = try proxy.responseStatus(head);
        if (status >= 200) break;
        if (status == 101) return error.InvalidResponse;
        informational += 1;
        if (informational > 10) return error.TooManyInformationalResponses;
        if (status == 100 and state.get("expect") != null) continue;
        var fields: std.ArrayList(proxy.Header) = .empty;
        for (head.headers) |header| if (!proxy.hop(head, header.name) and !std.ascii.eqlIgnoreCase(header.name, "content-length") and !std.ascii.eqlIgnoreCase(header.name, "alt-svc")) try fields.append(a, header);
        const index = state.info_count.load(.monotonic);
        state.infos[index] = .{ .status = status, .headers = fields.items };
        state.info_count.store(index + 1, .release);
        conn.notify();
    }
    transferred = try publishResponse(conn, state, up, head, status);
}
fn publishResponse(conn: *Connection, state: *StreamState, up: proxy.Upstream, head: proxy.Head, status: u16) !bool {
    const a = state.worker_arena.allocator();
    const route = state.route.?;
    const public_url = try conn.config.publicUrl(a, state.authority);
    const method = state.get(":method").?;
    var return_live = false;
    _ = try proxy.trailerNames(a, head);
    state.response_head = head;
    const response_framing = try proxy.framing(head);
    var headers: std.ArrayList(proxy.Header) = .empty;
    for (head.headers) |header| {
        if (proxy.hop(head, header.name) or std.ascii.eqlIgnoreCase(header.name, "x-dotlocal") or std.ascii.eqlIgnoreCase(header.name, "alt-svc") or (status == 204 and std.ascii.eqlIgnoreCase(header.name, "content-length"))) continue;
        const value = if (std.ascii.eqlIgnoreCase(header.name, "location")) try proxy.rewriteLocation(a, header.value, route, public_url) else header.value;
        try headers.append(a, .{ .name = try std.ascii.allocLowerString(a, header.name), .value = value });
    }
    if (!std.mem.eql(u8, method, "HEAD") and status != 204 and status != 304) {
        state.chunked = response_framing.chunked;
        state.remaining = response_framing.length;
        const old_flags = c.fcntl(up.stream.fd, c.F_GETFL);
        if (old_flags < 0 or c.fcntl(up.stream.fd, c.F_SETFL, old_flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
        state.upstream = up;
        return_live = true;
    }
    state.response_status = status;
    state.response_fields = headers.items;
    state.response_body = "";
    return return_live;
}
/// Nonblocking source reads let nghttp2 defer each stream without blocking siblings.
fn sourceRead(state: *StreamState, bytes: []u8) !usize {
    if (state.tunnel_live.load(.acquire)) {
        const count = c.recv(state.tunnel_pipe[0], bytes.ptr, bytes.len, 0);
        if (count >= 0) return @intCast(count);
        if (std.posix.errno(count) == .AGAIN) {
            state.poll_events = c.POLLIN;
            return error.WouldBlock;
        }
        return error.ReadFailed;
    }
    if (state.upstream.?.http2) |client| {
        return client.read(bytes) catch |err| {
            if (err == error.WouldBlock) state.poll_events = client.poll_events;
            return err;
        };
    }
    return sourceSocket(state, bytes, false);
}
fn sourceSocket(state: *StreamState, bytes: []u8, comptime peeking: bool) !usize {
    const stream = state.upstream.?.stream;
    const len: c_int = @intCast(@min(bytes.len, std.math.maxInt(c_int)));
    const count = if (stream.ssl) |ssl| (if (peeking) c.SSL_peek(ssl, bytes.ptr, len) else c.SSL_read(ssl, bytes.ptr, len)) else c.recv(stream.fd, bytes.ptr, bytes.len, if (peeking) c.MSG_PEEK else 0);
    if (count > 0) return @intCast(count);
    if (stream.ssl) |ssl| {
        switch (c.SSL_get_error(ssl, @intCast(count))) {
            c.SSL_ERROR_ZERO_RETURN => return 0,
            c.SSL_ERROR_WANT_READ => {
                state.poll_events = c.POLLIN;
                return error.WouldBlock;
            },
            c.SSL_ERROR_WANT_WRITE => {
                state.poll_events = c.POLLOUT;
                return error.WouldBlock;
            },
            else => return error.ReadFailed,
        }
    }
    if (count == 0) return 0;
    if (std.posix.errno(count) == .AGAIN) {
        state.poll_events = c.POLLIN;
        return error.WouldBlock;
    }
    return error.ReadFailed;
}
/// HTTP/1 upstream lines are peeked and consumed only through their LF, so
/// chunk data stays queued and a WouldBlock never loses partial progress.
fn sourceLine(state: *StreamState) ![]const u8 {
    const peekable = !state.tunnel_live.load(.acquire) and state.upstream.?.http2 == null;
    while (state.line_len < state.line_buf.len) {
        const rest = state.line_buf[state.line_len..];
        if (!peekable) {
            if (try sourceRead(state, rest[0..1]) == 0) return error.UnexpectedEOF;
            state.line_len += 1;
        } else {
            const count = try sourceSocket(state, rest, true);
            if (count == 0) return error.UnexpectedEOF;
            const take = if (std.mem.indexOfScalar(u8, rest[0..count], '\n')) |index| index + 1 else count;
            var taken: usize = 0;
            while (taken < take) {
                const n = try sourceSocket(state, rest[taken..take], false);
                if (n == 0) return error.UnexpectedEOF;
                taken += n;
                state.line_len += n;
            }
        }
        if (state.line_len >= 2 and std.mem.endsWith(u8, state.line_buf[0..state.line_len], "\r\n")) {
            const line_value = state.line_buf[0 .. state.line_len - 2];
            state.line_len = 0;
            return line_value;
        }
    }
    return error.LineTooLong;
}
fn readLive(state: *StreamState, bytes: []u8) !usize {
    if (!state.chunked) {
        if (state.remaining) |remaining| if (remaining == 0) return 0;
        const limit: usize = if (state.remaining) |remaining| @intCast(@min(bytes.len, remaining)) else bytes.len;
        const count = try sourceRead(state, bytes[0..limit]);
        if (state.remaining) |*remaining| {
            if (count == 0 and remaining.* != 0) return error.UnexpectedEOF;
            remaining.* -= count;
        }
        return count;
    }
    while (true) switch (state.chunk_stage) {
        .size => {
            const text = try sourceLine(state);
            state.chunk_remaining = try proxy.chunkSize(text);
            state.chunk_stage = if (state.chunk_remaining == 0) .trailers else .data;
        },
        .data => {
            const limit: usize = @intCast(@min(bytes.len, state.chunk_remaining));
            const count = try sourceRead(state, bytes[0..limit]);
            if (count == 0) return error.UnexpectedEOF;
            state.chunk_remaining -= count;
            if (state.chunk_remaining == 0) state.chunk_stage = .crlf;
            return count;
        },
        .crlf => {
            if ((try sourceLine(state)).len != 0) return error.InvalidChunk;
            state.chunk_stage = .size;
        },
        .trailers => {
            const text = try sourceLine(state);
            state.trailer_bytes += text.len + 2;
            if (state.trailer_bytes > max_headers) return error.HeadersTooLarge;
            if (text.len == 0) {
                state.chunk_stage = .done;
                return 0;
            }
            const header = try proxy.parseHeader(text);
            if (proxy.forbiddenTrailer(header.name)) return error.InvalidTrailer;
            const response_head = state.response_head.?;
            if (!proxy.hop(response_head, header.name) and !proxy.forwardingHeader(header.name) and !std.ascii.eqlIgnoreCase(header.name, "alt-svc")) try state.response_trailers.append(state.allocator(), .{ .name = try std.ascii.allocLowerString(state.allocator(), header.name), .value = try state.allocator().dupe(u8, header.value) });
        },
        .done => return 0,
    };
}
fn readExact(stream: net.Stream, bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try stream.read(bytes[offset..]);
        if (count == 0) return error.UnexpectedEOF;
        offset += count;
    }
}
/// Route tables are immutable for the lifetime of their listener; registries serialize mutations.
/// The allocator must be thread-safe and reclaim allocations; do not pass a connection arena.
pub fn serve(a: A, io: std.Io, stream: net.Stream, reg: anytype, config: profile.Config, ca_path: ?[]const u8, remote: []const u8) !void {
    return serveIdle(a, io, stream, reg, config, ca_path, remote, 30_000);
}
/// `idle_ms` closes a connection with no peer traffic and no stream awaiting its upstream.
fn serveIdle(a: A, io: std.Io, stream: net.Stream, reg: anytype, config: profile.Config, ca_path: ?[]const u8, remote: []const u8, idle_ms: c_int) !void {
    const source: @FieldType(Connection, "source") = if (@TypeOf(reg) == *registry.Registry) .{ .registry = reg } else if (@TypeOf(reg) == *routes.Table or @TypeOf(reg) == *const routes.Table) .{ .table = reg } else @compileError("HTTP/2 requires *Registry or *Table");
    var conn: Connection = .{ .allocator = a, .io = io, .stream = stream, .source = source, .config = config, .ca_path = ca_path, .remote = remote };
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &conn.wake) != 0) return error.SocketFailed;
    defer for (conn.wake) |fd| net.close(fd);
    for (conn.wake) |fd| {
        net.configure(fd, 30);
        const flags = c.fcntl(fd, c.F_GETFL);
        if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    }
    defer {
        var it = conn.streams.valueIterator();
        while (it.next()) |state| {
            state.*.deinit();
            a.destroy(state.*);
        }
        conn.streams.deinit(a);
    }
    var callbacks: ?*c.nghttp2_session_callbacks = null;
    if (c.nghttp2_session_callbacks_new(&callbacks) != 0) return error.OutOfMemory;
    defer c.nghttp2_session_callbacks_del(callbacks);
    c.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, beginHeaders);
    c.nghttp2_session_callbacks_set_on_header_callback(callbacks, headerCallback);
    c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, dataCallback);
    c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frameCallback);
    c.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, streamClose);
    var session: ?*c.nghttp2_session = null;
    var options: ?*c.nghttp2_option = null;
    if (c.nghttp2_option_new(&options) != 0) return error.OutOfMemory;
    defer c.nghttp2_option_del(options);
    c.nghttp2_option_set_no_auto_window_update(options, 1);
    if (c.nghttp2_session_server_new2(&session, callbacks, &conn, options) != 0) return error.Http2InitFailed;
    defer c.nghttp2_session_del(session);
    const settings = [_]c.nghttp2_settings_entry{ .{ .settings_id = c.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = max_streams }, .{ .settings_id = c.NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, .value = max_headers }, .{ .settings_id = c.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 16384 }, .{ .settings_id = c.NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, .value = 1 } };
    if (c.nghttp2_submit_settings(session, 0, &settings, settings.len) != 0) return error.Http2InitFailed;
    var buf: [32768]u8 = undefined;
    while (true) {
        var states = conn.streams.iterator();
        while (states.next()) |entry| {
            const state = entry.value_ptr.*;
            const id = entry.key_ptr.*;
            const consumed = state.consumed.swap(0, .acquire);
            if (consumed != 0) {
                state.unconsumed -= consumed;
                _ = c.nghttp2_session_consume(session, id, consumed);
            }
            // Acquire the final result first so every preceding 1xx is queued before it.
            const result_ready = state.ready.load(.acquire);
            const info_count = state.info_count.load(.acquire);
            while (state.info_sent < info_count) : (state.info_sent += 1) {
                const info = state.infos[state.info_sent];
                try submitInformational(session, id, state.allocator(), info.status, info.headers);
            }
            if (!state.completed and result_ready) {
                state.completed = true;
                try submit(session, id, state, state.response_status, state.response_fields, state.response_body);
            }
        }
        while (true) {
            var bytes: [*c]const u8 = null;
            const count = c.nghttp2_session_mem_send2(session, &bytes);
            if (count < 0) return error.Http2SendFailed;
            if (count == 0) break;
            try stream.writeAll(bytes[0..@intCast(count)]);
        }
        if (c.nghttp2_session_want_read(session) == 0 and c.nghttp2_session_want_write(session) == 0) return;
        var polls: [max_streams + 2]c.struct_pollfd = undefined;
        var ids: [max_streams + 2]i32 = undefined;
        polls[0] = .{ .fd = stream.fd, .events = c.POLLIN, .revents = 0 };
        polls[1] = .{ .fd = conn.wake[0], .events = c.POLLIN, .revents = 0 };
        var poll_count: usize = 2;
        var entries = conn.streams.iterator();
        while (entries.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.deferred and (state.upstream != null or state.tunnel_live.load(.acquire))) {
                polls[poll_count] = .{ .fd = if (state.tunnel_live.load(.acquire)) state.tunnel_pipe[0] else state.upstream.?.stream.fd, .events = state.poll_events, .revents = 0 };
                ids[poll_count] = entry.key_ptr.*;
                poll_count += 1;
            }
        }
        const downstream_pending = if (stream.ssl) |ssl| c.SSL_pending(ssl) > 0 else false;
        const ready = c.poll(&polls, @intCast(poll_count), if (downstream_pending) 0 else idle_ms);
        if (ready < 0) {
            if (std.posix.errno(ready) == .INTR) continue;
            return error.PollFailed;
        }
        // Idle means no client traffic and no stream waiting on its upstream;
        // those waits are bounded by their own socket timeouts. Streams
        // blocked only on client flow control do not keep the connection.
        if (ready == 0 and !downstream_pending) {
            var pending = conn.streams.valueIterator();
            while (pending.next()) |state| {
                if (state.*.awaitingUpstream()) break;
            } else return;
            continue;
        }
        if (polls[1].revents != 0) {
            var wake_buf: [128]u8 = undefined;
            while (c.recv(conn.wake[0], &wake_buf, wake_buf.len, 0) > 0) {}
        }
        for (polls[2..poll_count], ids[2..poll_count]) |poll, id| {
            if (poll.revents != 0) {
                if (conn.streams.get(id)) |state| state.deferred = false;
                _ = c.nghttp2_session_resume_data(session, id);
            }
        }
        if (downstream_pending or polls[0].revents != 0) {
            const count = try stream.read(&buf);
            if (count == 0) return;
            const consumed = c.nghttp2_session_mem_recv2(session, &buf, count);
            if (consumed < 0 or consumed != count) return error.Http2ReceiveFailed;
        }
    }
}

const ClientResult = struct { status: u16 = 0, body: std.ArrayList(u8) = .empty, done: bool = false };
fn clientHeader(_: ?*c.nghttp2_session, _: [*c]const c.nghttp2_frame, name: [*c]const u8, name_len: usize, value: [*c]const u8, value_len: usize, _: u8, user: ?*anyopaque) callconv(.c) c_int {
    const result: *ClientResult = @ptrCast(@alignCast(user.?));
    if (std.mem.eql(u8, name[0..name_len], ":status")) result.status = std.fmt.parseInt(u16, value[0..value_len], 10) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}
fn clientData(_: ?*c.nghttp2_session, _: u8, _: i32, bytes: [*c]const u8, len: usize, user: ?*anyopaque) callconv(.c) c_int {
    const result: *ClientResult = @ptrCast(@alignCast(user.?));
    result.body.appendSlice(std.testing.allocator, bytes[0..len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}
fn clientFrame(_: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
    const result: *ClientResult = @ptrCast(@alignCast(user.?));
    if ((frame.*.hd.type == c.NGHTTP2_HEADERS or frame.*.hd.type == c.NGHTTP2_DATA) and frame.*.hd.flags & c.NGHTTP2_FLAG_END_STREAM != 0) result.done = true;
    return 0;
}
test "real HTTP2 session over sockets rejects unknown authority" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    var reg = try registry.Registry.init(a, io, path, .{ .scheme = "http" });
    defer reg.deinit();
    try exchangeTest(&reg, .{ .scheme = "http" }, "unknown.local", "/", 404, "unknown host\n", 30_000);
}

fn exchangeTest(reg: anytype, config: profile.Config, authority: []const u8, path: []const u8, expected_status: u16, expected_body: []const u8, idle_ms: c_int) !void {
    const a = std.testing.allocator;
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    net.configure(sockets[0], 5);
    net.configure(sockets[1], 5);
    defer net.close(sockets[0]);
    defer net.close(sockets[1]);
    const ServerState = struct {
        reg: @TypeOf(reg),
        config: profile.Config,
        fd: c_int,
        idle_ms: c_int,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            serveIdle(std.heap.c_allocator, std.testing.io, .{ .fd = self.fd }, self.reg, self.config, null, "127.0.0.1", self.idle_ms) catch |err| {
                self.err = err;
            };
        }
    };
    var server_state: ServerState = .{ .reg = reg, .config = config, .fd = sockets[1], .idle_ms = idle_ms };
    const thread = try std.Thread.spawn(.{}, ServerState.run, .{&server_state});
    defer {
        _ = c.shutdown(sockets[0], c.SHUT_RDWR);
        thread.join();
    }
    var result: ClientResult = .{};
    defer result.body.deinit(a);
    var callbacks: ?*c.nghttp2_session_callbacks = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_callbacks_new(&callbacks));
    defer c.nghttp2_session_callbacks_del(callbacks);
    c.nghttp2_session_callbacks_set_on_header_callback(callbacks, clientHeader);
    c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, clientData);
    c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, clientFrame);
    var session: ?*c.nghttp2_session = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_client_new(&session, callbacks, &result));
    defer c.nghttp2_session_del(session);
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_submit_settings(session, 0, null, 0));
    const fields = [_]c.nghttp2_nv{ nv(":method", "GET"), nv(":scheme", "http"), nv(":authority", authority), nv(":path", path) };
    try std.testing.expect(c.nghttp2_submit_request2(session, null, &fields, fields.len, null, null) > 0);
    const stream: net.Stream = .{ .fd = sockets[0] };
    var buf: [16384]u8 = undefined;
    while (!result.done) {
        while (true) {
            var bytes: [*c]const u8 = null;
            const count = c.nghttp2_session_mem_send2(session, &bytes);
            if (count < 0) return error.Http2SendFailed;
            if (count == 0) break;
            try stream.writeAll(bytes[0..@intCast(count)]);
        }
        const count = try stream.read(&buf);
        if (count == 0) return error.UnexpectedEOF;
        if (c.nghttp2_session_mem_recv2(session, &buf, count) != count) return error.Http2ReceiveFailed;
    }
    try std.testing.expectEqual(expected_status, result.status);
    try std.testing.expectEqualStrings(expected_body, result.body.items);
}

/// A real HTTP/1 backend for one proxied GET /table, optionally answering late.
const TableBackend = struct {
    listener: c_int,
    delay_us: c_uint = 0,
    err: ?anyerror = null,
    fn run(self: *TableBackend) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }
    fn serve(self: *TableBackend) !void {
        const fd = c.accept(self.listener, null, null);
        if (fd < 0) return error.AcceptFailed;
        defer net.close(fd);
        net.configure(fd, 5);
        var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
        defer arena.deinit();
        const stream: net.Stream = .{ .fd = fd };
        const request = try proxy.readHead(arena.allocator(), stream);
        if (!std.mem.eql(u8, request.first, "GET /table HTTP/1.1")) return error.InvalidRequest;
        const forwarded = request.get("x-forwarded-host") orelse return error.InvalidRequest;
        if (!std.mem.eql(u8, forwarded, "app.local:18080")) return error.InvalidRequest;
        var end: [5]u8 = undefined;
        try readExact(stream, &end);
        if (!std.mem.eql(u8, &end, "0\r\n\r\n")) return error.InvalidRequest;
        if (self.delay_us != 0) _ = c.usleep(self.delay_us);
        try stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\ntable backed\n");
    }
};
fn tableExchange(delay_us: c_uint, idle_ms: c_int) !void {
    const a = std.testing.allocator;
    const listener = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(listener);
    net.configure(listener, 5);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(listener, @ptrCast(&address), &length) != 0) return error.SocketFailed;
    const port = std.mem.bigToNative(u16, address.sin_port);
    var table = try routes.Table.init(a, ".local", false);
    defer table.deinit();
    try table.set(.{ .name = "app.local", .scheme = "http", .host = "127.0.0.1", .port = port });
    var backend: TableBackend = .{ .listener = listener, .delay_us = delay_us };
    const thread = try std.Thread.spawn(.{}, TableBackend.run, .{&backend});
    const result = exchangeTest(&table, .{ .scheme = "http", .listen = "127.0.0.1:18080", .tld = ".local" }, "app.local", "/table", 200, "table backed\n", idle_ms);
    thread.join();
    try result;
    if (backend.err) |err| return err;
}
test "real HTTP2 session routes through an ephemeral LAN table" {
    try tableExchange(0, 30_000);
}
test "HTTP2 idle timeout does not close a connection awaiting an upstream response" {
    // The backend answers well after the idle timeout with no client traffic in between.
    try tableExchange(600_000, 100);
}

/// Requests with a zero initial stream window, waits for the response head,
/// then goes silent. The server must close the connection near `idle_ms`.
fn stalledClient(reg: anytype, config: profile.Config, authority: []const u8, path: []const u8, expected_status: u16, idle_ms: c_int) !void {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    defer for (sockets) |fd| net.close(fd);
    for (sockets) |fd| net.configure(fd, 5);
    const Server = struct {
        reg: @TypeOf(reg),
        config: profile.Config,
        fd: c_int,
        idle_ms: c_int,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            serveIdle(std.heap.c_allocator, std.testing.io, .{ .fd = self.fd }, self.reg, self.config, null, "127.0.0.1", self.idle_ms) catch |err| {
                self.err = err;
            };
            // The daemon closes the socket once serve returns.
            _ = c.shutdown(self.fd, c.SHUT_RDWR);
        }
    };
    var server: Server = .{ .reg = reg, .config = config, .fd = sockets[1], .idle_ms = idle_ms };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer {
        _ = c.shutdown(sockets[0], c.SHUT_RDWR);
        thread.join();
    }
    var result: ClientResult = .{};
    defer result.body.deinit(a);
    var callbacks: ?*c.nghttp2_session_callbacks = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_callbacks_new(&callbacks));
    defer c.nghttp2_session_callbacks_del(callbacks);
    c.nghttp2_session_callbacks_set_on_header_callback(callbacks, clientHeader);
    c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, clientData);
    var session: ?*c.nghttp2_session = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_client_new(&session, callbacks, &result));
    defer c.nghttp2_session_del(session);
    const window = [_]c.nghttp2_settings_entry{.{ .settings_id = c.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, .value = 0 }};
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_submit_settings(session, 0, &window, window.len));
    const fields = [_]c.nghttp2_nv{ nv(":method", "GET"), nv(":scheme", "http"), nv(":authority", authority), nv(":path", path) };
    try std.testing.expect(c.nghttp2_submit_request2(session, null, &fields, fields.len, null, null) > 0);
    const stream: net.Stream = .{ .fd = sockets[0] };
    var buf: [16384]u8 = undefined;
    while (result.status == 0) {
        while (true) {
            var bytes: [*c]const u8 = null;
            const count = c.nghttp2_session_mem_send2(session, &bytes);
            if (count < 0) return error.Http2SendFailed;
            if (count == 0) break;
            try stream.writeAll(bytes[0..@intCast(count)]);
        }
        const count = try stream.read(&buf);
        if (count == 0) return error.UnexpectedEOF;
        if (c.nghttp2_session_mem_recv2(session, &buf, count) != count) return error.Http2ReceiveFailed;
    }
    try std.testing.expectEqual(expected_status, result.status);
    // Silent from here on: no WINDOW_UPDATE, no reads acknowledged.
    const started = std.Io.Clock.awake.now(io).nanoseconds;
    while (true) {
        const count = try stream.read(&buf);
        if (count == 0) break;
    }
    const elapsed_ms = @divTrunc(std.Io.Clock.awake.now(io).nanoseconds - started, std.time.ns_per_ms);
    try std.testing.expect(elapsed_ms < 2_000);
    try std.testing.expectEqual(@as(usize, 0), result.body.items.len);
    if (server.err) |err| return err;
}
test "HTTP2 idle timeout closes a connection stalled on client flow control" {
    const a = std.testing.allocator;
    // A locally produced response body that the client never opens a window for.
    var empty = try routes.Table.init(a, ".local", false);
    defer empty.deinit();
    try stalledClient(&empty, .{ .scheme = "http" }, "unknown.local", "/", 404, 100);
    // A proxied response whose upstream body is ready but blocked on the client window.
    const listener = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(listener);
    net.configure(listener, 5);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(listener, @ptrCast(&address), &length) != 0) return error.SocketFailed;
    var table = try routes.Table.init(a, ".local", false);
    defer table.deinit();
    try table.set(.{ .name = "app.local", .scheme = "http", .host = "127.0.0.1", .port = std.mem.bigToNative(u16, address.sin_port) });
    var backend: TableBackend = .{ .listener = listener };
    const thread = try std.Thread.spawn(.{}, TableBackend.run, .{&backend});
    const result = stalledClient(&table, .{ .scheme = "http", .listen = "127.0.0.1:18080", .tld = ".local" }, "app.local", "/table", 200, 100);
    thread.join();
    try result;
    if (backend.err) |err| return err;
}

fn uploadSource(_: ?*c.nghttp2_session, _: i32, buf: [*c]u8, len: usize, _: [*c]u32, source: [*c]c.nghttp2_data_source, _: ?*anyopaque) callconv(.c) isize {
    const left: *usize = @ptrCast(@alignCast(source.*.ptr.?));
    const count = @min(len, left.*);
    if (count == 0) return c.NGHTTP2_ERR_DEFERRED;
    @memset(buf[0..count], 'x');
    left.* -= count;
    return @intCast(count);
}
test "reset uploads return undrained bytes to the connection window" {
    const a = std.testing.allocator;
    // The HTTPS upstream never answers TLS, so no worker drains its upload pipe before the reset.
    const listener = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(listener);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(listener, @ptrCast(&address), &length) != 0) return error.SocketFailed;
    var table = try routes.Table.init(a, ".localhost", false);
    defer table.deinit();
    try table.set(.{ .name = "stall.localhost", .scheme = "https", .host = "127.0.0.1", .port = std.mem.bigToNative(u16, address.sin_port) });
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    defer for (sockets) |fd| net.close(fd);
    for (sockets) |fd| net.configure(fd, 5);
    const Server = struct {
        fn run(table_ptr: *routes.Table, fd: c_int) void {
            serve(std.heap.c_allocator, std.testing.io, .{ .fd = fd }, table_ptr, .{ .scheme = "http" }, null, "127.0.0.1") catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Server.run, .{ &table, sockets[1] });
    defer {
        _ = c.shutdown(sockets[0], c.SHUT_RDWR);
        thread.join();
    }
    var callbacks: ?*c.nghttp2_session_callbacks = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_callbacks_new(&callbacks));
    defer c.nghttp2_session_callbacks_del(callbacks);
    var session: ?*c.nghttp2_session = null;
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_session_client_new(&session, callbacks, null));
    defer c.nghttp2_session_del(session);
    try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_submit_settings(session, 0, null, 0));
    const stream: net.Stream = .{ .fd = sockets[0] };
    const flush = struct {
        fn send(s: ?*c.nghttp2_session, out: net.Stream) !void {
            while (true) {
                var bytes: [*c]const u8 = null;
                const count = c.nghttp2_session_mem_send2(s, &bytes);
                if (count < 0) return error.Http2SendFailed;
                if (count == 0) return;
                try out.writeAll(bytes[0..@intCast(count)]);
            }
        }
    }.send;
    const per_stream = 16384;
    var budgets: [3]usize = @splat(per_stream);
    const fields = [_]c.nghttp2_nv{ nv(":method", "POST"), nv(":scheme", "http"), nv(":authority", "stall.localhost"), nv(":path", "/") };
    for (&budgets) |*budget| {
        var provider: c.nghttp2_data_provider2 = .{ .source = .{ .ptr = budget }, .read_callback = uploadSource };
        const id = c.nghttp2_submit_request2(session, null, &fields, fields.len, &provider, null);
        try std.testing.expect(id > 0);
        try flush(session, stream);
        try std.testing.expectEqual(@as(usize, 0), budget.*);
        try std.testing.expectEqual(@as(c_int, 0), c.nghttp2_submit_rst_stream(session, 0, id, c.NGHTTP2_CANCEL));
        try flush(session, stream);
    }
    const leaked = 65535 - budgets.len * per_stream;
    // Without the server returning reset bytes, the window never recovers and this read times out.
    var buf: [16384]u8 = undefined;
    while (c.nghttp2_session_get_remote_window_size(session) <= leaked) {
        const count = try stream.read(&buf);
        if (count == 0) return error.UnexpectedEOF;
        if (c.nghttp2_session_mem_recv2(session, &buf, count) != count) return error.Http2ReceiveFailed;
        try flush(session, stream);
    }
    try std.testing.expect(c.nghttp2_session_get_remote_window_size(session) <= 65535);
}
