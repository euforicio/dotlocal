//! Independent real TLS HTTP/2 fixture with request/response trailers and flow control.
const std = @import("std");
const net = @import("dotlocal").net;
const c = net.c;
const A = std.mem.Allocator;
const Request = struct {
    id: i32,
    headers: std.json.ObjectMap = .empty,
    trailers: std.json.ObjectMap = .empty,
    body: std.ArrayList(u8) = .empty,
    response: []const u8 = "",
    offset: usize = 0,
    replied: bool = false,
    closed: bool = false,
    second_event_at: ?std.Io.Timestamp = null,
};
const State = struct { a: A, io: std.Io, stream: net.Stream, session: ?*c.nghttp2_session = null, requests: std.AutoHashMap(i32, *Request) };
fn ctx(user: ?*anyopaque) *State {
    return @ptrCast(@alignCast(user.?));
}
fn field(name: []const u8, value: []const u8) c.nghttp2_nv {
    return .{ .name = @constCast(name.ptr), .value = @constCast(value.ptr), .namelen = name.len, .valuelen = value.len, .flags = c.NGHTTP2_NV_FLAG_NONE };
}
fn begin(_: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
    const self = ctx(user);
    if (!self.requests.contains(frame.*.hd.stream_id)) {
        const request = self.a.create(Request) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        request.* = .{ .id = frame.*.hd.stream_id };
        self.requests.put(request.id, request) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}
fn header(_: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, name: [*c]const u8, n: usize, value: [*c]const u8, len: usize, _: u8, user: ?*anyopaque) callconv(.c) c_int {
    const self = ctx(user);
    const request = self.requests.get(frame.*.hd.stream_id) orelse return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    const map = if (frame.*.headers.cat == c.NGHTTP2_HCAT_REQUEST) &request.headers else &request.trailers;
    map.put(self.a, self.a.dupe(u8, name[0..n]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE, .{ .string = self.a.dupe(u8, value[0..len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE }) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}
fn data(session: ?*c.nghttp2_session, _: u8, id: i32, bytes: [*c]const u8, len: usize, user: ?*anyopaque) callconv(.c) c_int {
    const self = ctx(user);
    const request = self.requests.get(id) orelse return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    if (std.mem.eql(u8, path(request), "/stall-h2-upload")) return 0;
    if (request.body.items.len + len > 32 * 1024 * 1024) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    request.body.appendSlice(self.a, bytes[0..len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    _ = c.nghttp2_session_consume(session, id, len);
    return 0;
}
fn path(request: *Request) []const u8 {
    return if (request.headers.get(":path")) |value| value.string else "/";
}
fn received(session: ?*c.nghttp2_session, frame: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
    const self = ctx(user);
    const request = self.requests.get(frame.*.hd.stream_id) orelse return 0;
    if (frame.*.hd.type != c.NGHTTP2_HEADERS and frame.*.hd.type != c.NGHTTP2_DATA) return 0;
    if (std.mem.eql(u8, path(request), "/early") or frame.*.hd.flags & c.NGHTTP2_FLAG_END_STREAM != 0) reply(self, session, request) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}
fn closed(_: ?*c.nghttp2_session, id: i32, _: u32, user: ?*anyopaque) callconv(.c) c_int {
    if (ctx(user).requests.get(id)) |request| request.closed = true;
    return 0;
}
fn reply(self: *State, session: ?*c.nghttp2_session, request: *Request) !void {
    if (request.replied or std.mem.eql(u8, path(request), "/stall-h2-upload")) return;
    request.replied = true;
    const early = std.mem.eql(u8, path(request), "/early");
    if (std.mem.eql(u8, path(request), "/hints")) {
        const hints = [_]c.nghttp2_nv{ field(":status", "103"), field("link", "</asset.css>; rel=preload") };
        const processing = [_]c.nghttp2_nv{field(":status", "102")};
        if (c.nghttp2_submit_headers(session, 0, request.id, null, &hints, hints.len, null) < 0 or c.nghttp2_submit_headers(session, 0, request.id, null, &processing, processing.len, null) < 0) return error.H2SubmitFailed;
    }
    if (std.mem.eql(u8, path(request), "/large")) {
        const bytes = try self.a.alloc(u8, 12 * 1024 * 1024);
        @memset(bytes, 'z');
        request.response = bytes;
    } else if (std.mem.eql(u8, path(request), "/sse")) {
        request.response = "data: first\n\ndata: second\n\n";
        request.second_event_at = .{ .nanoseconds = std.Io.Clock.awake.now(self.io).nanoseconds + 2 * std.time.ns_per_s };
    } else if (!early) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(request.body.items, &digest, .{});
        request.response = try std.json.Stringify.valueAlloc(self.a, .{ .proto = "HTTP/2.0", .body = if (std.mem.eql(u8, path(request), "/count")) "" else request.body.items, .bytes = request.body.items.len, .sha256 = std.fmt.bytesToHex(digest, .lower), .trailers = std.json.Value{ .object = request.trailers }, .forwarded = if (request.headers.get("x-forwarded-host")) |value| value.string else "" }, .{});
    }
    const fields = [_]c.nghttp2_nv{ field(":status", if (early) "413" else "200"), field("content-type", if (request.second_event_at != null) "text/event-stream" else "application/json"), field("trailer", "x-checksum") };
    const provider: c.nghttp2_data_provider2 = .{ .source = .{ .ptr = request }, .read_callback = provide };
    if (c.nghttp2_submit_response2(session, request.id, &fields, fields.len, if (early) null else &provider) != 0) return error.H2SubmitFailed;
}
fn provide(session: ?*c.nghttp2_session, id: i32, buffer: [*c]u8, len: usize, flags: [*c]u32, source: [*c]c.nghttp2_data_source, user: ?*anyopaque) callconv(.c) isize {
    const request: *Request = @ptrCast(@alignCast(source.*.ptr.?));
    var remaining = request.response.len - request.offset;
    if (request.second_event_at) |due| {
        if (request.offset >= 13 and std.Io.Clock.awake.now(ctx(user).io).nanoseconds < due.nanoseconds) return c.NGHTTP2_ERR_DEFERRED;
        if (request.offset == 0) remaining = 13;
    }
    const count = @min(len, remaining);
    @memcpy(buffer[0..count], request.response[request.offset .. request.offset + count]);
    request.offset += count;
    if (request.offset == request.response.len) {
        flags.* |= c.NGHTTP2_DATA_FLAG_EOF | c.NGHTTP2_DATA_FLAG_NO_END_STREAM;
        const trailers = [_]c.nghttp2_nv{field("x-checksum", "real-h2-upstream-trailer")};
        if (c.nghttp2_submit_trailer(session, id, &trailers, trailers.len) != 0) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return @intCast(count);
}
pub fn serve(a: A, io: std.Io, stream: net.Stream) !void {
    var state: State = .{ .a = a, .io = io, .stream = stream, .requests = std.AutoHashMap(i32, *Request).init(a) };
    var callbacks: ?*c.nghttp2_session_callbacks = null;
    if (c.nghttp2_session_callbacks_new(&callbacks) != 0) return error.OutOfMemory;
    defer c.nghttp2_session_callbacks_del(callbacks);
    c.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin);
    c.nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
    c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data);
    c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, received);
    c.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, closed);
    var options: ?*c.nghttp2_option = null;
    if (c.nghttp2_option_new(&options) != 0) return error.OutOfMemory;
    defer c.nghttp2_option_del(options);
    c.nghttp2_option_set_no_auto_window_update(options, 1);
    if (c.nghttp2_session_server_new2(&state.session, callbacks, &state, options) != 0) return error.H2InitFailed;
    defer c.nghttp2_session_del(state.session);
    const settings = [_]c.nghttp2_settings_entry{.{ .settings_id = c.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = 16 }};
    if (c.nghttp2_submit_settings(state.session, 0, &settings, settings.len) != 0) return error.H2SubmitFailed;
    var buffer: [16384]u8 = undefined;
    while (true) {
        var requests = state.requests.valueIterator();
        while (requests.next()) |request| if (!request.*.closed and request.*.second_event_at != null) {
            _ = c.nghttp2_session_resume_data(state.session, request.*.id);
        };
        while (true) {
            var bytes: [*c]const u8 = null;
            const n = c.nghttp2_session_mem_send2(state.session, &bytes);
            if (n < 0) return error.H2SendFailed;
            if (n == 0) break;
            try stream.writeAll(bytes[0..@intCast(n)]);
        }
        var pollfd: c.struct_pollfd = .{ .fd = stream.fd, .events = c.POLLIN, .revents = 0 };
        if (c.SSL_pending(stream.ssl) == 0 and c.poll(&pollfd, 1, 50) == 0) continue;
        const n = try stream.read(&buffer);
        if (n == 0) return;
        const used = c.nghttp2_session_mem_recv2(state.session, &buffer, n);
        if (used < 0 or used != n) return error.H2ReceiveFailed;
    }
}
