//! One HTTP/2 upstream exchange. HTTP/1 framing keeps both proxy callers streaming.
//! DATA storage is bounded by the advertised stream window; consumption drives WINDOW_UPDATE.
const std = @import("std");
const net = @import("net.zig");
const proxy = @import("proxy.zig");
const c = net.c;
const A = std.mem.Allocator;
pub const Client = struct {
    allocator: A,
    parent: A,
    arena: std.heap.ArenaAllocator,
    stream: net.Stream,
    session: ?*c.nghttp2_session = null,
    id: i32 = -1,
    poll_events: c_short = c.POLLIN,
    pending_out: []const u8 = "",
    head_out: std.ArrayList(u8) = .empty,
    head_offset: usize = 0,
    headers: std.ArrayList(proxy.Header) = .empty,
    trailers: std.ArrayList(proxy.Header) = .empty,
    header_bytes: usize = 0,
    informational: usize = 0,
    final_received: bool = false,
    response_done: bool = false,
    failed: bool = false,
    no_body: bool = false,
    chunked_response: bool = false,
    tail_written: bool = false,
    body: [65536]u8 = undefined,
    body_start: usize = 0,
    body_end: usize = 0,
    encoded: [16416]u8 = undefined,
    encoded_slice: []const u8 = "",
    upload: []const u8 = "",
    upload_done: bool = false,
    upload_trailers: std.ArrayList(proxy.Header) = .empty,
    upload_mode: enum { head, fixed, size, data, crlf, trailers, done } = .head,
    remaining: u64 = 0,
    line: [8192]u8 = undefined,
    line_len: usize = 0,
    authority: []const u8,

    pub fn init(a: A, stream: net.Stream, authority: []const u8) !*Client {
        const self = try a.create(Client);
        errdefer a.destroy(self);
        self.* = .{ .allocator = undefined, .parent = a, .arena = std.heap.ArenaAllocator.init(a), .stream = stream, .authority = authority };
        self.allocator = self.arena.allocator();
        errdefer self.arena.deinit();
        var callbacks: ?*c.nghttp2_session_callbacks = null;
        if (c.nghttp2_session_callbacks_new(&callbacks) != 0) return error.OutOfMemory;
        defer c.nghttp2_session_callbacks_del(callbacks);
        c.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, beginHeaders);
        c.nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
        c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data);
        c.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame);
        c.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, closed);
        var options: ?*c.nghttp2_option = null;
        if (c.nghttp2_option_new(&options) != 0) return error.OutOfMemory;
        defer c.nghttp2_option_del(options);
        c.nghttp2_option_set_no_auto_window_update(options, 1);
        if (c.nghttp2_session_client_new2(&self.session, callbacks, self, options) != 0) return error.Http2InitFailed;
        errdefer c.nghttp2_session_del(self.session);
        const settings = [_]c.nghttp2_settings_entry{
            .{ .settings_id = c.NGHTTP2_SETTINGS_ENABLE_PUSH, .value = 0 },
            .{ .settings_id = c.NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, .value = 65536 },
        };
        if (c.nghttp2_submit_settings(self.session, 0, &settings, settings.len) != 0) return error.Http2InitFailed;
        return self;
    }
    pub fn deinit(self: *Client) void {
        c.nghttp2_session_del(self.session);
        const parent = self.parent;
        self.arena.deinit();
        parent.destroy(self);
    }
    fn ctx(user: ?*anyopaque) *Client {
        return @ptrCast(@alignCast(user.?));
    }
    fn field(name: []const u8, value: []const u8) c.nghttp2_nv {
        return .{ .name = @constCast(name.ptr), .value = @constCast(value.ptr), .namelen = name.len, .valuelen = value.len, .flags = c.NGHTTP2_NV_FLAG_NONE };
    }
    fn beginHeaders(_: ?*c.nghttp2_session, _: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
        const self = ctx(user);
        self.headers.clearRetainingCapacity();
        return 0;
    }
    fn header(_: ?*c.nghttp2_session, _: [*c]const c.nghttp2_frame, name: [*c]const u8, name_len: usize, value: [*c]const u8, value_len: usize, _: u8, user: ?*anyopaque) callconv(.c) c_int {
        const self = ctx(user);
        self.header_bytes += name_len + value_len;
        if (self.header_bytes > 65536 or self.headers.items.len >= 128) return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        const a = self.allocator;
        self.headers.append(a, .{ .name = a.dupe(u8, name[0..name_len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE, .value = a.dupe(u8, value[0..value_len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE }) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        return 0;
    }
    fn data(_: ?*c.nghttp2_session, _: u8, _: i32, bytes: [*c]const u8, len: usize, user: ?*anyopaque) callconv(.c) c_int {
        const self = ctx(user);
        if (len > self.body.len - (self.body_end - self.body_start)) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        if (self.body_end + len > self.body.len) {
            std.mem.copyForwards(u8, &self.body, self.body[self.body_start..self.body_end]);
            self.body_end -= self.body_start;
            self.body_start = 0;
        }
        @memcpy(self.body[self.body_end .. self.body_end + len], bytes[0..len]);
        self.body_end += len;
        return 0;
    }
    fn frame(_: ?*c.nghttp2_session, received: [*c]const c.nghttp2_frame, user: ?*anyopaque) callconv(.c) c_int {
        const self = ctx(user);
        if (received.*.hd.stream_id != self.id) return 0;
        if (received.*.hd.type == c.NGHTTP2_HEADERS) self.receivedHeaders() catch return c.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        if ((received.*.hd.type == c.NGHTTP2_HEADERS or received.*.hd.type == c.NGHTTP2_DATA) and received.*.hd.flags & c.NGHTTP2_FLAG_END_STREAM != 0) self.response_done = true;
        return 0;
    }
    fn closed(_: ?*c.nghttp2_session, _: i32, err: u32, user: ?*anyopaque) callconv(.c) c_int {
        const self = ctx(user);
        // RST_STREAM(NO_ERROR) before END_STREAM truncates the response; it must not look complete.
        if (err != 0 or !self.response_done) self.failed = true;
        self.response_done = true;
        return 0;
    }
    fn receivedHeaders(self: *Client) !void {
        const a = self.allocator;
        if (self.final_received) {
            for (self.headers.items) |h| {
                if (proxy.forbiddenTrailer(h.name)) return error.InvalidTrailer;
                if (!proxy.forwardingHeader(h.name) and !std.ascii.eqlIgnoreCase(h.name, "alt-svc")) try self.trailers.append(a, h);
            }
            return;
        }
        var status: u16 = 0;
        for (self.headers.items) |h| if (std.mem.eql(u8, h.name, ":status")) {
            status = try std.fmt.parseInt(u16, h.value, 10);
        };
        if (status < 100 or status > 599 or status == 101) return error.InvalidResponse;
        if (status < 200) {
            self.informational += 1;
            if (self.informational > 10) return error.TooManyInformationalResponses;
        } else {
            self.final_received = true;
            self.chunked_response = !self.no_body and status != 204 and status != 304;
        }
        var out: std.Io.Writer.Allocating = .init(a);
        defer out.deinit();
        try out.writer.print("HTTP/1.1 {d} Upstream\r\n", .{status});
        for (self.headers.items) |h| {
            if (h.name[0] == ':' or (std.mem.eql(u8, h.name, "content-length") and (self.chunked_response or status < 200 or status == 204))) continue;
            try out.writer.print("{s}: {s}\r\n", .{ h.name, h.value });
        }
        if (self.chunked_response) try out.writer.writeAll("Transfer-Encoding: chunked\r\n");
        try out.writer.writeAll("\r\n");
        try self.head_out.appendSlice(a, out.written());
    }
    fn provide(session: ?*c.nghttp2_session, id: i32, buf: [*c]u8, len: usize, flags: [*c]u32, source: [*c]c.nghttp2_data_source, _: ?*anyopaque) callconv(.c) isize {
        const self: *Client = @ptrCast(@alignCast(source.*.ptr.?));
        const count = @min(len, self.upload.len);
        @memcpy(buf[0..count], self.upload[0..count]);
        self.upload = self.upload[count..];
        if (self.upload.len == 0 and self.upload_done) {
            flags.* |= c.NGHTTP2_DATA_FLAG_EOF;
            if (self.upload_trailers.items.len > 0) {
                flags.* |= c.NGHTTP2_DATA_FLAG_NO_END_STREAM;
                const fields = self.allocator.alloc(c.nghttp2_nv, self.upload_trailers.items.len) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
                defer self.allocator.free(fields);
                for (self.upload_trailers.items, 0..) |h, i| fields[i] = field(h.name, h.value);
                if (c.nghttp2_submit_trailer(session, id, fields.ptr, fields.len) != 0) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        } else if (count == 0) return c.NGHTTP2_ERR_DEFERRED;
        return @intCast(count);
    }
    fn start(self: *Client, raw: []const u8) !void {
        const a = self.allocator;
        const head = try proxy.parseHead(a, raw);
        const parsed = try proxy.requestLine(head);
        const body_framing = try proxy.framing(head);
        self.no_body = std.mem.eql(u8, parsed.method, "HEAD");
        var fields: std.ArrayList(c.nghttp2_nv) = .empty;
        defer fields.deinit(a);
        try fields.appendSlice(a, &.{ field(":method", parsed.method), field(":scheme", "https"), field(":authority", head.get("host") orelse self.authority), field(":path", parsed.target) });
        for (head.headers) |h| {
            if ((proxy.hop(head, h.name) and !std.ascii.eqlIgnoreCase(h.name, "trailer")) or std.ascii.eqlIgnoreCase(h.name, "host")) continue;
            try fields.append(a, field(try std.ascii.allocLowerString(a, h.name), h.value));
        }
        if (body_framing.chunked) {
            self.upload_mode = .size;
        } else {
            self.remaining = body_framing.length orelse 0;
            self.upload_mode = if (self.remaining == 0) .done else .fixed;
            self.upload_done = self.remaining == 0;
        }
        var provider: c.nghttp2_data_provider2 = .{ .source = .{ .ptr = self }, .read_callback = provide };
        self.id = c.nghttp2_submit_request2(self.session, null, fields.items.ptr, fields.items.len, &provider, null);
        if (self.id < 0) return error.Http2SubmitFailed;
        try self.flush();
    }
    fn sendBody(self: *Client, bytes: []const u8) !void {
        self.upload = bytes;
        _ = c.nghttp2_session_resume_data(self.session, self.id);
        while (self.upload.len != 0) {
            try self.flush();
            if (self.upload.len == 0) break;
            if (self.final_received) {
                try self.stopUpload();
                return error.EarlyResponse;
            }
            try self.receive();
        }
    }
    pub fn receiveReady(self: *Client) !void {
        try self.receive();
        try self.flush();
    }
    pub fn stopUpload(self: *Client) !void {
        self.upload = "";
        try self.finish();
    }
    fn finish(self: *Client) !void {
        self.upload_done = true;
        self.upload_mode = .done;
        _ = c.nghttp2_session_resume_data(self.session, self.id);
        try self.flush();
    }
    pub fn writeAll(self: *Client, bytes: []const u8) !void {
        if (self.upload_mode == .head) return self.start(bytes);
        var rest = bytes;
        while (rest.len > 0) switch (self.upload_mode) {
            .fixed, .data => {
                const count: usize = @intCast(@min(rest.len, self.remaining));
                try self.sendBody(rest[0..count]);
                rest = rest[count..];
                self.remaining -= count;
                if (self.remaining == 0) {
                    if (self.upload_mode == .fixed) try self.finish() else self.upload_mode = .crlf;
                }
            },
            .size, .crlf, .trailers => {
                if (self.line_len == self.line.len) return error.LineTooLong;
                self.line[self.line_len] = rest[0];
                self.line_len += 1;
                rest = rest[1..];
                if (self.line_len >= 2 and std.mem.endsWith(u8, self.line[0..self.line_len], "\r\n")) {
                    const line = self.line[0 .. self.line_len - 2];
                    self.line_len = 0;
                    switch (self.upload_mode) {
                        .size => {
                            self.remaining = try proxy.chunkSize(line);
                            self.upload_mode = if (self.remaining == 0) .trailers else .data;
                        },
                        .crlf => {
                            if (line.len != 0) return error.InvalidChunk;
                            self.upload_mode = .size;
                        },
                        .trailers => {
                            if (line.len == 0) {
                                try self.finish();
                            } else {
                                const h = try proxy.parseHeader(line);
                                if (proxy.forbiddenTrailer(h.name)) return error.InvalidTrailer;
                                self.header_bytes += line.len;
                                if (self.header_bytes > 65536) return error.HeadersTooLarge;
                                try self.upload_trailers.append(self.allocator, .{ .name = try std.ascii.allocLowerString(self.allocator, h.name), .value = try self.allocator.dupe(u8, h.value) });
                            }
                        },
                        else => unreachable,
                    }
                }
            },
            .done => return error.InvalidContentLength,
            .head => unreachable,
        };
    }
    fn flush(self: *Client) !void {
        while (true) {
            if (self.pending_out.len == 0) {
                var bytes: [*c]const u8 = null;
                const count = c.nghttp2_session_mem_send2(self.session, &bytes);
                if (count < 0) return error.Http2SendFailed;
                if (count == 0) return;
                self.pending_out = bytes[0..@intCast(count)];
            }
            const out = self.pending_out;
            const count = if (self.stream.ssl) |ssl| c.SSL_write(ssl, out.ptr, @intCast(out.len)) else c.send(self.stream.fd, out.ptr, out.len, 0);
            if (count <= 0) return self.socketError(count, true);
            self.pending_out = self.pending_out[@intCast(count)..];
        }
    }
    fn socketError(self: *Client, count: isize, writing: bool) anyerror {
        if (self.stream.ssl) |ssl| switch (c.SSL_get_error(ssl, @intCast(count))) {
            c.SSL_ERROR_WANT_READ => {
                self.poll_events = c.POLLIN;
                return error.WouldBlock;
            },
            c.SSL_ERROR_WANT_WRITE => {
                self.poll_events = c.POLLOUT;
                return error.WouldBlock;
            },
            else => return error.UpstreamClosed,
        };
        if (std.posix.errno(count) == .AGAIN) {
            self.poll_events = if (writing) c.POLLOUT else c.POLLIN;
            return error.WouldBlock;
        }
        return error.UpstreamClosed;
    }
    fn receive(self: *Client) !void {
        var buf: [16384]u8 = undefined;
        const count = if (self.stream.ssl) |ssl| c.SSL_read(ssl, &buf, buf.len) else c.recv(self.stream.fd, &buf, buf.len, 0);
        if (count <= 0) return self.socketError(count, false);
        if (c.nghttp2_session_mem_recv2(self.session, &buf, @intCast(count)) != count) return error.Http2ReceiveFailed;
        if (self.failed) return error.InvalidResponse;
    }
    /// Synthesizes chunked HTTP/1 framing without accumulating the response body.
    pub fn read(self: *Client, bytes: []u8) !usize {
        while (true) {
            if (self.failed) return error.InvalidResponse;
            if (self.head_offset < self.head_out.items.len) {
                const count = @min(bytes.len, self.head_out.items.len - self.head_offset);
                @memcpy(bytes[0..count], self.head_out.items[self.head_offset .. self.head_offset + count]);
                self.head_offset += count;
                return count;
            }
            if (self.encoded_slice.len > 0) {
                const count = @min(bytes.len, self.encoded_slice.len);
                @memcpy(bytes[0..count], self.encoded_slice[0..count]);
                self.encoded_slice = self.encoded_slice[count..];
                return count;
            }
            if (self.body_start < self.body_end) {
                const count = @min(16384, self.body_end - self.body_start);
                const prefix = try std.fmt.bufPrint(&self.encoded, "{x}\r\n", .{count});
                @memcpy(self.encoded[prefix.len .. prefix.len + count], self.body[self.body_start .. self.body_start + count]);
                @memcpy(self.encoded[prefix.len + count ..][0..2], "\r\n");
                self.encoded_slice = self.encoded[0 .. prefix.len + count + 2];
                self.body_start += count;
                if (c.nghttp2_session_consume(self.session, self.id, count) != 0) return error.Http2ReceiveFailed;
                continue;
            }
            if (self.response_done) {
                if (self.chunked_response and !self.tail_written) {
                    self.tail_written = true;
                    var out: std.Io.Writer.Allocating = .init(self.allocator);
                    try out.writer.writeAll("0\r\n");
                    for (self.trailers.items) |h| try out.writer.print("{s}: {s}\r\n", .{ h.name, h.value });
                    try out.writer.writeAll("\r\n");
                    self.encoded_slice = try out.toOwnedSlice();
                    continue;
                }
                return 0;
            }
            try self.flush();
            try self.receive();
        }
    }
};

test "a stream reset with NO_ERROR before END_STREAM is a truncated response" {
    var sockets: [2]c_int = undefined;
    if (c.socketpair(c.AF_UNIX, c.SOCK_STREAM, 0, &sockets) != 0) return error.SocketFailed;
    defer for (sockets) |fd| net.close(fd);
    for (sockets) |fd| net.configure(fd, 5);
    const server: net.Stream = .{ .fd = sockets[1] };
    // SETTINGS; HEADERS(:status 200, END_HEADERS); DATA "abc"; RST_STREAM(NO_ERROR) on stream 1.
    try server.writeAll("\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88" ++
        "\x00\x00\x03\x00\x00\x00\x00\x00\x01abc" ++
        "\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00");
    const client = try Client.init(std.testing.allocator, .{ .fd = sockets[0] }, "127.0.0.1:1");
    defer client.deinit();
    try client.writeAll("GET / HTTP/1.1\r\nHost: app.localhost\r\n\r\n");
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(std.testing.allocator);
    var buf: [256]u8 = undefined;
    const result = while (true) {
        const count = client.read(&buf) catch |err| break err;
        if (count == 0) break error.Complete;
        try response.appendSlice(std.testing.allocator, buf[0..count]);
    };
    try std.testing.expectEqual(error.InvalidResponse, result);
    try std.testing.expect(std.mem.indexOf(u8, response.items, "0\r\n\r\n") == null);
}
