//! Real HTTP/2 wire client with nghttp2 HPACK decoding; no extra runtime.
const std = @import("std");
const t = @import("test_support.zig");
const c = t.c;
pub const Header = struct { name: []const u8, value: []const u8 };
pub const Frame = struct { kind: u8, flags: u8, id: u32, data: []const u8, headers: std.json.Value = .null };
pub const Client = struct {
    stream: t.net.Stream,
    a: t.A,
    decoder: *c.nghttp2_hd_inflater,
    authority: []const u8,
    window: i64 = 65535,
    connection_window: i64 = 65535,
    pub fn init(f: *t.Fixture, host: []const u8) !Client {
        const stream = try f.tls(host, "h2", "127.0.0.1");
        errdefer stream.deinit();
        var decoder: ?*c.nghttp2_hd_inflater = null;
        if (c.nghttp2_hd_inflate_new(&decoder) != 0) return error.HpackFailed;
        var self: Client = .{ .stream = stream, .a = f.a, .decoder = decoder.?, .authority = try std.fmt.allocPrint(f.a, "{s}:{d}", .{ host, f.port }) };
        try stream.writeAll("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        try self.send(4, 0, 0, "");
        while (true) {
            const frame = try self.receive();
            if (frame.kind == 4 and frame.flags == 0) {
                var advertised = false;
                var i: usize = 0;
                while (i + 6 <= frame.data.len) : (i += 6) {
                    const key = std.mem.readInt(u16, frame.data[i..][0..2], .big);
                    const value = std.mem.readInt(u32, frame.data[i + 2 ..][0..4], .big);
                    if (key == 4) self.window = value;
                    if (key == 8) advertised = value == 1;
                }
                try t.check(advertised, "HTTP/2 omitted RFC8441 setting");
                break;
            }
        }
        return self;
    }
    pub fn deinit(self: *Client) void {
        c.nghttp2_hd_inflate_del(self.decoder);
        self.stream.deinit();
    }
    pub fn send(self: *Client, kind: u8, flags: u8, id: u32, data: []const u8) !void {
        var head: [9]u8 = undefined;
        std.mem.writeInt(u24, head[0..3], @intCast(data.len), .big);
        head[3] = kind;
        head[4] = flags;
        std.mem.writeInt(u32, head[5..9], id, .big);
        try self.stream.writeAll(&head);
        try self.stream.writeAll(data);
    }
    pub fn headers(self: *Client, id: u32, flags: u8, fields: []const Header) !void {
        var data: std.ArrayList(u8) = .empty;
        for (fields) |field| {
            try data.append(self.a, 0);
            for ([_][]const u8{ field.name, field.value }) |value| {
                if (value.len >= 127) return error.FixtureHeaderTooLong;
                try data.append(self.a, @intCast(value.len));
                try data.appendSlice(self.a, value);
            }
        }
        try self.send(1, flags, id, data.items);
    }
    pub fn request(self: *Client, id: u32, path: []const u8, tunnel: bool) !void {
        var fields = [_]Header{ .{ .name = ":method", .value = if (tunnel) "CONNECT" else "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = self.authority }, .{ .name = ":path", .value = path }, .{ .name = ":protocol", .value = "websocket" } };
        try self.headers(id, if (tunnel) 4 else 5, fields[0..if (tunnel) 5 else 4]);
    }
    pub fn receive(self: *Client) !Frame {
        var head: [9]u8 = undefined;
        try @import("server.zig").exact(self.stream, &head);
        const n = std.mem.readInt(u24, head[0..3], .big);
        if (n > 65536) return error.H2FrameTooLarge;
        const data = try self.a.alloc(u8, n);
        try @import("server.zig").exact(self.stream, data);
        var frame: Frame = .{ .kind = head[3], .flags = head[4], .id = std.mem.readInt(u32, head[5..9], .big) & 0x7fffffff, .data = data };
        if (frame.kind == 4 and frame.flags == 0) try self.send(4, 1, 0, "");
        if (frame.kind == 1) {
            try t.check(frame.flags & 4 != 0, "fixture response header fragmentation");
            var values: std.json.ObjectMap = .empty;
            var offset: usize = 0;
            while (true) {
                var nv: c.nghttp2_nv = undefined;
                var flags: c_int = 0;
                const used = c.nghttp2_hd_inflate_hd2(self.decoder, &nv, &flags, data.ptr + offset, data.len - offset, 1);
                if (used < 0) return error.HpackFailed;
                offset += @intCast(used);
                if (flags & c.NGHTTP2_HD_INFLATE_EMIT != 0) try values.put(self.a, try self.a.dupe(u8, nv.name[0..nv.namelen]), .{ .string = try self.a.dupe(u8, nv.value[0..nv.valuelen]) });
                if (flags & c.NGHTTP2_HD_INFLATE_FINAL != 0) break;
                if (used == 0 and flags == 0) return error.HpackFailed;
            }
            if (c.nghttp2_hd_inflate_end_headers(self.decoder) != 0) return error.HpackFailed;
            frame.headers = .{ .object = values };
        }
        if (frame.kind == 0 and data.len != 0) {
            try self.credit(0, @intCast(data.len));
            try self.credit(frame.id, @intCast(data.len));
        }
        return frame;
    }
    pub fn credit(self: *Client, id: u32, n: u32) !void {
        var data: [4]u8 = undefined;
        std.mem.writeInt(u32, &data, n, .big);
        try self.send(8, 0, id, &data);
    }
    pub fn response(self: *Client, id: u32, expected: []const u8) ![]u8 {
        var body: std.ArrayList(u8) = .empty;
        var status: []const u8 = "";
        while (true) {
            const frame = try self.receive();
            try t.check(frame.kind != 3 and frame.kind != 7, "HTTP/2 reset response");
            if (frame.id != id) continue;
            if (frame.kind == 1) if (frame.headers.object.get(":status")) |value| {
                status = value.string;
            };
            if (frame.kind == 0) try body.appendSlice(self.a, frame.data);
            if ((frame.kind == 0 or frame.kind == 1) and frame.flags & 1 != 0) break;
        }
        try t.equal(status, expected);
        return body.toOwnedSlice(self.a);
    }
};
