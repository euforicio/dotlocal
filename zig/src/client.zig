//! Protocol-v2 Unix management client. The caller owns every returned parsed response.
const std = @import("std");
const net = @import("net.zig");
const protocol = @import("protocol.zig");
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket_path: []const u8 = "/var/run/dotlocal-zig/management.sock",
    pub fn call(self: Client, original: protocol.Request) !std.json.Parsed(protocol.Response) {
        var request = original;
        var id_buf: [32]u8 = undefined;
        if (request.id.len == 0) {
            var random: [16]u8 = undefined;
            self.io.random(&random);
            id_buf = std.fmt.bytesToHex(random, .lower);
            request.id = &id_buf;
        }
        try request.validate(self.allocator);
        const data = try std.json.Stringify.valueAlloc(self.allocator, request, .{});
        defer self.allocator.free(data);
        const stream: net.Stream = .{ .fd = try net.connectUnix(self.allocator, self.socket_path) };
        defer stream.deinit();
        try stream.writeAll(data);
        try stream.writeAll("\n");
        if (net.c.shutdown(stream.fd, net.c.SHUT_WR) != 0) return error.ShutdownFailed;
        const response_data = try net.readFrame(self.allocator, stream, 1 << 20);
        defer self.allocator.free(response_data);
        const parsed = try parseResponse(self.allocator, response_data, request.id);
        errdefer parsed.deinit();
        if (!parsed.value.ok) {
            if (parsed.value.@"error") |problem| {
                std.log.err("management {s}: {s}", .{ problem.code, problem.message });
            }
            return error.ManagementFailed;
        }
        return parsed;
    }
};

/// Decodes an owned response, enforcing explicit wire identity and error fields.
pub fn parseResponse(a: std.mem.Allocator, bytes: []const u8, id: []const u8) !std.json.Parsed(protocol.Response) {
    // Response.jsonParse rejects omitted identity and route fields in the same pass.
    const parsed = std.json.parseFromSlice(protocol.Response, a, bytes, .{ .allocate = .alloc_always }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
    errdefer parsed.deinit();
    if (parsed.value.version != 2 or !std.mem.eql(u8, parsed.value.id, id)) return error.InvalidResponse;
    if (parsed.value.ok) {
        if (parsed.value.@"error" != null) return error.InvalidResponse;
    } else {
        const problem = parsed.value.@"error" orelse return error.InvalidResponse;
        if (problem.code.len == 0 or problem.message.len == 0) return error.InvalidResponse;
    }
    return parsed;
}
