const std = @import("std");
const server = @import("server.zig");

pub fn main(init: std.process.Init) !void {
    try server.run(init, .{ .page = @embedFile("examples/demo/index.html"), .demo = true });
}
