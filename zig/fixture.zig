//! Real child process and protocol server used by the integration checks.
const std = @import("std");
const server = @import("server.zig");
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len > 1 and std.mem.eql(u8, args[1], "exit")) {
        if (args.len > 3) try std.Io.sleep(init.io, .fromMilliseconds(try std.fmt.parseInt(i64, args[3], 10)), .awake);
        std.process.exit(try std.fmt.parseInt(u8, args[2], 10));
    }
    if (args.len > 1 and std.mem.eql(u8, args[1], "environment")) {
        var buffer: [4096]u8 = undefined;
        var out = std.Io.File.stdout().writer(init.io, &buffer);
        try std.json.Stringify.value(.{ .url = init.environ_map.get("DOTLOCAL_URL"), .argv = args[2..] }, .{}, &out.interface);
        try out.interface.flush();
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "file")) {
        const page = try std.Io.Dir.cwd().readFileAlloc(init.io, try std.fs.path.join(init.arena.allocator(), &.{ args[2], "index.html" }), init.arena.allocator(), .limited(1 << 20));
        return server.run(init, .{ .page = page, .demo = true });
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "stubborn")) {
        // Ignores TERM, as does its inherited grandchild; only group KILL stops both.
        std.posix.sigaction(.TERM, &.{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 }, null);
        const grandchild = try std.process.spawn(init.io, .{ .argv = &.{ "/bin/sleep", "60" }, .stdin = .ignore });
        return server.run(init, .{ .grandchild = grandchild.id.? });
    }
    if (args.len == 6 and std.mem.eql(u8, args[1], "tls") and std.mem.eql(u8, args[4], "static")) return server.run(init, .{ .static_root = args[5] });
    if (args.len == 3 and std.mem.eql(u8, args[1], "fixed")) return server.run(init, .{ .fixed_port = try std.fmt.parseInt(u16, args[2], 10) });
    try server.run(init, .{});
}
