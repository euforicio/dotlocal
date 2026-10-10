const std = @import("std");
const dotlocal = @import("dotlocal");
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.ExpectedStateDirectoryAndSocket;
    const runtime = try dotlocal.daemon.Runtime.init(init.gpa, init.io, .{ .state_dir = args[1], .socket_path = args[2], .profile = .{ .scheme = "http", .listen = args[3] } });
    defer runtime.deinit();
    var stop: std.atomic.Value(bool) = .init(false);
    var future = try init.io.concurrent(dotlocal.daemon.Runtime.run, .{ runtime, &stop });
    defer _ = future.cancel(init.io) catch {};
    var buffer: [1024]u8 = undefined;
    var input = std.Io.File.stdin().reader(init.io, &buffer);
    _ = input.interface.takeDelimiterExclusive('\n') catch {};
    stop.store(true, .release);
    try future.await(init.io);
}
