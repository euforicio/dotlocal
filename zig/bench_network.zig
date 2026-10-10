//! Five samples of real file streaming, with a native Zig server and curl client.
const std = @import("std");
const t = @import("test_support.zig");
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.ExpectedCliAndFixture;
    const binary = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[1], init.arena.allocator());
    const server = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[2], init.arena.allocator());
    for ([_][]const u8{ "http", "https", "https" }, [_][]const u8{ "--http1.1", "--http1.1", "--http2" }) |scheme, protocol| {
        var f = try t.Fixture.init(init, binary, server, scheme);
        defer f.cleanup();
        const upstream = try t.port(f.a);
        var backend = try f.backend(upstream);
        defer backend.cleanup();
        try f.start(&.{ "--tld", ".test" }, true);
        try f.alias("app", upstream);
        var samples: [5]f64 = undefined;
        var requests: std.ArrayList([]const u8) = .empty;
        try requests.appendSlice(f.a, &.{ "--write-out", "%{http_version} %{size_download}\n" });
        for (0..19) |_| try requests.appendSlice(f.a, &.{ "--output", "/dev/null", try std.fmt.allocPrint(f.a, "{s}://app.test:{d}/payload", .{ scheme, f.port }) });
        try requests.appendSlice(f.a, &.{ "--output", "/dev/null" });
        for (&samples, 0..) |*sample, index| {
            const started = std.Io.Clock.awake.now(f.io);
            const response = try f.curl("app.test", "/payload", protocol, requests.items);
            var lines = std.mem.tokenizeScalar(u8, response.stdout, '\n');
            var count: usize = 0;
            while (lines.next()) |line| {
                try t.equal(line, if (std.mem.eql(u8, protocol, "--http2")) "2 77824" else "1.1 77824");
                count += 1;
            }
            try t.check(count == 20, "benchmark response count differs");
            sample.* = @as(f64, @floatFromInt(started.durationTo(std.Io.Clock.awake.now(f.io)).nanoseconds)) / 1_000_000 / 20;
            std.debug.print("network-{s}-{s} sample={d} requests=20 payload=77824 bytes ms/request={d:.3}\n", .{ scheme, protocol[2..], index, sample.* });
        }
        std.mem.sort(f64, &samples, {}, std.sort.asc(f64));
        std.debug.print("network-{s}-{s} median-ms/request={d:.3}\n", .{ scheme, protocol[2..], samples[2] });
        try f.stop();
    }
}
