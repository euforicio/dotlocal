//! Repeatable measurements using real allocations, durable files and cryptography.
const std = @import("std");
const p = @import("dotlocal");
extern "c" fn SSL_CTX_free(?*anyopaque) void;
fn report(io: std.Io, writer: *std.Io.Writer, name: []const u8, sample: usize, count: usize, start: i96) !void {
    const elapsed = std.Io.Clock.awake.now(io).toNanoseconds() - start;
    try writer.print("{s} sample={d} operations={d} ns/op={d}\n", .{ name, sample, count, @divTrunc(elapsed, count) });
    try writer.flush();
}
pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;
    var output_buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &output_buffer);
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const temporary = try std.fmt.allocPrint(a, "/tmp/dotlocal-bench-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    defer a.free(temporary);
    try std.Io.Dir.createDirAbsolute(io, temporary, .fromMode(0o700));
    const directory = try std.Io.Dir.cwd().realPathFileAlloc(io, temporary, a);
    defer a.free(directory);
    defer std.Io.Dir.cwd().deleteTree(io, directory) catch {};
    var table = try p.routes.Table.init(a, ".local", true);
    defer table.deinit();
    try table.set(.{ .name = "app.local", .host = "127.0.0.1", .port = 3000 });
    const request: p.protocol.Request = .{ .id = "bench", .operation = "add", .route = .{ .name = "app.local", .host = "127.0.0.1", .port = 3000 }, .match = "absent" };
    const bytes = try std.json.Stringify.valueAlloc(a, request, .{});
    defer a.free(bytes);
    for (0..5) |sample| {
        var start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..10000) |_| {
            const route = (try table.resolve(a, "child.app.local:443")).?;
            if (route.port != 3000) return error.InvalidBenchmarkResult;
            route.deinit(a);
        }
        try report(io, &output.interface, "route-resolve", sample, 10000, start);
        start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..10000) |_| {
            const parsed = try p.protocol.parseRequest(a, bytes);
            parsed.deinit();
        }
        try report(io, &output.interface, "protocol-parse", sample, 10000, start);
        start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..10000) |_| {
            const serialized = try std.json.Stringify.valueAlloc(a, request, .{});
            a.free(serialized);
        }
        try report(io, &output.interface, "protocol-serialize", sample, 10000, start);
        start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..10000) |_| {
            const head = try p.proxy.parseHead(a, "POST /api HTTP/1.1\r\nHost: app.local\r\nContent-Length: 1234\r\nConnection: close\r\n\r\n");
            defer a.free(head.headers);
            const frame = try p.proxy.framing(head);
            if (frame.length != 1234) return error.InvalidBenchmarkResult;
        }
        try report(io, &output.interface, "http1-head-parse-framing", sample, 10000, start);
    }
    for ([_]usize{ 1, 100, 1024 }) |size| {
        const state = try std.fmt.allocPrint(a, "{s}/registry-{d}", .{ directory, size });
        defer a.free(state);
        var registry = try p.registry.Registry.init(a, io, state, .{});
        defer registry.deinit();
        // Seed real tables once; every measured mutation persists the complete snapshot.
        for (0..size) |index| {
            const name = try std.fmt.allocPrint(a, "r{d}.local", .{index});
            defer a.free(name);
            const route: p.protocol.Route = .{ .name = name, .host = "127.0.0.1", .port = 3000 };
            try registry.records.set(route);
            try registry.active.set(route);
        }
        const label = try std.fmt.allocPrint(a, "registry-cas-fsync-{d}", .{size});
        defer a.free(label);
        for (0..5) |sample| {
            const start = std.Io.Clock.awake.now(io).toNanoseconds();
            for (0..20) |index| {
                const result = (try registry.mutate(.{ .id = "bench", .operation = "add", .route = .{ .name = "r0.local", .host = "127.0.0.1", .port = @intCast(3000 + index) }, .match = "owner", .expected_owner = .{} })).?;
                result.deinit(a);
            }
            try report(io, &output.interface, label, sample, 20, start);
        }
    }
    const ca_dir = try std.fmt.allocPrint(a, "{s}/pki", .{directory});
    defer a.free(ca_dir);
    var authority = try p.pki.Authority.initWithOptions(a, io, ca_dir, .{ .max_leaf_certificates = 16 });
    defer authority.deinit();
    for (0..5) |sample| {
        var start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..32) |index| {
            const host = try std.fmt.allocPrint(a, "s{d}-h{d}.local", .{ sample, index });
            defer a.free(host);
            const ctx = try authority.serverContext(host);
            SSL_CTX_free(ctx);
        }
        try report(io, &output.interface, "pki-issue-bounded-eviction", sample, 32, start);
        start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..1000) |_| {
            const ctx = try authority.serverContext("cached.local");
            SSL_CTX_free(ctx);
        }
        try report(io, &output.interface, "pki-durable-cache", sample, 1000, start);
        const cached = try authority.serverContext("cached.local");
        defer SSL_CTX_free(cached);
        start = std.Io.Clock.awake.now(io).toNanoseconds();
        for (0..1000) |_| if (authority.contextNeedsRenewal(cached, "cached.local")) return error.InvalidBenchmarkResult;
        try report(io, &output.interface, "pki-context-renewal-check", sample, 1000, start);
    }
}
