const std = @import("std");
const lan = @import("lan.zig");
const hosts = @import("hosts.zig");
const process = @import("process.zig");
const A = std.mem.Allocator;
pub const Config = struct { host: []const u8, address: []const u8, port: u16, scheme: []const u8 = "https" };
pub const Preflight = struct {
    argv: [][]const u8,
    pub fn deinit(self: Preflight, a: A) void {
        for (self.argv) |v| a.free(v);
        a.free(self.argv);
    }
};
pub fn check(a: A, io: std.Io, config: Config) !Preflight {
    try hosts.validateName(config.host, ".local");
    if (config.port == 0 or (!std.mem.eql(u8, config.scheme, "http") and !std.mem.eql(u8, config.scheme, "https"))) return error.InvalidAdvertisement;
    const address = try lan.select(a, io, config.address);
    defer address.deinit(a);
    var argv: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (argv.items) |v| a.free(v);
        argv.deinit(a);
    }
    const idx = try std.fmt.allocPrint(a, "{d}", .{address.index});
    defer a.free(idx);
    const port = try std.fmt.allocPrint(a, "{d}", .{config.port});
    defer a.free(port);
    const typ = try std.fmt.allocPrint(a, "_{s}._tcp", .{config.scheme});
    defer a.free(typ);
    const hostname = try std.fmt.allocPrint(a, "{s}.", .{config.host});
    defer a.free(hostname);
    for ([_][]const u8{ "/usr/bin/dns-sd", "-i", idx, "-P", config.host[0 .. config.host.len - 6], typ, "local.", port, hostname, config.address, "path=/" }) |arg| try argv.append(a, try a.dupe(u8, arg));
    return .{ .argv = try argv.toOwnedSlice(a) };
}
pub const Publisher = struct {
    child: std.process.Child,
    closed: bool = false,
    stdout_drain: ?std.Io.Future(void) = null,
    stderr_drain: ?std.Io.Future(void) = null,
    pub fn close(self: *Publisher, io: std.Io) void {
        if (!self.closed) {
            self.child.kill(io);
            if (self.stdout_drain) |*task| task.await(io);
            if (self.stderr_drain) |*task| task.await(io);
            self.closed = true;
        }
    }
};
/// Owns exactly the direct child. Readiness requires both DNS record and service acknowledgements.
pub fn start(a: A, io: std.Io, config: Config) !Publisher {
    const preflight = try check(a, io, config);
    defer preflight.deinit(a);
    var child = try std.process.spawn(io, .{ .argv = preflight.argv, .stdin = .ignore, .stdout = .pipe, .stderr = .pipe });
    errdefer child.kill(io);
    var buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var reader: std.Io.File.MultiReader = undefined;
    reader.init(a, io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer reader.deinit();
    const deadline = std.Io.Timeout{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } };
    const timeout = deadline.toDeadline(io);
    while (true) {
        try reader.fill(256, timeout);
        const output = reader.reader(0).buffered();
        const errors = reader.reader(1).buffered();
        if (output.len + errors.len > 64 << 10) return error.AdvertisementOutputLimit;
        if (std.mem.find(u8, output, "Name Conflict") != null or std.mem.find(u8, errors, "Name Conflict") != null) return error.NameConflict;
        if (std.mem.find(u8, output, "Got a reply for record") != null and std.mem.find(u8, output, "Got a reply for service") != null and std.mem.find(u8, output, "Name now registered and active") != null) break;
    }
    // Independent read descriptors survive child.kill closing its owned pipes.
    // Drain after readiness so later network notifications cannot fill the pipes.
    var stdout_drain = try process.drainPipe(io, child.stdout.?);
    errdefer {
        child.kill(io);
        stdout_drain.await(io);
    }
    const stderr_drain = try process.drainPipe(io, child.stderr.?);
    return .{ .child = child, .stdout_drain = stdout_drain, .stderr_drain = stderr_drain };
}
