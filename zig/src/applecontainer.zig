const std = @import("std");
const A = std.mem.Allocator;
const Io = std.Io;
pub const Endpoint = struct {
    container: []u8,
    network: []u8,
    scheme: []u8,
    host: []u8,
    port: u16,
    pub fn deinit(self: Endpoint, a: A) void {
        a.free(self.container);
        a.free(self.network);
        a.free(self.scheme);
        a.free(self.host);
    }
};
pub fn validateID(id: []const u8) !void {
    if (id.len == 0 or id.len > 128) return error.InvalidContainerID;
    for (id, 0..) |ch, i| if (!std.ascii.isAlphanumeric(ch) and !(i > 0 and (ch == '-' or ch == '_' or ch == '.'))) return error.InvalidContainerID;
}
pub fn privateAddress(raw: []const u8) bool {
    const ip = Io.net.IpAddress.parse(raw, 0) catch return false;
    return switch (ip) {
        .ip4 => |v| v.bytes[0] == 10 or (v.bytes[0] == 172 and v.bytes[1] >= 16 and v.bytes[1] <= 31) or (v.bytes[0] == 192 and v.bytes[1] == 168),
        .ip6 => |v| (v.bytes[0] & 0xfe) == 0xfc,
    };
}
const Port = struct { containerPort: i64, count: i64, proto: []const u8 };
const Network = struct { network: []const u8, ipv4Address: []const u8 = "", ipv6Address: []const u8 = "" };
const Record = struct { id: []const u8, configuration: struct { id: []const u8, publishedPorts: []Port = &.{} }, status: struct { state: []const u8, networks: []Network = &.{} } };
pub fn resolve(a: A, io: Io, executable: []const u8, name: []const u8, requested_port: u16, scheme: []const u8) !Endpoint {
    try validateID(name);
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return error.UnsupportedProtocol;
    // Root must not inspect its catalog on behalf of an untrusted route owner.
    if (std.c.geteuid() == 0) return error.UnprivilegedLoginRequired;
    const result = try std.process.run(a, io, .{ .argv = &.{ executable, "inspect", name }, .stdout_limit = .limited(8 << 20), .stderr_limit = .limited(64 << 10), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.InspectionFailed;
    return parse(a, result.stdout, name, requested_port, scheme);
}

pub fn parse(a: A, data: []const u8, name: []const u8, requested_port: u16, scheme: []const u8) !Endpoint {
    try validateID(name);
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return error.UnsupportedProtocol;
    if (data.len > 8 << 20) return error.InspectionOutputTooLarge;
    const parsed = try std.json.parseFromSlice([]Record, a, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value.len != 1) return error.UnexpectedContainer;
    const r = parsed.value[0];
    if (!std.mem.eql(u8, r.id, name) or !std.mem.eql(u8, r.configuration.id, name)) return error.UnexpectedContainer;
    if (!std.mem.eql(u8, r.status.state, "running")) return error.ContainerNotRunning;
    var chosen: u16 = requested_port;
    var distinct: ?u16 = null;
    var unsupported = false;
    for (r.configuration.publishedPorts) |p| {
        if (p.containerPort < 1 or p.containerPort > 65535 or p.count < 1 or p.count > 65536 - p.containerPort) return error.InvalidMetadata;
        if (!std.ascii.eqlIgnoreCase(p.proto, "tcp")) {
            unsupported = true;
            if (requested_port >= p.containerPort and requested_port < p.containerPort + p.count) return error.UnsupportedProtocol;
            continue;
        }
        if (requested_port == 0) {
            if (p.count != 1) return error.AmbiguousPort;
            const port: u16 = @intCast(p.containerPort);
            if (distinct != null and distinct.? != port) return error.AmbiguousPort;
            distinct = port;
        }
    }
    if (chosen == 0) chosen = distinct orelse return if (unsupported) error.UnsupportedProtocol else error.MissingPort;
    if (r.status.networks.len == 0 or r.status.networks[0].network.len == 0) return error.MissingAddress;
    const network = r.status.networks[0];
    var host: ?[]const u8 = null;
    for ([_][]const u8{ network.ipv4Address, network.ipv6Address }) |prefix| {
        const slash = std.mem.findScalar(u8, prefix, '/') orelse continue;
        const bits = std.fmt.parseInt(u8, prefix[slash + 1 ..], 10) catch continue;
        const addr = prefix[0..slash];
        const ip = Io.net.IpAddress.parse(addr, 0) catch continue;
        if (bits > @as(u8, if (ip == .ip4) 32 else 128)) continue;
        if (privateAddress(addr)) {
            host = addr;
            break;
        }
    }
    const address = host orelse return error.MissingAddress;
    const container = try a.dupe(u8, name);
    errdefer a.free(container);
    const net = try a.dupe(u8, network.network);
    errdefer a.free(net);
    const s = try a.dupe(u8, scheme);
    errdefer a.free(s);
    return .{ .container = container, .network = net, .scheme = s, .host = try a.dupe(u8, address), .port = chosen };
}
