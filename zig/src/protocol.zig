const std = @import("std");
const routes = @import("routes.zig");
const Allocator = std.mem.Allocator;
pub const version = 2;

pub const Owner = struct {
    kind: []const u8 = "static",
    pid: i32 = 0,
    process_start: i64 = 0,
    inspector_uid: u32 = 0,
    container: []const u8 = "",
    network: []const u8 = "",
    refresh: []const u8 = "never",
    pub fn eql(a: Owner, b: Owner) bool {
        return std.mem.eql(u8, a.kind, b.kind) and a.pid == b.pid and a.process_start == b.process_start and a.inspector_uid == b.inspector_uid and std.mem.eql(u8, a.container, b.container) and std.mem.eql(u8, a.network, b.network) and std.mem.eql(u8, a.refresh, b.refresh);
    }
    pub fn validate(self: Owner, expected: bool) !void {
        if (std.mem.eql(u8, self.kind, "static")) {
            if (self.pid != 0 or self.process_start != 0 or self.inspector_uid != 0 or self.container.len != 0 or self.network.len != 0 or !std.mem.eql(u8, self.refresh, "never")) return error.InvalidOwner;
        } else if (std.mem.eql(u8, self.kind, "process")) {
            if (self.pid <= 0 or self.process_start < 0 or (expected and self.process_start == 0) or self.inspector_uid != 0 or self.container.len != 0 or self.network.len != 0 or !std.mem.eql(u8, self.refresh, "never")) return error.InvalidOwner;
        } else if (std.mem.eql(u8, self.kind, "container")) {
            if (self.pid != 0 or self.process_start != 0 or (expected and self.inspector_uid == 0) or !validToken(self.container, 128, true) or !validToken(self.network, 128, true) or !std.mem.eql(u8, self.refresh, "container-address")) return error.InvalidOwner;
        } else return error.InvalidOwner;
    }
    pub fn validateExpected(self: Owner) !void {
        try self.validate(true);
    }
    /// Wire owners must name kind and refresh explicitly.
    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !Owner {
        const wire = try std.json.innerParse(struct {
            kind: []const u8,
            pid: i32 = 0,
            process_start: i64 = 0,
            inspector_uid: u32 = 0,
            container: []const u8 = "",
            network: []const u8 = "",
            refresh: []const u8,
        }, allocator, source, options);
        return .{ .kind = wire.kind, .pid = wire.pid, .process_start = wire.process_start, .inspector_uid = wire.inspector_uid, .container = wire.container, .network = wire.network, .refresh = wire.refresh };
    }
};

pub const Route = struct {
    name: []const u8,
    scheme: []const u8 = "http",
    host: []const u8,
    port: u16,
    owner: Owner = .{},
    pub fn validate(self: Route, allocator: Allocator, tld: []const u8) !void {
        const suffix = if (tld.len != 0) tld else blk: {
            const i = std.mem.lastIndexOfScalar(u8, self.name, '.') orelse return error.InvalidHost;
            break :blk self.name[i..];
        };
        const normalized = try routes.normalizeAuthority(allocator, self.name, suffix);
        defer allocator.free(normalized);
        if (!std.mem.eql(u8, normalized, self.name)) return error.NonCanonicalName;
        try routes.validateUpstream(self.scheme, self.host, self.port);
        const address = try std.Io.net.IpAddress.parse(self.host, 0);
        const canonical = switch (address) {
            .ip4 => |ip| try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3] }),
            .ip6 => |ip| try std.fmt.allocPrint(allocator, "{f}", .{ip}),
        };
        defer allocator.free(canonical);
        // Zig's IPv6 formatter includes brackets and port; canonical host format is checked separately below.
        if (address == .ip4 and !std.mem.eql(u8, canonical, self.host)) return error.NonCanonicalAddress;
        if (address == .ip6) {
            const end = std.mem.indexOfScalar(u8, canonical, ']') orelse return error.NonCanonicalAddress;
            if (!std.mem.eql(u8, canonical[1..end], self.host)) return error.NonCanonicalAddress;
        }
        try self.owner.validate(false);
        const class = try routes.classifyAddress(self.host);
        if (std.mem.eql(u8, self.owner.kind, "process") and !class.loopback) return error.InvalidOwnerAddress;
        if (std.mem.eql(u8, self.owner.kind, "container") and (class.loopback or class.link_local or !class.private)) return error.InvalidOwnerAddress;
    }
    /// Wire routes must carry every field explicitly; struct defaults are library conveniences.
    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !Route {
        const wire = try std.json.innerParse(struct { name: []const u8, scheme: []const u8, host: []const u8, port: u16, owner: Owner }, allocator, source, options);
        return .{ .name = wire.name, .scheme = wire.scheme, .host = wire.host, .port = wire.port, .owner = wire.owner };
    }
    /// Copies every string into one allocation; release it with deinit.
    pub fn clone(self: Route, allocator: Allocator) !Route {
        const parts = [_][]const u8{ self.name, self.scheme, self.host, self.owner.kind, self.owner.container, self.owner.network, self.owner.refresh };
        var size: usize = 0;
        for (parts) |part| size += part.len;
        const buffer = try allocator.alloc(u8, size);
        var copies: [parts.len][]const u8 = undefined;
        var offset: usize = 0;
        for (parts, &copies) |part, *copy| {
            @memcpy(buffer[offset..][0..part.len], part);
            copy.* = buffer[offset..][0..part.len];
            offset += part.len;
        }
        var result = self;
        result.name = copies[0];
        result.scheme = copies[1];
        result.host = copies[2];
        result.owner.kind = copies[3];
        result.owner.container = copies[4];
        result.owner.network = copies[5];
        result.owner.refresh = copies[6];
        return result;
    }
    /// Releases a route returned by clone. Its strings share one contiguous allocation.
    pub fn deinit(self: Route, allocator: Allocator) void {
        const parts = [_][]const u8{ self.name, self.scheme, self.host, self.owner.kind, self.owner.container, self.owner.network, self.owner.refresh };
        var size: usize = 0;
        for (parts) |part| {
            std.debug.assert(part.ptr == self.name.ptr + size);
            size += part.len;
        }
        allocator.free(self.name.ptr[0..size]);
    }
};

pub const Request = struct {
    version: u32 = 2,
    id: []const u8 = "",
    operation: []const u8,
    route: ?Route = null,
    name: []const u8 = "",
    match: []const u8 = "",
    expected_owner: ?Owner = null,
    /// Wire requests must carry version, id and operation explicitly.
    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !Request {
        const wire = try std.json.innerParse(struct {
            version: u32,
            id: []const u8,
            operation: []const u8,
            route: ?Route = null,
            name: []const u8 = "",
            match: []const u8 = "",
            expected_owner: ?Owner = null,
        }, allocator, source, options);
        return .{ .version = wire.version, .id = wire.id, .operation = wire.operation, .route = wire.route, .name = wire.name, .match = wire.match, .expected_owner = wire.expected_owner };
    }
    pub fn validate(self: Request, allocator: Allocator) !void {
        if (self.version != version) return error.UnsupportedVersion;
        if (!validToken(self.id, 64, false)) return error.InvalidRequestId;
        const add = std.mem.eql(u8, self.operation, "add");
        const remove = std.mem.eql(u8, self.operation, "remove");
        if (add or remove) {
            if (add) {
                if (self.route == null or self.name.len != 0) return error.InvalidRequest;
                try self.route.?.validate(allocator, "");
            } else {
                if (self.route != null) return error.InvalidRequest;
                const name = try routes.normalizeAuthority(allocator, self.name, suffixFor(self.name));
                defer allocator.free(name);
                if (!std.mem.eql(u8, name, self.name)) return error.NonCanonicalName;
            }
            if (std.mem.eql(u8, self.match, "absent")) {
                if (!add or self.expected_owner != null) return error.InvalidMatch;
            } else if (std.mem.eql(u8, self.match, "any")) {
                if (self.expected_owner != null) return error.InvalidMatch;
            } else if (std.mem.eql(u8, self.match, "owner")) {
                try (self.expected_owner orelse return error.InvalidMatch).validateExpected();
            } else return error.InvalidMatch;
        } else {
            const supported = std.mem.eql(u8, self.operation, "install") or std.mem.eql(u8, self.operation, "list") or std.mem.eql(u8, self.operation, "status") or std.mem.eql(u8, self.operation, "doctor") or std.mem.eql(u8, self.operation, "refresh") or std.mem.eql(u8, self.operation, "uninstall");
            if (!supported) return error.UnsupportedOperation;
            if (self.route != null or self.name.len != 0 or self.match.len != 0 or self.expected_owner != null) return error.InvalidRequest;
        }
    }
};
fn suffixFor(name: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    return name[i..];
}
fn validToken(text: []const u8, max: usize, dot: bool) bool {
    if (text.len == 0 or text.len > max) return false;
    for (text, 0..) |c, i| if (!std.ascii.isAlphanumeric(c) and !(c == '-' or c == '_') and !(dot and i > 0 and c == '.')) return false;
    if (dot and !std.ascii.isAlphanumeric(text[0])) return false;
    return true;
}

pub const Problem = struct { code: []const u8, message: []const u8 };
pub const Diagnostic = struct { name: []const u8, level: []const u8, message: []const u8 };
pub const Status = struct {
    running: bool = false,
    version: []const u8 = "",
    socket_path: []const u8 = "",
    scheme: []const u8 = "",
    listen_address: []const u8 = "",
    tld: []const u8 = "",
    tlds: ?[]const []const u8 = null,
    wildcard_fallback: bool = false,
    certificate_mode: []const u8 = "",
    certificate_file: []const u8 = "",
    key_file: []const u8 = "",
};
pub const Response = struct {
    version: u32 = 0,
    id: []const u8,
    ok: bool,
    @"error": ?Problem = null,
    routes: ?[]const Route = null,
    status: ?Status = null,
    diagnostics: ?[]const Diagnostic = null,
    route: ?Route = null,
    /// Wire responses must carry version, id and ok explicitly.
    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !Response {
        const wire = try std.json.innerParse(struct {
            version: u32,
            id: []const u8,
            ok: bool,
            @"error": ?Problem = null,
            routes: ?[]const Route = null,
            status: ?Status = null,
            diagnostics: ?[]const Diagnostic = null,
            route: ?Route = null,
        }, allocator, source, options);
        return .{ .version = wire.version, .id = wire.id, .ok = wire.ok, .@"error" = wire.@"error", .routes = wire.routes, .status = wire.status, .diagnostics = wire.diagnostics, .route = wire.route };
    }
};

/// Decodes and validates one request. Wire strictness lives in the jsonParse hooks.
pub fn parseRequest(allocator: Allocator, data: []const u8) !std.json.Parsed(Request) {
    const parsed = try std.json.parseFromSlice(Request, allocator, data, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    try parsed.value.validate(allocator);
    return parsed;
}
