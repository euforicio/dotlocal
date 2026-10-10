const std = @import("std");
const routes = @import("routes.zig");
const Allocator = std.mem.Allocator;

pub const Config = struct {
    scheme: []const u8 = "https",
    listen: []const u8 = "127.0.0.1:443",
    tld: []const u8 = routes.default_tld,
    tlds: []const []const u8 = &.{},
    wildcard: bool = false,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    pub fn isDefault(self: Config) bool {
        return std.mem.eql(u8, self.scheme, "https") and std.mem.eql(u8, self.listen, "127.0.0.1:443") and std.ascii.eqlIgnoreCase(self.tld, routes.default_tld) and self.tlds.len <= 1 and !self.wildcard and self.cert == null and self.key == null;
    }
    pub fn validate(self: Config, allocator: Allocator) !void {
        if (!std.mem.eql(u8, self.scheme, "https") and !std.mem.eql(u8, self.scheme, "http")) return error.InvalidScheme;
        if (std.mem.indexOfScalar(u8, self.listen, '%') != null) return error.InvalidListener;
        const address = std.Io.net.IpAddress.parseLiteral(self.listen) catch return error.InvalidListener;
        if (address.getPort() == 0) return error.InvalidListener;
        const loopback = switch (address) {
            .ip4 => |ip| ip.bytes[0] == 127,
            .ip6 => |ip| ip.isLoopBack(),
        };
        if (!loopback) return error.InvalidListener;
        const tlds = try routes.cloneTlds(allocator, self.tld, self.tlds);
        defer {
            for (tlds) |suffix| allocator.free(suffix);
            allocator.free(tlds);
        }
        if ((self.cert == null) != (self.key == null)) return error.InvalidCertificate;
        if (std.mem.eql(u8, self.scheme, "http") and (self.cert != null or self.key != null)) return error.InvalidCertificate;
        if (self.cert) |cert| {
            const key = self.key.?;
            if (!cleanAbsolute(cert) or !cleanAbsolute(key) or std.mem.eql(u8, cert, key)) return error.InvalidCertificate;
        }
    }
    pub fn publicUrl(self: Config, allocator: Allocator, name: []const u8) ![]u8 {
        try self.validate(allocator);
        const host = routes.normalizeAnyAuthority(allocator, name, self.tld, self.tlds) catch try routes.normalizeName(allocator, name, self.tld);
        defer allocator.free(host);
        const address = try std.Io.net.IpAddress.parseLiteral(self.listen);
        const port = address.getPort();
        if ((std.mem.eql(u8, self.scheme, "https") and port == 443) or (std.mem.eql(u8, self.scheme, "http") and port == 80)) return std.fmt.allocPrint(allocator, "{s}://{s}", .{ self.scheme, host });
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ self.scheme, host, port });
    }
};

/// Loads owned strings only after validating the private directory and file.
pub fn load(allocator: Allocator, io: std.Io, state_dir: []const u8) !?std.json.Parsed(Config) {
    if (!std.fs.path.isAbsolute(state_dir)) return error.InvalidStateDirectory;
    const dir = std.Io.Dir.openDirAbsolute(io, state_dir, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer dir.close(io);
    try @import("process.zig").validateOwned(dir.handle, 0o700, true);
    const file = dir.openFile(io, "zig-profile.json", .{ .follow_symlinks = false, .allow_directory = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    try @import("process.zig").validateOwned(file.handle, 0o600, false);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const bytes = try reader.interface.allocRemaining(allocator, .limited(65536));
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Config, allocator, bytes, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    try parsed.value.validate(allocator);
    return parsed;
}

fn cleanAbsolute(path: []const u8) bool {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return false;
    var parts = std.mem.splitScalar(u8, path, '/');
    _ = parts.next();
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

/// Namespace equality includes order: the first suffix determines DOTLOCAL_URL.
pub fn sameTlds(a: Allocator, left: []const u8, left_tlds: []const []const u8, right: []const u8, right_tlds: []const []const u8) bool {
    const l = routes.cloneTlds(a, left, left_tlds) catch return false;
    defer {
        for (l) |suffix| a.free(suffix);
        a.free(l);
    }
    const r = routes.cloneTlds(a, right, right_tlds) catch return false;
    defer {
        for (r) |suffix| a.free(suffix);
        a.free(r);
    }
    if (l.len != r.len) return false;
    for (l, r) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}
