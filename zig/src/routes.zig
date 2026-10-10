const std = @import("std");
const protocol = @import("protocol.zig");
const Allocator = std.mem.Allocator;
pub const default_tld = ".local";

pub fn validLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
    for (label) |c| if (!(c >= 'a' and c <= 'z') and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

const max_name = 253;
const TldBuffer = [max_name + 1]u8;

pub fn normalizeTld(allocator: Allocator, input: []const u8) ![]u8 {
    var buffer: TldBuffer = undefined;
    return allocator.dupe(u8, try tldInto(&buffer, input));
}

/// Writes the canonical ".label" suffix into caller storage, avoiding hot-path allocation.
fn tldInto(buffer: *TldBuffer, input: []const u8) ![]const u8 {
    var label = if (input.len == 0) default_tld else input;
    if (label[label.len - 1] == '.') label = label[0 .. label.len - 1];
    if (std.mem.startsWith(u8, label, ".")) label = label[1..];
    if (label.len == 0 or label.len > max_name) return error.InvalidTld;
    buffer[0] = '.';
    const lower = std.ascii.lowerString(buffer[1..][0..label.len], label);
    var labels = std.mem.splitScalar(u8, lower, '.');
    while (labels.next()) |part| if (!validLabel(part)) return error.InvalidTld;
    for (lower) |c| {
        if (std.ascii.isAlphabetic(c)) break;
    } else return error.InvalidTld;
    return buffer[0 .. lower.len + 1];
}

pub fn normalizeAuthority(allocator: Allocator, input: []const u8, tld: []const u8) ![]u8 {
    var buffer: TldBuffer = undefined;
    const suffix = try tldInto(&buffer, tld);
    if (input.len == 0 or std.mem.indexOfAny(u8, input, " \t\r\n/?#@\\") != null) return error.InvalidHost;
    var host = input;
    if (std.mem.indexOfScalar(u8, input, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, input[colon + 1 ..], ':') != null) return error.InvalidHost;
        const port = input[colon + 1 ..];
        if (port.len == 0) return error.InvalidHost;
        for (port) |c| if (!std.ascii.isDigit(c)) return error.InvalidHost;
        if ((std.fmt.parseInt(u16, port, 10) catch return error.InvalidHost) == 0) return error.InvalidHost;
        host = input[0..colon];
    }
    if (std.mem.endsWith(u8, host, ".")) host = host[0 .. host.len - 1];
    if (host.len > max_name or host.len <= suffix.len) return error.InvalidHost;
    const lower = try std.ascii.allocLowerString(allocator, host);
    errdefer allocator.free(lower);
    if (!std.mem.endsWith(u8, lower, suffix)) return error.InvalidHost;
    var labels = std.mem.splitScalar(u8, lower, '.');
    while (labels.next()) |label| if (!validLabel(label)) return error.InvalidHost;
    return lower;
}

pub fn normalizeName(allocator: Allocator, input: []const u8, tld: []const u8) ![]u8 {
    var buffer: TldBuffer = undefined;
    const suffix = try tldInto(&buffer, tld);
    var text = std.mem.trim(u8, input, " \t\r\n");
    if (std.mem.endsWith(u8, text, ".")) text = text[0 .. text.len - 1];
    const lower = try std.ascii.allocLowerString(allocator, text);
    defer allocator.free(lower);
    if (std.mem.endsWith(u8, lower, suffix)) return normalizeAuthority(allocator, lower, suffix);
    var labels = std.mem.splitScalar(u8, lower, '.');
    while (labels.next()) |part| if (!validLabel(part)) return error.InvalidHost;
    if (lower.len + suffix.len > max_name) return error.InvalidHost;
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ lower, suffix });
}

/// Keep the requested public hostname while checking every configured namespace.
pub fn normalizeAnyAuthority(a: Allocator, input: []const u8, primary: []const u8, suffixes: []const []const u8) ![]u8 {
    if (suffixes.len == 0 or (suffixes.len == 1 and std.mem.eql(u8, primary, suffixes[0]))) return normalizeAuthority(a, input, primary);
    var best: ?[]u8 = null;
    var length: usize = 0;
    defer if (best) |value| a.free(value);
    for (suffixes) |suffix| {
        const candidate = normalizeAuthority(a, input, suffix) catch |err| {
            if (err == error.OutOfMemory) return err;
            continue;
        };
        if (suffix.len > length) {
            if (best) |value| a.free(value);
            best = candidate;
            length = suffix.len;
        } else a.free(candidate);
    }
    if (best) |value| {
        best = null; // Ownership moves to the caller.
        return value;
    }
    return normalizeAuthority(a, input, primary);
}

pub fn cloneTlds(a: Allocator, primary: []const u8, suffixes: []const []const u8) ![][]const u8 {
    if (suffixes.len > 16) return error.TooManyTlds;
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |item| a.free(item);
        out.deinit(a);
    }
    const first = try normalizeTld(a, primary);
    out.append(a, first) catch |err| {
        a.free(first);
        return err;
    };
    for (suffixes) |suffix| {
        const normalized = try normalizeTld(a, suffix);
        var exists = false;
        for (out.items) |item| if (std.mem.eql(u8, normalized, item)) {
            exists = true;
            break;
        };
        if (exists) a.free(normalized) else {
            out.append(a, normalized) catch |err| {
                a.free(normalized);
                return err;
            };
        }
    }
    return out.toOwnedSlice(a);
}

fn sameJoined(left: []const u8, left_suffix: []const u8, right: []const u8, right_suffix: []const u8) bool {
    const length = left.len + left_suffix.len;
    if (length != right.len + right_suffix.len) return false;
    for (0..length) |i| {
        const x = if (i < left.len) left[i] else left_suffix[i - left.len];
        const y = if (i < right.len) right[i] else right_suffix[i - right.len];
        if (x != y) return false;
    }
    return true;
}

pub const AddressClass = struct { loopback: bool, private: bool, link_local: bool };
pub fn classifyAddress(host: []const u8) !AddressClass {
    if (std.mem.indexOfScalar(u8, host, '%') != null) return error.InvalidUpstream;
    const address = std.Io.net.IpAddress.parse(host, 0) catch return error.InvalidUpstream;
    return switch (address) {
        .ip4 => |ip| blk: {
            const b = ip.bytes;
            if (b[0] == 0 or b[0] >= 224) return error.InvalidUpstream;
            break :blk .{ .loopback = b[0] == 127, .private = b[0] == 10 or (b[0] == 172 and b[1] >= 16 and b[1] <= 31) or (b[0] == 192 and b[1] == 168), .link_local = b[0] == 169 and b[1] == 254 };
        },
        .ip6 => |ip| blk: {
            if (ip.isMultiCast() or std.mem.allEqual(u8, &ip.bytes, 0)) return error.InvalidUpstream;
            if (std.Io.net.Ip4Address.fromIp6(ip) != null) return error.InvalidUpstream;
            break :blk .{ .loopback = ip.isLoopBack(), .private = ip.bytes[0] & 0xfe == 0xfc, .link_local = ip.isLinkLocal() };
        },
    };
}

pub fn validateUpstream(scheme: []const u8, host: []const u8, port: u16) !void {
    if ((!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) or port == 0) return error.InvalidUpstream;
    const c = try classifyAddress(host);
    if (!c.loopback and !c.private) return error.InvalidUpstream;
}

/// Table operations are serialized by Registry. Returned snapshots own their strings.
pub const Table = struct {
    allocator: Allocator,
    tld: []u8,
    wildcard: bool,
    tlds: [][]const u8,
    records: std.StringHashMapUnmanaged(protocol.Route) = .empty,
    pub fn init(allocator: Allocator, tld: []const u8, wildcard: bool) !Table {
        return initWithTlds(allocator, tld, &.{}, wildcard);
    }
    pub fn initWithTlds(allocator: Allocator, tld: []const u8, tlds: []const []const u8, wildcard: bool) !Table {
        const primary = try normalizeTld(allocator, tld);
        errdefer allocator.free(primary);
        return .{ .allocator = allocator, .tld = primary, .tlds = try cloneTlds(allocator, primary, tlds), .wildcard = wildcard };
    }
    pub fn deinit(self: *Table) void {
        var it = self.records.valueIterator();
        while (it.next()) |route| route.deinit(self.allocator);
        self.records.deinit(self.allocator);
        self.allocator.free(self.tld);
        for (self.tlds) |suffix| self.allocator.free(suffix);
        self.allocator.free(self.tlds);
    }
    pub fn set(self: *Table, route: protocol.Route) !void {
        try route.validate(self.allocator, self.tld);
        if (self.tlds.len > 1) {
            var existing = self.records.valueIterator();
            while (existing.next()) |other| {
                if (std.mem.eql(u8, route.name, other.name)) continue;
                const left = route.name[0 .. route.name.len - self.tld.len];
                const right = other.name[0 .. other.name.len - self.tld.len];
                for (self.tlds) |x| for (self.tlds) |y| {
                    if (sameJoined(left, x, right, y)) return error.RouteAliasConflict;
                };
            }
        }
        const copy = try route.clone(self.allocator);
        errdefer copy.deinit(self.allocator);
        const entry = try self.records.getOrPut(self.allocator, copy.name);
        if (entry.found_existing) entry.value_ptr.deinit(self.allocator);
        entry.key_ptr.* = copy.name;
        entry.value_ptr.* = copy;
    }
    /// Atomically replaces the table after validating the entire input.
    pub fn replace(self: *Table, entries: []const protocol.Route) !void {
        var next = try Table.initWithTlds(self.allocator, self.tld, self.tlds, self.wildcard);
        errdefer next.deinit();
        for (entries) |entry| {
            if (next.records.contains(entry.name)) return error.DuplicateRoute;
            try next.set(entry);
        }
        const previous = self.*;
        self.* = next;
        var old = previous;
        old.deinit();
    }
    fn canonicalAuthority(self: *const Table, a: Allocator, authority: []const u8) ![]u8 {
        if (self.tlds.len == 1) return normalizeAuthority(a, authority, self.tld);
        const host = try normalizeAnyAuthority(a, authority, self.tld, self.tlds);
        if (self.records.contains(host)) return host;
        defer a.free(host);
        var selected: []const u8 = self.tld;
        for (self.tlds) |suffix| if (std.mem.endsWith(u8, host, suffix) and suffix.len > selected.len) {
            selected = suffix;
        };
        if (!std.mem.endsWith(u8, host, selected)) {
            for (self.tlds) |suffix| if (std.mem.endsWith(u8, host, suffix)) {
                selected = suffix;
                break;
            };
        }
        return std.fmt.allocPrint(a, "{s}{s}", .{ host[0 .. host.len - selected.len], self.tld });
    }
    pub fn lookup(self: *const Table, allocator: Allocator, authority: []const u8) !?protocol.Route {
        return self.findPublicRoute(allocator, authority, false);
    }
    pub fn remove(self: *Table, name: []const u8) bool {
        const normalized = self.canonicalAuthority(self.allocator, name) catch return false;
        defer self.allocator.free(normalized);
        if (self.records.fetchRemove(normalized)) |entry| {
            entry.value.deinit(self.allocator);
            return true;
        }
        return false;
    }
    pub fn resolve(self: *const Table, allocator: Allocator, authority: []const u8) !?protocol.Route {
        return self.findPublicRoute(allocator, authority, self.wildcard);
    }
    fn findPublicRoute(self: *const Table, a: Allocator, authority: []const u8, wildcard: bool) !?protocol.Route {
        if (self.tlds.len == 1) {
            const host = try normalizeAuthority(a, authority, self.tld);
            defer a.free(host);
            return if (self.findCanonical(host, wildcard)) |value| try value.clone(a) else null;
        }
        const host = try normalizeAnyAuthority(a, authority, self.tld, self.tlds);
        defer a.free(host);
        var selected: ?protocol.Route = null;
        for (self.tlds) |suffix| {
            if (!std.mem.endsWith(u8, host, suffix) or host.len <= suffix.len) continue;
            const canonical = try std.fmt.allocPrint(a, "{s}{s}", .{ host[0 .. host.len - suffix.len], self.tld });
            defer a.free(canonical);
            if (self.findCanonical(canonical, wildcard)) |value| {
                if (selected == null or value.name.len > selected.?.name.len) selected = value;
            }
        }
        return if (selected) |value| try value.clone(a) else null;
    }
    fn findCanonical(self: *const Table, host: []const u8, wildcard: bool) ?protocol.Route {
        var candidate = host;
        while (true) {
            if (self.records.get(candidate)) |value| return value;
            if (!wildcard) return null;
            const separator = std.mem.indexOfScalar(u8, candidate, '.') orelse return null;
            candidate = candidate[separator + 1 ..];
            if (std.mem.eql(u8, candidate, self.tld[1..])) return null;
        }
    }
    pub fn list(self: *const Table, allocator: Allocator) ![]protocol.Route {
        const result = try allocator.alloc(protocol.Route, self.records.count());
        var count: usize = 0;
        errdefer {
            for (result[0..count]) |route| route.deinit(allocator);
            allocator.free(result);
        }
        var it = self.records.valueIterator();
        while (it.next()) |route| {
            result[count] = try route.clone(allocator);
            count += 1;
        }
        std.mem.sort(protocol.Route, result, {}, struct {
            fn less(_: void, a: protocol.Route, b: protocol.Route) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.less);
        return result;
    }
};
