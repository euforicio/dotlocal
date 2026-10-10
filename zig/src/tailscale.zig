const std = @import("std");
const A = std.mem.Allocator;
const Io = std.Io;
const V = std.json.Value;
pub const Mode = enum { serve, funnel };
pub const Registration = struct { name: []const u8, mode: Mode, port: u16, target: []const u8, host: []const u8 };
pub const Request = struct { name: []const u8, mode: Mode = .serve, target: []const u8, reserved_ports: []const u16 = &.{} };
const Active = struct { port: u16, target: []const u8, funnel: bool };
pub const Snapshot = struct {
    arena: std.heap.ArenaAllocator,
    executable: []const u8,
    version: []const u8,
    dns_name: []const u8,
    used_ports: []const u16,
    funnel_ports: []const u16,
    active: []const Active,
    pub fn deinit(self: *Snapshot) void {
        self.arena.deinit();
    }
};
pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    registration: Registration,
    executable: []const u8,
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
    }
};
fn field(v: V, key: []const u8) !V {
    if (v != .object) return error.InvalidMetadata;
    return v.object.get(key) orelse error.InvalidMetadata;
}
fn text(v: V) ![]const u8 {
    if (v != .string) return error.InvalidMetadata;
    return v.string;
}
fn boolean(v: V) bool {
    return v == .bool and v.bool;
}
fn get(v: V, key: []const u8) ?V {
    return if (v == .object) v.object.get(key) else null;
}
fn run(a: A, io: Io, args: []const []const u8) ![]u8 {
    const result = try std.process.run(a, io, .{ .argv = args, .stdout_limit = .limited(4 << 20), .stderr_limit = .limited(4 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } } });
    a.free(result.stderr);
    errdefer a.free(result.stdout);
    if (result.term != .exited or result.term.exited != 0) return error.TailscaleCommandFailed;
    return result.stdout;
}
fn jsonRun(a: A, io: Io, args: []const []const u8) !V {
    const raw = try run(a, io, args);
    return (try std.json.parseFromSlice(V, a, raw, .{ .allocate = .alloc_always })).value;
}
fn validVersion(raw: []const u8) bool {
    var parts = std.mem.splitScalar(u8, raw, '.');
    const major = std.fmt.parseInt(u16, parts.next() orelse return false, 10) catch return false;
    const minor = std.fmt.parseInt(u16, parts.next() orelse return false, 10) catch return false;
    const patchraw = parts.next() orelse return false;
    const patch = std.fmt.parseInt(u16, patchraw[0..(std.mem.findScalar(u8, patchraw, '-') orelse patchraw.len)], 10) catch return false;
    return major > 1 or (major == 1 and (minor > 98 or (minor == 98 and patch >= 9)));
}
fn capabilityPorts(a: A, caps: V) ![]const u16 {
    var ports: std.ArrayList(u16) = .empty;
    if (caps != .object or caps.object.get("funnel") == null) return ports.toOwnedSlice(a);
    var it = caps.object.iterator();
    while (it.next()) |entry| {
        const prefix = "https://tailscale.com/cap/funnel-ports?";
        if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
        var params = std.mem.splitScalar(u8, entry.key_ptr.*[prefix.len..], '&');
        while (params.next()) |param| {
            if (!std.mem.startsWith(u8, param, "ports=")) continue;
            var tokens = std.mem.splitScalar(u8, param[6..], ',');
            while (tokens.next()) |token| {
                const dash = std.mem.findScalar(u8, token, '-');
                const first = std.fmt.parseInt(u16, token[0 .. dash orelse token.len], 10) catch continue;
                const last = if (dash) |d| std.fmt.parseInt(u16, token[d + 1 ..], 10) catch continue else first;
                for ([_]u16{ 443, 8443, 10000 }) |p| if (first <= p and p <= last and std.mem.findScalar(u16, ports.items, p) == null) try ports.append(a, p);
            }
        }
    }
    return ports.toOwnedSlice(a);
}
pub fn check(a: A, io: Io, executable: []const u8, mode: Mode) !Snapshot {
    return snapshot(a, io, executable, mode, true);
}
fn snapshot(a: A, io: Io, executable: []const u8, mode: Mode, require_capability: bool) !Snapshot {
    if (!std.fs.path.isAbsolute(executable)) return error.AbsoluteExecutableRequired;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const g = arena.allocator();
    const version = try text(try field(try jsonRun(g, io, &.{ executable, "version", "--json" }), "majorMinorPatch"));
    if (!validVersion(version)) return error.TailscaleUpgradeRequired;
    const status = try jsonRun(g, io, &.{ executable, "status", "--json" });
    if (!std.mem.eql(u8, try text(try field(status, "BackendState")), "Running")) return error.TailscaleUnavailable;
    const self = try field(status, "Self");
    if (!boolean(try field(self, "Online"))) return error.TailscaleUnavailable;
    const name = std.mem.trimEnd(u8, try text(try field(self, "DNSName")), ".");
    if (name.len == 0 or std.mem.findScalar(u8, name, ':') != null) return error.InvalidMetadata;
    const caps = try field(self, "CapMap");
    const dns = try jsonRun(g, io, &.{ executable, "dns", "status", "--json" });
    if (require_capability) {
        const tailnet = try field(dns, "CurrentTailnet");
        if (!boolean(try field(dns, "TailscaleDNS")) or !boolean(try field(tailnet, "MagicDNSEnabled")) or !std.mem.eql(u8, std.mem.trimEnd(u8, try text(try field(tailnet, "SelfDNSName")), "."), name) or (try text(try field(tailnet, "MagicDNSSuffix"))).len == 0 or get(caps, "https") == null) return error.HTTPSUnavailable;
        const domains = try field(dns, "CertDomains");
        if (domains != .array) return error.InvalidMetadata;
        var present = false;
        for (domains.array.items) |d| if (std.mem.eql(u8, std.mem.trimEnd(u8, try text(d), "."), name)) {
            present = true;
            break;
        };
        if (!present) return error.HTTPSUnavailable;
    }
    const permitted = try capabilityPorts(g, caps);
    if (require_capability and mode == .funnel and permitted.len == 0) return error.FunnelUnavailable;
    const serve = try jsonRun(g, io, &.{ executable, @tagName(mode), "status", "--json" });
    var used: std.ArrayList(u16) = .empty;
    var active: std.ArrayList(Active) = .empty;
    const tcp = get(serve, "TCP") orelse .null;
    const web = get(serve, "Web") orelse .null;
    const funnel = get(serve, "AllowFunnel") orelse .null;
    if (tcp == .object) {
        var it = tcp.object.iterator();
        while (it.next()) |entry| {
            const port = std.fmt.parseInt(u16, entry.key_ptr.*, 10) catch return error.InvalidMetadata;
            if (port == 0) return error.InvalidMetadata;
            try used.append(g, port);
            if (!boolean(get(entry.value_ptr.*, "HTTPS") orelse .null)) continue;
            const key = try std.fmt.allocPrint(g, "{s}:{d}", .{ name, port });
            const handlers = get(get(web, key) orelse .null, "Handlers") orelse continue;
            if (handlers != .object or handlers.object.count() != 1) continue;
            const root = get(handlers, "/") orelse continue;
            const target = text(get(root, "Proxy") orelse .null) catch continue;
            try active.append(g, .{ .port = port, .target = target, .funnel = boolean(get(funnel, key) orelse .null) });
        }
    }
    if (web == .object) {
        var it = web.object.iterator();
        while (it.next()) |entry| {
            const colon = std.mem.lastIndexOfScalar(u8, entry.key_ptr.*, ':') orelse return error.InvalidMetadata;
            const port = std.fmt.parseInt(u16, entry.key_ptr.*[colon + 1 ..], 10) catch return error.InvalidMetadata;
            if (port == 0) return error.InvalidMetadata;
            if (std.mem.findScalar(u16, used.items, port) == null) try used.append(g, port);
        }
    }
    // Finish every arena allocation before copying the arena state into the result.
    const owned_executable = try g.dupe(u8, executable);
    const used_ports = try used.toOwnedSlice(g);
    const active_ports = try active.toOwnedSlice(g);
    return .{ .arena = arena, .executable = owned_executable, .version = version, .dns_name = name, .used_ports = used_ports, .funnel_ports = permitted, .active = active_ports };
}
pub fn allocate(mode: Mode, occupied: []const u16) !u16 {
    if (std.mem.findScalar(u16, occupied, 443) == null) return 443;
    if (mode == .funnel) {
        for ([_]u16{ 8443, 10000 }) |port| if (std.mem.findScalar(u16, occupied, port) == null) return port;
    } else {
        var p: u32 = 8443;
        while (p <= 65535) : (p += 1) if (std.mem.findScalar(u16, occupied, @as(u16, @intCast(p))) == null) return @intCast(p);
    }
    return error.NoPort;
}
fn validateRequest(name: []const u8, target: []const u8) !void {
    if (name.len == 0 or name.len > 253) return error.InvalidName;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return error.InvalidName;
        for (label) |ch| if (!(ch >= 'a' and ch <= 'z') and !std.ascii.isDigit(ch) and ch != '-') return error.InvalidName;
    }
    const prefix = "http://127.0.0.1:";
    if (!std.mem.startsWith(u8, target, prefix)) return error.InvalidTarget;
    const digits = target[prefix.len..];
    // parseInt accepts '+' and '_'; the CLI argument and journal match must be canonical.
    for (digits) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidTarget;
    const port = std.fmt.parseInt(u16, digits, 10) catch return error.InvalidTarget;
    if (port == 0 or digits[0] == '0') return error.InvalidTarget;
}
pub fn plan(a: A, s: Snapshot, req: Request) !Plan {
    try validateRequest(req.name, req.target);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const g = arena.allocator();
    const occupied = try std.mem.concat(g, u16, &.{ s.used_ports, req.reserved_ports });
    const port = if (req.mode == .serve) try allocate(req.mode, occupied) else blk: {
        for ([_]u16{ 443, 8443, 10000 }) |p| if (std.mem.findScalar(u16, occupied, p) == null and std.mem.findScalar(u16, s.funnel_ports, p) != null) break :blk p;
        return error.NoPort;
    };
    const registration: Registration = .{ .name = try g.dupe(u8, req.name), .mode = req.mode, .port = port, .target = try g.dupe(u8, req.target), .host = try g.dupe(u8, s.dns_name) };
    const executable = try g.dupe(u8, s.executable);
    return .{ .arena = arena, .executable = executable, .registration = registration };
}
fn matches(s: Snapshot, r: Registration) bool {
    for (s.active) |v| if (v.port == r.port and std.mem.eql(u8, v.target, r.target) and v.funnel == (r.mode == .funnel)) return true;
    return false;
}
fn validatePlan(executable: []const u8, p: Plan) !void {
    try validateRequest(p.registration.name, p.registration.target);
    if (!std.mem.eql(u8, executable, p.executable) or p.registration.port == 0 or (p.registration.mode == .funnel and std.mem.findScalar(u16, &.{ 443, 8443, 10000 }, p.registration.port) == null)) return error.InvalidPlan;
}
pub fn apply(a: A, io: Io, executable: []const u8, p: Plan) !void {
    try validatePlan(executable, p);
    var before = try check(a, io, executable, p.registration.mode);
    defer before.deinit();
    if (!std.mem.eql(u8, before.dns_name, p.registration.host) or std.mem.findScalar(u16, before.used_ports, p.registration.port) != null) return error.RegistrationConflict;
    if (p.registration.mode == .funnel and std.mem.findScalar(u16, before.funnel_ports, p.registration.port) == null) return error.FunnelUnavailable;
    const flag = try std.fmt.allocPrint(a, "--https={d}", .{p.registration.port});
    defer a.free(flag);
    a.free(try run(a, io, &.{ executable, @tagName(p.registration.mode), "--bg", "--yes", flag, "--set-path=/", p.registration.target }));
    var after = try snapshot(a, io, executable, p.registration.mode, false);
    defer after.deinit();
    if (!matches(after, p.registration)) return error.RegistrationVerificationFailed;
}
pub fn clean(a: A, io: Io, executable: []const u8, p: Plan) !void {
    try validatePlan(executable, p);
    var before = try snapshot(a, io, executable, p.registration.mode, false);
    defer before.deinit();
    if (!std.mem.eql(u8, before.dns_name, p.registration.host)) return error.RegistrationConflict;
    // A journal recorded before a failed apply has no live registration to remove.
    if (std.mem.findScalar(u16, before.used_ports, p.registration.port) == null) return;
    if (!matches(before, p.registration)) return error.RegistrationConflict;
    const flag = try std.fmt.allocPrint(a, "--https={d}", .{p.registration.port});
    defer a.free(flag);
    a.free(try run(a, io, &.{ executable, @tagName(p.registration.mode), "--yes", flag, "--set-path=/", "off" }));
    var after = try snapshot(a, io, executable, p.registration.mode, false);
    defer after.deinit();
    if (std.mem.findScalar(u16, after.used_ports, p.registration.port) != null) return error.CleanupVerificationFailed;
}
