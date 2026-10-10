const std = @import("std");
pub const protocol = @import("protocol.zig");
pub const routes = @import("routes.zig");
pub const profile = @import("profile.zig");
const Allocator = std.mem.Allocator;
const max_state_bytes = 4 << 20;
const max_routes = 1024;
const State = struct { version: u32 = 0, routes: []const protocol.Route = &.{} };

pub const Registry = struct {
    allocator: Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    state_lock: std.Io.File,
    mutex: std.Io.Mutex = .init,
    records: routes.Table,
    active: routes.Table,

    pub fn init(allocator: Allocator, io: std.Io, state_dir: []const u8, config: profile.Config) !Registry {
        try config.validate(allocator);
        if (!std.fs.path.isAbsolute(state_dir)) return error.InvalidStateDirectory;
        std.Io.Dir.createDirAbsolute(io, state_dir, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const dir = try std.Io.Dir.openDirAbsolute(io, state_dir, .{ .follow_symlinks = false, .iterate = true });
        errdefer dir.close(io);
        const stat = try dir.stat(io);
        if (stat.kind != .directory or stat.permissions.toMode() & 0o7777 != 0o700) return error.UnsafeStateDirectory;
        try checkOwner(dir.handle);
        const state_lock = dir.createFile(io, "routes.lock", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) }) catch |err| switch (err) {
            error.PathAlreadyExists => try dir.openFile(io, "routes.lock", .{ .mode = .read_write, .follow_symlinks = false, .allow_directory = false }),
            else => return err,
        };
        errdefer state_lock.close(io);
        _ = try checkFile(state_lock, io);
        if (!try state_lock.tryLock(io, .exclusive)) return error.StateInUse;
        var records = try routes.Table.initWithTlds(allocator, config.tld, config.tlds, false);
        errdefer records.deinit();
        var active = try routes.Table.initWithTlds(allocator, config.tld, config.tlds, config.wildcard);
        errdefer active.deinit();
        const file = dir.openFile(io, "routes.json", .{ .follow_symlinks = false, .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => return .{ .allocator = allocator, .io = io, .dir = dir, .state_lock = state_lock, .records = records, .active = active },
            else => return err,
        };
        defer file.close(io);
        const info = try checkFile(file, io);
        if (info.size > max_state_bytes) return error.StateTooLarge;
        const data = try allocator.alloc(u8, @intCast(info.size));
        defer allocator.free(data);
        if (try file.readPositionalAll(io, data, 0) != data.len) return error.InvalidState;
        var extra: [1]u8 = undefined;
        if (try file.readPositionalAll(io, &extra, info.size) != 0) return error.StateTooLarge;
        // Route.jsonParse requires explicit wire fields for every persisted route.
        const parsed = try std.json.parseFromSlice(State, allocator, data, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
        defer parsed.deinit();
        if (parsed.value.version != 1) return error.UnsupportedStateVersion;
        if (parsed.value.routes.len > max_routes) return error.RouteLimit;
        for (parsed.value.routes) |route| {
            if (records.records.contains(route.name)) return error.DuplicateRoute;
            try records.set(route);
            // Dynamic registrations require live identity validation before activation.
            if (std.mem.eql(u8, route.owner.kind, "static")) try active.set(route);
        }
        return .{ .allocator = allocator, .io = io, .dir = dir, .state_lock = state_lock, .records = records, .active = active };
    }

    pub fn deinit(self: *Registry) void {
        self.records.deinit();
        self.active.deinit();
        self.state_lock.close(self.io);
        self.dir.close(self.io);
    }

    /// The caller owns the returned route and releases it with Route.deinit(self.allocator).
    /// Peer/process/container identity must already have been canonicalized by the daemon.
    pub fn mutate(self: *Registry, request: protocol.Request) !?protocol.Route {
        try request.validate(self.allocator);
        const add = std.mem.eql(u8, request.operation, "add");
        if (!add and !std.mem.eql(u8, request.operation, "remove")) return error.UnsupportedOperation;
        const name = if (add) request.route.?.name else request.name;
        if (add) try request.route.?.validate(self.allocator, self.records.tld);
        const normalized = try routes.normalizeAuthority(self.allocator, name, self.records.tld);
        defer self.allocator.free(normalized);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const current = self.records.records.get(name);
        const matches = if (std.mem.eql(u8, request.match, "absent")) current == null else if (std.mem.eql(u8, request.match, "any")) true else current != null and request.expected_owner != null and current.?.owner.eql(request.expected_owner.?);
        if (!matches) return error.RouteConflict;
        if (!add and current == null) return null;
        if (add and current == null and self.records.records.count() >= max_routes) return error.RouteLimit;
        const result = try (if (add) request.route.? else current.?).clone(self.allocator);
        errdefer result.deinit(self.allocator);
        var next = try copyTable(self.allocator, &self.records);
        errdefer next.deinit();
        var next_active = try copyTable(self.allocator, &self.active);
        errdefer next_active.deinit();
        if (add) {
            try next.set(request.route.?);
            try next_active.set(request.route.?);
        } else {
            _ = next.remove(name);
            _ = next_active.remove(name);
        }
        try self.persist(&next);
        self.records.deinit();
        self.active.deinit();
        self.records = next;
        self.active = next_active;
        return result;
    }

    /// Activate a persisted dynamic route only after checking its live owner identity.
    pub fn setActive(self: *Registry, name: []const u8, enabled: bool) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (!enabled) {
            _ = self.active.remove(name);
            return;
        }
        const route = self.records.records.get(name) orelse return error.RouteNotFound;
        try self.active.set(route);
    }
    pub fn setActiveOwned(self: *Registry, name: []const u8, expected: protocol.Owner, enabled: bool) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const route = self.records.records.get(name) orelse return error.RouteConflict;
        if (!route.owner.eql(expected)) return error.RouteConflict;
        if (!enabled) {
            _ = self.active.remove(name);
            return;
        }
        try self.active.set(route);
    }
    pub fn replaceOwned(self: *Registry, route: protocol.Route, expected: protocol.Owner) !void {
        if (try self.mutate(.{ .id = "refresh", .operation = "add", .route = route, .match = "owner", .expected_owner = expected })) |updated| updated.deinit(self.allocator);
    }
    pub fn list(self: *Registry, allocator: Allocator) ![]protocol.Route {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.records.list(allocator);
    }
    pub fn resolve(self: *Registry, allocator: Allocator, authority: []const u8) !?protocol.Route {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.active.resolve(allocator, authority);
    }
    fn persist(self: *Registry, table: *const routes.Table) !void {
        if (self.dir.statFile(self.io, "routes.json", .{ .follow_symlinks = false })) |info| {
            if (info.kind != .file) return error.UnsafeStateFile;
            const file = try self.dir.openFile(self.io, "routes.json", .{ .follow_symlinks = false, .allow_directory = false });
            defer file.close(self.io);
            _ = try checkFile(file, self.io);
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const entries = try table.list(allocator);
        const data = try std.json.Stringify.valueAlloc(allocator, State{ .version = 1, .routes = entries }, .{ .whitespace = .indent_2 });
        if (data.len + 1 > max_state_bytes) return error.StateTooLarge;
        var atomic = try self.dir.createFileAtomic(self.io, "routes.json", .{ .permissions = .fromMode(0o600), .replace = true });
        defer atomic.deinit(self.io);
        try atomic.file.setPermissions(self.io, .fromMode(0o600));
        try atomic.file.writePositionalAll(self.io, data, 0);
        try atomic.file.writePositionalAll(self.io, "\n", data.len);
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
        const directory_file: std.Io.File = .{ .handle = self.dir.handle, .flags = .{ .nonblocking = false } };
        try directory_file.sync(self.io);
    }
};
/// Entries were validated when inserted, so copies skip per-route and alias revalidation.
fn copyTable(allocator: Allocator, original: *const routes.Table) !routes.Table {
    var result = try routes.Table.initWithTlds(allocator, original.tld, original.tlds, original.wildcard);
    errdefer result.deinit();
    try result.records.ensureTotalCapacity(allocator, original.records.count());
    var it = original.records.valueIterator();
    while (it.next()) |route| {
        const copy = try route.clone(allocator);
        result.records.putAssumeCapacityNoClobber(copy.name, copy);
    }
    return result;
}
fn checkOwner(handle: std.posix.fd_t) !void {
    // std.Io.File.Stat currently omits UID; libc is restricted to this metadata boundary.
    const c = @import("native");
    var stat: c.struct_stat = undefined;
    if (c.fstat(handle, &stat) != 0) return error.StatFailed;
    if (stat.st_uid != c.geteuid()) return error.UnsafeOwnership;
}
fn checkFile(file: std.Io.File, io: std.Io) !std.Io.File.Stat {
    const info = try file.stat(io);
    if (info.kind != .file or info.permissions.toMode() & 0o7777 != 0o600 or info.nlink != 1) return error.UnsafeStateFile;
    try checkOwner(file.handle);
    return info;
}
