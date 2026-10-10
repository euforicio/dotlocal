//! Per-run explicit exposure and identity-bound crash reconciliation.
const std = @import("std");
const runner = @import("runner.zig");
const process = @import("process.zig");
const tailscale = @import("tailscale.zig");
const lan = @import("lan.zig");
const ngrok = @import("ngrok.zig");
const A = std.mem.Allocator;
const Tail = struct { executable: []const u8, registration: tailscale.Registration };
const Record = struct { version: u32 = 1, runner: runner.Record, tail: ?Tail = null, advertisement: ?process.Identity = null, ngrok: ?ngrok.Registration = null };
const Pending = struct { version: u32 = 1, supervisor: process.Identity, name: []const u8, tail: ?Tail = null, advertisement: ?process.Identity = null, ngrok: ?ngrok.Registration = null };
pub const Session = struct {
    allocator: A,
    io: std.Io,
    state_dir: []const u8,
    tld: []const u8 = @import("routes.zig").default_tld,
    use_lan: bool = false,
    use_ngrok: bool = false,
    ngrok_cli: []const u8 = "/opt/homebrew/bin/ngrok",
    https: bool = false,
    ip: ?[]const u8 = null,
    tail_mode: ?tailscale.Mode = null,
    tail_cli: []const u8 = "/opt/homebrew/bin/tailscale",
    local: ?*lan.Session = null,
    tunnel: ?*ngrok.Tunnel = null,
    tail: ?tailscale.Plan = null,
    stop: std.atomic.Value(bool) = .init(false),
    tasks: std.Io.Group = .init,
    record: ?Record = null,
    pending: ?Pending = null,
    journal_arena: ?std.heap.ArenaAllocator = null,

    /// Runner preparation happens before direct execution so the child receives sharing URLs.
    pub fn prepare(endpoint: runner.Endpoint, env: *std.process.Environ.Map, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (!self.use_lan and !self.use_ngrok and self.tail_mode == null) return;
        if (!endpoint.proxy) return error.ExposureRequiresProxy;
        if (self.pending != null or self.record != null) return error.SharingAlreadyPrepared;
        self.stop.store(false, .release);
        self.journal_arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer self.cleanup();
        const owned = self.journal_arena.?.allocator();
        self.pending = .{ .supervisor = try process.current(), .name = try owned.dupe(u8, endpoint.name) };
        try self.persistPending();
        if (!std.mem.endsWith(u8, endpoint.name, self.tld) or endpoint.name.len <= self.tld.len) return error.InvalidSharingName;
        const short = endpoint.name[0 .. endpoint.name.len - self.tld.len];
        if (self.tail_mode) |mode| {
            var snapshot = try tailscale.check(self.allocator, self.io, self.tail_cli, mode);
            defer snapshot.deinit();
            const target = try std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}", .{endpoint.port});
            defer self.allocator.free(target);
            self.tail = try tailscale.plan(self.allocator, snapshot, .{ .name = short, .mode = mode, .target = target });
            self.pending.?.tail = .{ .executable = self.tail_cli, .registration = self.tail.?.registration };
            try self.persistPending();
            try tailscale.apply(self.allocator, self.io, self.tail_cli, self.tail.?);
            const registration = self.tail.?.registration;
            const url = try std.fmt.allocPrint(owned, "https://{s}:{d}", .{ registration.host, registration.port });
            try env.put("DOTLOCAL_TAILSCALE_URL", url);
            std.log.info("shared {s}", .{url});
        }
        if (self.use_lan) {
            self.local = try lan.Session.init(self.allocator, self.io, self.state_dir, endpoint.host, endpoint.port, short, self.ip, self.https);
            const local = self.local.?;
            local.on_changed = lanChanged;
            local.change_context = self;
            if (local.publisher) |publisher| self.pending.?.advertisement = try process.inspect(publisher.child.id.?);
            try self.persistPending();
            try env.put("DOTLOCAL_LAN", "1");
            try env.put("DOTLOCAL_LAN_URL", local.url);
            try env.put("DOTLOCAL_URL", local.url);
            std.log.info("LAN {s}", .{local.url});
            if (local.ca_path) |path| std.log.info("client CA trust file: {s}", .{path});
        }
        if (self.use_ngrok) {
            self.tunnel = try ngrok.start(self.allocator, self.io, .{ .executable = self.ngrok_cli, .state_dir = self.state_dir, .port = endpoint.port, .host_header = endpoint.name, .environ_map = env, .on_spawn = ngrokSpawned, .context = self });
            self.pending.?.ngrok = self.tunnel.?.registration;
            try self.persistPending();
            try env.put("DOTLOCAL_NGROK_URL", self.tunnel.?.registration.url);
            std.log.info("ngrok {s}", .{self.tunnel.?.registration.url});
        }
    }
    fn ngrokSpawned(registration: ngrok.Registration, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        var copy = registration;
        copy.policy = try self.journal_arena.?.allocator().dupe(u8, registration.policy);
        self.pending.?.ngrok = copy;
        try self.persistPending();
    }
    pub fn started(child: *runner.Process, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        if (self.pending) |pending| {
            self.record = .{ .runner = child.record, .tail = pending.tail, .advertisement = pending.advertisement, .ngrok = pending.ngrok };
            try self.persist(); // Commit runner ownership before removing the preparation journal.
            try removePending(self.allocator, self.io, self.state_dir, pending);
            self.pending = null;
        } else if (self.use_lan or self.use_ngrok or self.tail_mode != null) return error.SharingNotPrepared;
        if (self.tunnel) |tunnel| {
            const actual = try process.inspect(tunnel.registration.identity.pid);
            const expected = tunnel.registration.identity;
            if (actual.uid != expected.uid or actual.start != expected.start or actual.pgid != expected.pgid) return error.NgrokIdentityConflict;
            try self.tasks.concurrent(self.io, watchTunnel, .{self});
        }
        if (self.local != null) try self.tasks.concurrent(self.io, serve, .{self});
        std.log.info("{s}", .{child.record.endpoint.url});
    }
    fn lanChanged(local: *lan.Session, context: ?*anyopaque) !void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        const identity = if (local.publisher) |publisher| try process.inspect(publisher.child.id.?) else null;
        if (self.pending != null) {
            self.pending.?.advertisement = identity;
            try self.persistPending();
        } else if (self.record != null) {
            self.record.?.advertisement = identity;
            try self.persist();
        }
        if (local.publisher != null) std.log.info("LAN {s}", .{local.url});
    }
    fn serve(self: *Session) void {
        self.local.?.run(&self.stop) catch |err| std.log.err("LAN listener: {s}", .{@errorName(err)});
    }
    fn watchTunnel(self: *Session) void {
        const expected = self.tunnel.?.registration.identity;
        while (!self.stop.load(.acquire)) {
            const actual = process.inspect(expected.pid) catch |err| {
                if (!self.stop.load(.acquire)) std.log.err("ngrok tunnel ended: {s}", .{@errorName(err)});
                return;
            };
            if (actual.uid != expected.uid or actual.start != expected.start or actual.pgid != expected.pgid) {
                std.log.err("ngrok tunnel identity changed", .{});
                return;
            }
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch return;
        }
    }
    pub fn cancel(context: ?*anyopaque) void {
        const self: *Session = @ptrCast(@alignCast(context.?));
        self.cleanup();
    }
    pub fn exited(_: *runner.Process, context: ?*anyopaque) void {
        cancel(context);
    }
    fn cleanup(self: *Session) void {
        self.stop.store(true, .release);
        self.tasks.await(self.io) catch {};
        if (self.local) |local| {
            local.deinit();
            self.local = null;
        }
        var cleaned = true;
        if (self.tunnel) |tunnel| {
            tunnel.close() catch |err| {
                std.log.err("ngrok cleanup retained for prune: {s}", .{@errorName(err)});
                cleaned = false;
            };
            tunnel.deinit();
            self.tunnel = null;
        } else if (self.pending) |pending| if (pending.ngrok) |registration| {
            ngrok.clean(self.allocator, self.io, self.state_dir, registration) catch |err| {
                std.log.err("ngrok preparation cleanup retained for prune: {s}", .{@errorName(err)});
                cleaned = false;
            };
        };
        if (self.tail) |*tail| {
            tailscale.clean(self.allocator, self.io, self.tail_cli, tail.*) catch |err| {
                std.log.err("sharing cleanup retained for prune: {s}", .{@errorName(err)});
                cleaned = false;
            };
            tail.deinit();
            self.tail = null;
        }
        if (cleaned) {
            if (self.record) |record| remove(self.allocator, self.io, self.state_dir, record.runner) catch {};
            if (self.pending) |pending| removePending(self.allocator, self.io, self.state_dir, pending) catch {};
        }
        self.record = null;
        self.pending = null;
        if (self.journal_arena) |*arena| arena.deinit();
        self.journal_arena = null;
    }
    fn persistPending(self: *Session) !void {
        const pending = self.pending.?;
        const current = try process.current();
        if (current.uid != pending.supervisor.uid or current.pid != pending.supervisor.pid or current.start != pending.supervisor.start) return error.SharingOwnerConflict;
        var manager = try runner.Manager.open(self.allocator, self.io, self.state_dir);
        defer manager.deinit();
        const held = try lock(manager);
        defer held.close(self.io);
        const path = try pendingFilename(self.allocator, pending);
        defer self.allocator.free(path);
        const data = try std.json.Stringify.valueAlloc(self.allocator, pending, .{});
        defer self.allocator.free(data);
        const previous = manager.directory.openFile(self.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (previous) |file| {
            defer file.close(self.io);
            try process.validateOwned(file.handle, 0o600, false);
            const bytes = try readJournal(self.allocator, self.io, file);
            defer self.allocator.free(bytes);
            const parsed = try std.json.parseFromSlice(Pending, self.allocator, bytes, .{});
            defer parsed.deinit();
            const expected = parsed.value.supervisor;
            if (parsed.value.version != pending.version or expected.uid != current.uid or expected.pid != current.pid or expected.start != current.start) return error.SharingOwnerConflict;
        }
        try writeJournal(manager, path, data);
    }
    fn persist(self: *Session) !void {
        const record = self.record.?;
        var manager = try runner.Manager.open(self.allocator, self.io, self.state_dir);
        defer manager.deinit();
        const held = try lock(manager);
        defer held.close(self.io);
        const live = process.inspect(record.runner.identity.pid) catch return error.SharingOwnerConflict;
        if (live.uid != record.runner.uid or live.start != record.runner.identity.start or live.pgid != record.runner.process_group) return error.SharingOwnerConflict;
        const data = try std.json.Stringify.valueAlloc(self.allocator, record, .{});
        defer self.allocator.free(data);
        const path = try filename(self.allocator, record.runner.endpoint.name);
        defer self.allocator.free(path);
        const previous = manager.directory.openFile(self.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (previous) |file| {
            defer file.close(self.io);
            try process.validateOwned(file.handle, 0o600, false);
            const bytes = try readJournal(self.allocator, self.io, file);
            defer self.allocator.free(bytes);
            const parsed = try std.json.parseFromSlice(Record, self.allocator, bytes, .{});
            defer parsed.deinit();
            const old = parsed.value;
            if (old.version != 1 or old.runner.uid != record.runner.uid) return error.SharingOwnerConflict;
            if (old.runner.identity.pid != record.runner.identity.pid or old.runner.identity.start != record.runner.identity.start) {
                // Preserve cleanup obligations until exact crash reconciliation.
                if (old.tail != null or old.advertisement != null or old.ngrok != null) return error.SharingOwnerConflict;
                const prior = process.inspect(old.runner.identity.pid) catch |err| switch (err) {
                    error.ProcessGone => null,
                    else => return err,
                };
                if (prior) |owner| if (owner.uid == old.runner.uid and owner.start == old.runner.identity.start) return error.SharingOwnerConflict;
            }
        }
        try writeJournal(manager, path, data);
    }
};
fn readJournal(a: A, io: std.Io, file: std.Io.File) ![]u8 {
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(a, .limited(65536));
}
fn writeJournal(manager: runner.Manager, path: []const u8, data: []const u8) !void {
    const existing = manager.directory.openFile(manager.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |file| {
        defer file.close(manager.io);
        try process.validateOwned(file.handle, 0o600, false);
    }
    var atomic = try manager.directory.createFileAtomic(manager.io, path, .{ .permissions = .fromMode(0o600), .replace = true });
    defer atomic.deinit(manager.io);
    try atomic.file.writePositionalAll(manager.io, data, 0);
    try atomic.file.sync(manager.io);
    try atomic.replace(manager.io);
    try syncDirectory(manager.directory, manager.io);
}
fn pendingFilename(a: A, pending: Pending) ![]u8 {
    const name = try filename(a, pending.name);
    defer a.free(name);
    return std.fmt.allocPrint(a, "pending-{d}-{s}", .{ pending.supervisor.pid, name });
}
fn removePending(a: A, io: std.Io, state: []const u8, pending: Pending) !void {
    var manager = try runner.Manager.open(a, io, state);
    defer manager.deinit();
    const held = try lock(manager);
    defer held.close(io);
    const path = try pendingFilename(a, pending);
    defer a.free(path);
    const file = manager.directory.openFile(io, path, .{ .follow_symlinks = false }) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer file.close(io);
    try process.validateOwned(file.handle, 0o600, false);
    const bytes = try readJournal(a, io, file);
    defer a.free(bytes);
    const parsed = try std.json.parseFromSlice(Pending, a, bytes, .{});
    defer parsed.deinit();
    const actual = parsed.value.supervisor;
    if (actual.uid != pending.supervisor.uid or actual.pid != pending.supervisor.pid or actual.start != pending.supervisor.start) return error.SharingOwnerConflict;
    try manager.directory.deleteFile(io, path);
    try syncDirectory(manager.directory, io);
}

fn filename(a: A, name: []const u8) ![]u8 {
    try @import("hosts.zig").validateName(name, "");
    return std.fmt.allocPrint(a, "share-{s}.json", .{name});
}
fn remove(a: A, io: std.Io, state: []const u8, expected: runner.Record) !void {
    var manager = try runner.Manager.open(a, io, state);
    defer manager.deinit();
    const path = try filename(a, expected.endpoint.name);
    defer a.free(path);
    const held = try lock(manager);
    defer held.close(io);
    const file = manager.directory.openFile(io, path, .{ .follow_symlinks = false }) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer file.close(io);
    try process.validateOwned(file.handle, 0o600, false);
    const data = try readJournal(a, io, file);
    defer a.free(data);
    const parsed = try std.json.parseFromSlice(Record, a, data, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const current = parsed.value.runner;
    if (current.uid != expected.uid or current.identity.pid != expected.identity.pid or current.identity.start != expected.identity.start) return error.SharingOwnerConflict;
    try manager.directory.deleteFile(io, path);
    try syncDirectory(manager.directory, io);
}
pub fn prune(a: A, io: std.Io, state: []const u8, force: bool) !void {
    var manager = try runner.Manager.open(a, io, state);
    defer manager.deinit();
    const held = try lock(manager);
    defer held.close(io);
    var it = manager.directory.iterate();
    while (try it.next(io)) |entry| {
        if (std.mem.startsWith(u8, entry.name, "pending-") and std.mem.endsWith(u8, entry.name, ".json")) {
            const file = try manager.directory.openFile(io, entry.name, .{ .follow_symlinks = false });
            defer file.close(io);
            try process.validateOwned(file.handle, 0o600, false);
            const bytes = try readJournal(a, io, file);
            defer a.free(bytes);
            const parsed = try std.json.parseFromSlice(Pending, a, bytes, .{});
            defer parsed.deinit();
            const pending = parsed.value;
            const path = try pendingFilename(a, pending);
            defer a.free(path);
            if (pending.version != 1 or pending.supervisor.uid != process.uid() or !std.mem.eql(u8, path, entry.name)) return error.InvalidSharingRecord;
            const owner = process.inspect(pending.supervisor.pid) catch |err| switch (err) {
                error.ProcessGone => null,
                else => return err,
            };
            if (owner) |identity| if (identity.uid == pending.supervisor.uid and identity.start == pending.supervisor.start) {
                if (force) return error.LiveSharingSession;
                continue;
            };
            try cleanupRegistration(a, io, state, pending.tail, pending.advertisement, pending.ngrok);
            try manager.directory.deleteFile(io, entry.name);
            try syncDirectory(manager.directory, io);
            continue;
        }
        if (!std.mem.startsWith(u8, entry.name, "share-") or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const file = try manager.directory.openFile(io, entry.name, .{ .follow_symlinks = false });
        defer file.close(io);
        try process.validateOwned(file.handle, 0o600, false);
        const data = try readJournal(a, io, file);
        defer a.free(data);
        const parsed = try std.json.parseFromSlice(Record, a, data, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const record = parsed.value;
        if (record.version != 1) return error.UnsupportedSharingVersion;
        if (record.runner.uid != process.uid() or record.runner.supervisor_uid != process.uid() or (record.advertisement != null and record.advertisement.?.uid != process.uid())) return error.SharingOwnerConflict;
        const expected = try filename(a, record.runner.endpoint.name);
        defer a.free(expected);
        if (!std.mem.eql(u8, expected, entry.name)) return error.InvalidSharingRecord;
        const supervisor = process.inspect(record.runner.supervisor.pid) catch |err| switch (err) {
            error.ProcessGone => null,
            else => return err,
        };
        if (supervisor) |identity| if (identity.uid == record.runner.supervisor_uid and identity.start == record.runner.supervisor.start) {
            if (force) return error.LiveSharingSession;
            continue;
        };
        try cleanupRegistration(a, io, state, record.tail, record.advertisement, record.ngrok);
        try manager.directory.deleteFile(io, entry.name);
        try syncDirectory(manager.directory, io);
    }
}

fn cleanupRegistration(a: A, io: std.Io, state: []const u8, tail: ?Tail, advertisement: ?process.Identity, tunnel: ?ngrok.Registration) !void {
    if (tail) |registration| {
        const arena = std.heap.ArenaAllocator.init(a);
        const plan: tailscale.Plan = .{ .arena = arena, .executable = registration.executable, .registration = registration.registration };
        try tailscale.clean(a, io, registration.executable, plan);
    }
    if (tunnel) |registration| try ngrok.clean(a, io, state, registration);
    if (advertisement) |expected| {
        if (expected.uid != process.uid()) return error.AdvertisementIdentityConflict;
        const live = process.inspect(expected.pid) catch |err| switch (err) {
            error.ProcessGone => null,
            else => return err,
        };
        if (live) |identity| {
            if (identity.uid != expected.uid or identity.start != expected.start or identity.pgid != expected.pgid) return error.AdvertisementIdentityConflict;
            try std.posix.kill(expected.pid, .TERM);
        }
    }
}
fn syncDirectory(dir: std.Io.Dir, io: std.Io) !void {
    const file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}
fn lock(manager: runner.Manager) !std.Io.File {
    const io = manager.io;
    const file = manager.directory.createFile(io, "sharing.lock", .{ .exclusive = true, .truncate = false, .read = true, .permissions = .fromMode(0o600) }) catch |err| blk: {
        if (err != error.PathAlreadyExists) return err;
        break :blk try manager.directory.openFile(io, "sharing.lock", .{ .mode = .read_write, .follow_symlinks = false });
    };
    errdefer file.close(io);
    try process.validateOwned(file.handle, 0o600, false);
    try file.lock(io, .exclusive);
    return file;
}

test "real journal cleanup cannot remove a newer process owner" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const one = try std.fs.path.join(a, &.{ root, "one" });
    defer a.free(one);
    const two = try std.fs.path.join(a, &.{ root, "two" });
    defer a.free(two);
    var first = try runner.start(a, io, .{ .name = "journal", .argv = &.{ "/bin/sleep", "30" }, .state_directory = one, .proxy = false });
    defer first.deinit();
    var second = try runner.start(a, io, .{ .name = "journal", .argv = &.{ "/bin/sleep", "30" }, .state_directory = two, .proxy = false });
    defer second.deinit();
    var session: Session = .{ .allocator = a, .io = io, .state_dir = one, .record = .{ .runner = first.record } };
    try session.persist();
    session.record = .{ .runner = second.record };
    try std.testing.expectError(error.SharingOwnerConflict, session.persist());
    session.record = .{ .runner = first.record };
    try std.posix.kill(first.record.identity.pid, .KILL);
    _ = try first.child.wait(io);
    session.record = .{ .runner = second.record };
    try session.persist();
    session.record = .{ .runner = first.record };
    try std.testing.expectError(error.SharingOwnerConflict, session.persist());
    try std.testing.expectError(error.LiveSharingSession, prune(a, io, one, true));
    try prune(a, io, one, false);
    try std.testing.expectError(error.SharingOwnerConflict, remove(a, io, one, first.record));
    try remove(a, io, one, second.record);
    // Removing the exact journal twice is harmless.
    try remove(a, io, one, second.record);
}
