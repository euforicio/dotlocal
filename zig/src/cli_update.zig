//! User config defaults, the `config` and `update` commands, the detached
//! background update and the installed daemon's updater task.
const std = @import("std");
const p = @import("dotlocal");
const A = std.mem.Allocator;
const Io = std.Io;

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn print(io: Io, file: Io.File, comptime fmt: []const u8, args: anytype) void {
    var buffer: [1024]u8 = undefined;
    var writer = file.writerStreaming(io, &buffer);
    writer.interface.print(fmt, args) catch return;
    writer.interface.flush() catch {};
}

fn statePath(a: A, env: *const std.process.Environ.Map, name: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ env.get("HOME") orelse return error.HomeMissing, ".dotlocal", name });
}

/// Root never reads a user-writable config: it could redirect privileged
/// state, and under sudo HOME may still name the invoking user's home.
fn privileged() bool {
    return p.process.uid() == 0;
}

/// User config values become `DOTLOCAL_*` defaults below flags and the
/// environment. `config` reports its own load errors so a broken file can be
/// repaired.
pub fn applyUserConfig(init: std.process.Init, command: ?[]const u8) !void {
    if (privileged()) return;
    if (command) |name| if (eq(name, "config")) return;
    const a = init.arena.allocator();
    const path = p.userconfig.defaultPath(a, init.environ_map) catch return;
    const loaded = p.userconfig.load(a, init.io, path) catch |err| {
        print(init.io, .stderr(), "dotlocal: {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    // The arena owns `loaded`; Environ.Map.put copies the values.
    try p.userconfig.applyDefaults(loaded.value, init.environ_map);
}

/// Commands that never trigger a background check.
const quiet_commands = [_][]const u8{ "daemon", "__background", "__auto-update", "update", "config", "version", "help", "--help", "-h" };

fn backgroundEligible(init: std.process.Init, command: ?[]const u8) ?p.update.Settings {
    if (p.is_dev_build or privileged()) return null;
    if (command) |name| for (quiet_commands) |quiet| if (eq(name, quiet)) return null;
    const settings = p.update.settings(init.environ_map) catch return null;
    if (!settings.enabled or settings.pin != null) return null;
    return settings;
}

/// Prints the one-line notice from a finished background update, or a single
/// warning when checks keep failing.
pub fn reportBackground(init: std.process.Init, command: ?[]const u8) void {
    _ = backgroundEligible(init, command) orelse return;
    const a = init.arena.allocator();
    const state = statePath(a, init.environ_map, "update.json") catch return;
    const held = tryLock(init) orelse return;
    defer held.close(init.io);
    if (p.update.takeNotice(a, init.io, state) catch null) |notice| print(init.io, .stderr(), "{s}\n", .{notice});
    if (p.update.takeFailureWarning(a, init.io, state) catch null) |count|
        print(init.io, .stderr(), "dotlocal: automatic update failed {d} times in a row; run `dotlocal update` for details\n", .{count});
}

/// Starts a detached `__auto-update` when a check is due. Called after the
/// command finished; never changes its exit status or waits on the network.
pub fn spawnBackground(init: std.process.Init, command: ?[]const u8) void {
    _ = backgroundEligible(init, command) orelse return;
    const a = init.arena.allocator();
    const io = init.io;
    const state = statePath(a, init.environ_map, "update.json") catch return;
    const now = Io.Clock.real.now(io).toSeconds();
    if (!(p.update.due(a, io, state, now) catch false)) return;
    const exe = std.process.executablePathAlloc(io, a) catch |err| {
        // Throttle: do not retry on every command.
        const held = tryLock(init) orelse return;
        defer held.close(io);
        p.update.recordFailure(a, io, state, now, err) catch {};
        return;
    };
    // Package-manager installs are updated by their package manager.
    if (p.update.packageManaged(exe)) return;
    installDirectoryWritable(io, exe) catch return;
    // Not waited: the caller exits next and the child is reparented.
    _ = std.process.spawn(io, .{ .argv = &.{ exe, "__auto-update" }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore, .environ_map = init.environ_map }) catch return;
}

/// update.lock without waiting; null when another updater holds it.
fn tryLock(init: std.process.Init) ?Io.File {
    const path = statePath(init.arena.allocator(), init.environ_map, "update.lock") catch return null;
    return p.update.lock(init.io, path) catch null;
}

fn installDirectoryWritable(io: Io, exe: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, std.fs.path.dirname(exe) orelse return error.InvalidTarget, .{});
    defer dir.close(io);
    p.process.validateInstallDirectory(dir.handle) catch |err| return switch (err) {
        error.UnsafeStateFile => error.UnsafeInstallDirectory,
        else => err,
    };
}

/// Hidden `__auto-update`: detached check + apply. Results go to update.json
/// only; stdio is /dev/null.
pub fn autoUpdate(init: std.process.Init) u8 {
    if (std.c.setsid() < 0) return 1;
    autoUpdateOnce(init) catch return 1;
    return 0;
}

fn autoUpdateOnce(init: std.process.Init) !void {
    const settings = backgroundEligible(init, null) orelse return;
    const a = init.arena.allocator();
    const io = init.io;
    const state = try statePath(a, init.environ_map, "update.json");
    try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(state).?);
    const held = p.update.lock(io, try statePath(a, init.environ_map, "update.lock")) catch return;
    defer held.close(io);
    const now = Io.Clock.real.now(io).toSeconds();
    if (!(try p.update.due(a, io, state, now))) return;
    const source = p.update.sourceFromEnv(a, init.environ_map) catch |err| return p.update.recordFailure(a, io, state, now, err);
    var plan = (p.update.check(a, io, source, settings.channel, p.version, .automatic) catch |err|
        return p.update.recordFailure(a, io, state, now, err)) orelse return p.update.recordCheck(a, io, state, now, null);
    defer plan.deinit();
    const exe = std.process.executablePathAlloc(io, a) catch |err| return p.update.recordFailure(a, io, state, now, err);
    p.update.apply(a, io, source, plan, exe) catch |err| return p.update.recordFailure(a, io, state, now, err);
    try p.update.recordCheck(a, io, state, now, .{ .from = p.version, .to = plan.release.version });
}

/// `update` and `config` act on the invoking user's files and executable.
fn refuseRoot(io: Io, command: []const u8) !void {
    if (!privileged()) return;
    print(io, .stderr(), "dotlocal: run `dotlocal {s}` as your user, without sudo\n", .{command});
    return error.RunWithoutSudo;
}

pub fn configCommand(init: std.process.Init, rest: []const []const u8) !u8 {
    const a = init.arena.allocator();
    const io = init.io;
    try refuseRoot(io, "config");
    const path = try p.userconfig.defaultPath(a, init.environ_map);
    if (rest.len == 0 or (eq(rest[0], "get") and rest.len == 2)) {
        const loaded = try p.userconfig.load(a, io, path);
        if (rest.len == 0) return writeJson(io, loaded.value);
        inline for (@typeInfo(p.userconfig.Config).@"struct".field_names) |name| if (eq(name, rest[1])) {
            return writeJson(io, @field(loaded.value, name));
        };
        return error.UnknownConfigKey;
    }
    if (eq(rest[0], "set") and rest.len == 3) {
        try p.userconfig.set(a, io, path, rest[1], rest[2]);
        return 0;
    }
    if (eq(rest[0], "unset") and rest.len == 2) {
        try p.userconfig.unset(a, io, path, rest[1]);
        return 0;
    }
    return error.UnexpectedArgument;
}

fn writeJson(io: Io, value: anytype) !u8 {
    var buffer: [4096]u8 = undefined;
    var writer = Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2, .emit_null_optional_fields = false }, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
    return 0;
}

pub const UpdateOptions = struct { check: bool = false, channel: ?[]const u8 = null, version: ?[]const u8 = null };

/// `dotlocal update`: checks and installs now. A plain update clears the pin;
/// `--version X` installs X and pins it; `--channel` switches and records it.
pub fn updateCommand(init: std.process.Init, options: UpdateOptions) !u8 {
    const a = init.arena.allocator();
    const io = init.io;
    const stdout = Io.File.stdout();
    try refuseRoot(io, "update");
    if (p.is_dev_build) {
        print(io, .stderr(), "dotlocal: development builds do not self-update; install a release build\n", .{});
        return error.DevelopmentBuildCannotUpdate;
    }
    var settings = try p.update.settings(init.environ_map);
    var selection: p.manifest.Selection = .automatic;
    if (options.channel) |text| {
        settings.channel = std.meta.stringToEnum(p.manifest.Channel, text) orelse return error.InvalidChannel;
        selection = .channel_switch;
    }
    if (options.version) |v| {
        _ = std.SemanticVersion.parse(v) catch return error.InvalidVersion;
        selection = .{ .exact = v };
        // Rollback targets come from stable unless a channel is named.
        if (options.channel == null) settings.channel = .stable;
    }
    const config_path = try p.userconfig.defaultPath(a, init.environ_map);
    const state = try statePath(a, init.environ_map, "update.json");
    const exe = try std.process.executablePathAlloc(io, a);
    if (!options.check and p.update.packageManaged(exe)) {
        print(io, .stderr(), "dotlocal: {s} is managed by a package manager; update dotlocal with it\n", .{exe});
        return error.PackageManagedInstall;
    }
    if (!options.check) installDirectoryWritable(io, exe) catch |err| {
        print(io, .stderr(), "dotlocal: cannot replace {s} ({s}); update it with the tool that installed it\n", .{ exe, @errorName(err) });
        return err;
    };
    try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(state).?);
    const held = p.update.lock(io, try statePath(a, init.environ_map, "update.lock")) catch |err|
        return if (err == error.WouldBlock) error.UpdateInProgress else err;
    defer held.close(io);
    const source = try p.update.sourceFromEnv(a, init.environ_map);
    const now = Io.Clock.real.now(io).toSeconds();

    var installed: []const u8 = p.version;
    if (options.version != null and eq(options.version.?, p.version)) {
        if (options.check) print(io, stdout, "dotlocal {s} is installed\n", .{p.version});
    } else if (try p.update.check(a, io, source, settings.channel, p.version, selection)) |found| {
        var plan = found;
        defer plan.deinit();
        if (options.check) {
            print(io, stdout, "dotlocal {s} available ({t}); run `dotlocal update`\n", .{ plan.release.version, settings.channel });
            return 0;
        }
        try p.update.apply(a, io, source, plan, exe);
        installed = try a.dupe(u8, plan.release.version);
    } else print(io, stdout, "dotlocal {s} is up to date ({t})\n", .{ p.version, settings.channel });
    if (options.check) return 0;

    if (options.channel) |text| try p.userconfig.set(a, io, config_path, "channel", text);
    if (options.version) |v| try p.userconfig.set(a, io, config_path, "pin", v) else if (settings.pin != null or try hasPin(a, io, config_path))
        try p.userconfig.unset(a, io, config_path, "pin");
    try p.update.recordCheck(a, io, state, now, null);
    if (!eq(installed, p.version)) print(io, stdout, "dotlocal updated {s} → {s}\n", .{ p.version, installed });
    if (options.version) |v| print(io, stdout, "pinned to {s}; run `dotlocal update` to resume automatic updates\n", .{v});
    return 0;
}

fn hasPin(a: A, io: Io, path: []const u8) !bool {
    const loaded = try p.userconfig.load(a, io, path);
    return loaded.value.pin != null;
}

/// Installed daemon updater: checks daily, installs over its own executable,
/// then requests the normal graceful stop; `main` exits 75 so launchd
/// restarts the new binary. Canceled (or `stop` set) on shutdown.
pub fn daemonUpdater(gpa: A, io: Io, source: p.update.Source, channel: p.manifest.Channel, state_dir: []const u8, stop: *std.atomic.Value(bool), updated: *std.atomic.Value(bool)) void {
    // Let the network settle after boot before the first check.
    var delay: i64 = 60;
    while (!stop.load(.acquire)) {
        // Short slices keep shutdown prompt even if a cancel was absorbed.
        var slept: i64 = 0;
        while (slept < delay and !stop.load(.acquire)) : (slept += 5) Io.sleep(io, .fromSeconds(5), .awake) catch return;
        if (stop.load(.acquire)) return;
        delay = p.update.interval_seconds;
        const installed = daemonUpdateOnce(gpa, io, source, channel, state_dir) catch |err| switch (err) {
            error.Canceled => return,
            else => blk: {
                std.log.warn("update check: {s}", .{@errorName(err)});
                break :blk false;
            },
        };
        if (installed) {
            updated.store(true, .release);
            stop.store(true, .release); // normal graceful drain
            return;
        }
    }
}

fn daemonUpdateOnce(gpa: A, io: Io, source: p.update.Source, channel: p.manifest.Channel, state_dir: []const u8) !bool {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const held = try p.update.lock(io, try std.fs.path.join(a, &.{ state_dir, "update.lock" }));
    defer held.close(io);
    var plan = (try p.update.check(a, io, source, channel, p.version, .automatic)) orelse return false;
    defer plan.deinit();
    try p.update.apply(a, io, source, plan, try std.process.executablePathAlloc(io, a));
    std.log.info("updated {s} → {s}; restarting", .{ p.version, plan.release.version });
    return true;
}
