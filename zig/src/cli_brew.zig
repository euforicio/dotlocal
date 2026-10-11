//! Homebrew owns the immutable bootstrap; signed updates own the user copy.
const std = @import("std");
const p = @import("dotlocal");
const Io = std.Io;

pub fn launch(init: std.process.Init, args: []const []const u8) !noreturn {
    const a = init.arena.allocator();
    const io = init.io;
    const source = try std.process.executablePathAlloc(io, a);
    if (!p.update.packageManaged(source)) return error.NotHomebrewBootstrap;
    // A privileged command must never execute a binary selected from HOME.
    const target = if (p.process.uid() == 0) source else try prepare(init, source);
    const argv = try a.alloc([]const u8, args.len + 1);
    argv[0] = target;
    @memcpy(argv[1..], args);
    return std.process.replace(io, .{ .argv = argv, .environ_map = init.environ_map });
}

fn ownedDir(parent: Io.Dir, io: Io, name: []const u8) !Io.Dir {
    parent.createDir(io, name, .fromMode(0o700)) catch |err| if (err != error.PathAlreadyExists) return err;
    const dir = try parent.openDir(io, name, .{ .follow_symlinks = false });
    errdefer dir.close(io);
    try p.process.validateInstallDirectory(dir.handle);
    return dir;
}

fn runtimeVersion(init: std.process.Init, bin: Io.Dir, target: []const u8) !?[]const u8 {
    const file = bin.openFile(init.io, "dotlocal", .{ .follow_symlinks = false }) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close(init.io);
    try p.process.validateUserFile(file.handle);
    const version = try p.update.probeVersion(init.arena.allocator(), init.io, target);
    _ = try std.SemanticVersion.parse(version);
    return version;
}

fn bootstrapLock(state: Io.Dir, io: Io) !Io.File {
    if (state.createFile(io, "update.lock", .{ .exclusive = true, .permissions = .fromMode(0o600) })) |created| {
        created.close(io);
    } else |err| if (err != error.PathAlreadyExists) return err;
    const file = try state.openFile(io, "update.lock", .{ .mode = .read_write, .follow_symlinks = false, .lock = .exclusive, .lock_nonblocking = true });
    errdefer file.close(io);
    try p.process.validateUserFile(file.handle);
    return file;
}

fn prepare(init: std.process.Init, source: []const u8) ![]const u8 {
    const a = init.arena.allocator();
    const io = init.io;
    const home = init.environ_map.get("HOME") orelse return error.HomeMissing;
    if (!std.fs.path.isAbsolute(home)) return error.InvalidHome;
    const parent = try Io.Dir.openDirAbsolute(io, home, .{ .follow_symlinks = false });
    defer parent.close(io);
    try p.process.validateInstallDirectory(parent.handle);
    const state = try ownedDir(parent, io, ".dotlocal");
    defer state.close(io);
    const bin = try ownedDir(state, io, "bin");
    defer bin.close(io);
    const target = try std.fs.path.join(a, &.{ home, ".dotlocal", "bin", "dotlocal" });
    const installed = try runtimeVersion(init, bin, target);
    // Pins survive Brew upgrades. Without a pin, a newer Brew bundle advances
    // the runtime; an equal or older bundle leaves signed self-updates intact.
    const settings = try p.update.settings(init.environ_map);
    if (installed) |version| if (settings.pin != null or !p.update.newer(p.version, version)) return target;
    const held = bootstrapLock(state, io) catch |err| {
        if (err == error.WouldBlock and installed != null) return target;
        return err;
    };
    defer held.close(io);
    // Recheck under the shared updater lock: another launch or a signed update
    // may have advanced the runtime while the initial version was probed.
    if (try runtimeVersion(init, bin, target)) |version| {
        if (settings.pin != null or !p.update.newer(p.version, version)) return target;
    }
    const bytes = try Io.Dir.cwd().readFileAlloc(io, source, a, .limited(128 << 20));
    var atomic = try bin.createFileAtomic(io, "dotlocal", .{ .permissions = .fromMode(0o755), .replace = true });
    defer atomic.deinit(io);
    try atomic.file.setPermissions(io, .fromMode(0o755));
    try atomic.file.writeStreamingAll(io, bytes);
    try atomic.file.sync(io);
    try atomic.replace(io);
    return target;
}
