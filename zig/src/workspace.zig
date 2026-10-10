const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const config = @import("projectconfig.zig");
pub const Package = struct { cwd: []const u8, name: ?[]const u8 = null, scope: ?[]const u8 = null };
pub const Workspace = struct { root: []const u8, packages: []const Package };

fn packageWorkspaces(value: std.json.Value) ?[]std.json.Value {
    if (value != .object) return null;
    const ws = value.object.get("workspaces") orelse return null;
    if (ws == .array) return ws.array.items;
    if (ws == .object) if (ws.object.get("packages")) |packages| {
        if (packages == .array) return packages.array.items;
    };
    return null;
}

pub fn findRoot(allocator: Allocator, io: Io, cwd: []const u8) !?[]u8 {
    const real = try Io.Dir.cwd().realPathFileAlloc(io, if (cwd.len == 0) "." else cwd, allocator);
    defer allocator.free(real);
    var dir: []const u8 = real;
    while (true) {
        const path = try std.fs.path.join(allocator, &.{ dir, "pnpm-workspace.yaml" });
        defer allocator.free(path);
        // As in pnpm, presence marks the root; discover then reads it strictly.
        if (Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .file) return try allocator.dupe(u8, dir);
        } else |_| {}
        if (try config.packageJSON(allocator, io, dir)) |wire| {
            defer wire.deinit();
            if (packageWorkspaces(wire.value) != null) return try allocator.dupe(u8, dir);
        }
        const parent = std.fs.path.dirname(dir) orelse return null;
        if (std.mem.eql(u8, parent, dir)) return null;
        dir = parent;
    }
}

fn unquote(text: []const u8) []const u8 {
    var value = std.mem.trim(u8, text, " \t\r");
    if (value.len > 0 and (value[0] == '\'' or value[0] == '"')) value = value[1..];
    if (value.len > 0 and (value[value.len - 1] == '\'' or value[value.len - 1] == '"')) value = value[0 .. value.len - 1];
    return std.mem.trim(u8, value, " \t\r");
}

/// The upstream's deliberately small pnpm YAML subset: block or single-line flow packages.
pub fn parsePnpm(allocator: Allocator, yaml: []const u8) ![]const []const u8 {
    var globs: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (globs.items) |glob| allocator.free(glob);
        globs.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, yaml, '\n');
    var packages = false;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!packages) {
            if (!std.mem.startsWith(u8, line, "packages")) continue;
            const rest = std.mem.trimStart(u8, line[8..], " \t");
            if (rest.len == 0 or rest[0] != ':') continue;
            const value = std.mem.trim(u8, rest[1..], " \t\r");
            if (std.mem.startsWith(u8, value, "[")) {
                const end = std.mem.lastIndexOfScalar(u8, value, ']') orelse value.len;
                var items = std.mem.splitScalar(u8, value[1..end], ',');
                while (items.next()) |item| {
                    const glob = unquote(item);
                    if (glob.len > 0) try globs.append(allocator, try allocator.dupe(u8, glob));
                }
                break;
            }
            packages = true;
            continue;
        }
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (line.len > 0 and !std.ascii.isWhitespace(line[0]) and line[0] != '-') break;
        if (!std.mem.startsWith(u8, trimmed, "-") or trimmed.len < 2 or !std.ascii.isWhitespace(trimmed[1])) continue;
        var value = std.mem.trim(u8, trimmed[2..], " \t\r");
        if (std.mem.findScalar(u8, value, '#')) |comment| value = value[0..comment];
        value = unquote(value);
        if (value.len > 0) try globs.append(allocator, try allocator.dupe(u8, value));
    }
    return globs.toOwnedSlice(allocator);
}

/// `*` matches any run of characters within one path segment.
fn matches(name: []const u8, pattern: []const u8) bool {
    var n: usize = 0;
    var p: usize = 0;
    var star: ?usize = null;
    var resume_at: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            resume_at = n;
        } else if (p < pattern.len and pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if (star) |s| {
            p = s + 1;
            resume_at += 1;
            n = resume_at;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const max_packages = 4096;
const max_depth = 32;

fn hasPackageJSON(allocator: Allocator, io: Io, dir: []const u8) !bool {
    const path = try std.fs.path.join(allocator, &.{ dir, "package.json" });
    defer allocator.free(path);
    const stat = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .file;
}

/// Walks no-follow directories. `**` matches zero or more directories and,
/// like npm and pnpm, never descends into node_modules or dot directories.
/// Only directories holding a package.json are collected and counted; the
/// walk stops descending at `max_depth` instead of failing.
fn expand(allocator: Allocator, io: Io, dir: []const u8, segments: []const []const u8, depth: usize, output: *std.StringHashMap(void)) !void {
    if (segments.len == 0) {
        if (output.contains(dir) or !try hasPackageJSON(allocator, io, dir)) return;
        if (output.count() >= max_packages) return error.WorkspaceTooLarge;
        try output.put(dir, {});
        return;
    }
    const segment = segments[0];
    const globstar = std.mem.eql(u8, segment, "**");
    if (globstar) try expand(allocator, io, dir, segments[1..], depth, output);
    if (depth >= max_depth) return;
    var directory = Io.Dir.openDirAbsolute(io, dir, .{ .follow_symlinks = false, .iterate = true }) catch return;
    defer directory.close(io);
    if (std.mem.findScalar(u8, segment, '*') == null) {
        const child = directory.openDir(io, segment, .{ .follow_symlinks = false }) catch return;
        child.close(io);
        const path = try std.fs.path.join(allocator, &.{ dir, segment });
        try expand(allocator, io, path, segments[1..], depth + 1, output);
        return;
    }
    var it = directory.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (globstar) {
            if (entry.name[0] == '.' or std.mem.eql(u8, entry.name, "node_modules")) continue;
        } else if (!matches(entry.name, segment)) continue;
        const path = try std.fs.path.join(allocator, &.{ dir, entry.name });
        try expand(allocator, io, path, if (globstar) segments else segments[1..], depth + 1, output);
    }
}

/// Missing returns null. The file's presence already marked the root, so an
/// unreadable, non-regular or oversized file is an error, not a fallback.
fn readPnpm(allocator: Allocator, io: Io, path: []const u8) !?[]u8 {
    const file = Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    if ((try file.stat(io)).kind != .file) return error.InvalidWorkspaceFile;
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.StreamTooLong => error.WorkspaceFileTooLarge,
        error.ReadFailed => reader.err orelse error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Returned paths and metadata are owned by the caller's discovery arena.
pub fn discover(allocator: Allocator, io: Io, cwd: []const u8) !?Workspace {
    const root = (try findRoot(allocator, io, cwd)) orelse return null;
    const yaml_path = try std.fs.path.join(allocator, &.{ root, "pnpm-workspace.yaml" });
    defer allocator.free(yaml_path);
    var globs: std.ArrayList([]const u8) = .empty;
    defer globs.deinit(allocator);
    if (try readPnpm(allocator, io, yaml_path)) |yaml| {
        defer allocator.free(yaml);
        const parsed = try parsePnpm(allocator, yaml);
        defer allocator.free(parsed);
        try globs.appendSlice(allocator, parsed);
    } else if (try config.packageJSON(allocator, io, root)) |wire| {
        defer wire.deinit();
        if (packageWorkspaces(wire.value)) |items| for (items) |item| {
            if (item == .string) try globs.append(allocator, try allocator.dupe(u8, item.string));
        };
    }
    var include = std.StringHashMap(void).init(allocator);
    defer include.deinit();
    var exclude = std.StringHashMap(void).init(allocator);
    defer exclude.deinit();
    for (globs.items) |glob| {
        const negative = std.mem.startsWith(u8, glob, "!");
        const pattern = if (negative) glob[1..] else glob;
        if (std.fs.path.isAbsolute(pattern)) return error.UnsafeWorkspacePattern;
        var segments: std.ArrayList([]const u8) = .empty;
        defer segments.deinit(allocator);
        var parts = std.mem.splitScalar(u8, pattern, '/');
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, "..") or std.mem.findScalar(u8, part, 0) != null) return error.UnsafeWorkspacePattern;
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            // Consecutive `**` are equivalent and would only repeat the walk.
            if (std.mem.eql(u8, part, "**") and segments.items.len > 0 and std.mem.eql(u8, segments.getLast(), "**")) continue;
            if (segments.items.len >= max_depth) return error.WorkspaceTooDeep;
            try segments.append(allocator, part);
        }
        try expand(allocator, io, root, segments.items, 0, if (negative) &exclude else &include);
    }
    var packages: std.ArrayList(Package) = .empty;
    var it = include.keyIterator();
    while (it.next()) |path| {
        // `**` also matches the root itself, which is never its own package.
        if (exclude.contains(path.*) or std.mem.eql(u8, path.*, root)) continue;
        const wire = (try config.packageJSON(allocator, io, path.*)) orelse continue;
        defer wire.deinit();
        if (wire.value != .object) continue;
        var package: Package = .{ .cwd = path.* };
        if (wire.value.object.get("name")) |value| if (value == .string) {
            var name = value.string;
            if (std.mem.startsWith(u8, name, "@")) if (std.mem.findScalar(u8, name, '/')) |slash| {
                package.scope = try allocator.dupe(u8, name[1..slash]);
                name = name[slash + 1 ..];
            };
            package.name = try allocator.dupe(u8, name);
        };
        try packages.append(allocator, package);
    }
    std.mem.sort(Package, packages.items, {}, struct {
        fn less(_: void, left: Package, right: Package) bool {
            return std.mem.lessThan(u8, left.cwd, right.cwd);
        }
    }.less);
    return .{ .root = root, .packages = try packages.toOwnedSlice(allocator) };
}
