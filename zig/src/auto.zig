const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const config = @import("projectconfig.zig");

pub fn sanitize(allocator: Allocator, input: []const u8) ![]u8 {
    var label: std.ArrayList(u8) = .empty;
    defer label.deinit(allocator);
    var hyphen = false;
    for (input) |ch| {
        if (std.ascii.isAlphanumeric(ch)) {
            try label.append(allocator, std.ascii.toLower(ch));
            hyphen = false;
        } else if (label.items.len > 0 and !hyphen) {
            try label.append(allocator, '-');
            hyphen = true;
        }
    }
    const clean = std.mem.trimEnd(u8, label.items, "-");
    if (clean.len <= 63) return allocator.dupe(u8, clean);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(clean, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ std.mem.trimEnd(u8, clean[0..56], "-"), hex[0..6] });
}

fn git(allocator: Allocator, io: Io, cwd: []const u8, args: []const []const u8) !?[]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "git", "-C", cwd });
    try argv.appendSlice(allocator, args);
    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } },
    }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    if (!result.term.success()) return null;
    return try allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \t\r\n"));
}

pub fn readText(allocator: Allocator, io: Io, path: []const u8, max: usize) !?[]u8 {
    const file = Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false }) catch return null;
    defer file.close(io);
    if ((try file.stat(io)).kind != .file) return null;
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(max)) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
}

pub fn inferName(allocator: Allocator, io: Io, start: []const u8) ![]u8 {
    const cwd = try Io.Dir.cwd().realPathFileAlloc(io, if (start.len == 0) "." else start, allocator);
    defer allocator.free(cwd);
    var dir: []const u8 = cwd;
    while (true) {
        if (try config.packageJSON(allocator, io, dir)) |wire| {
            defer wire.deinit();
            if (wire.value == .object) if (wire.value.object.get("name")) |value| {
                if (value == .string and value.string.len > 0) {
                    var name = value.string;
                    if (name[0] == '@') if (std.mem.findScalar(u8, name, '/')) |slash| {
                        name = name[slash + 1 ..];
                    };
                    const clean = try sanitize(allocator, name);
                    if (clean.len > 0) return clean;
                    allocator.free(clean);
                    break;
                }
            };
        }
        const parent = std.fs.path.dirname(dir) orelse break;
        if (std.mem.eql(u8, parent, dir)) break;
        dir = parent;
    }
    if (try git(allocator, io, cwd, &.{ "rev-parse", "--show-toplevel" })) |root| {
        defer allocator.free(root);
        const clean = try sanitize(allocator, std.fs.path.basename(root));
        if (clean.len > 0) return clean;
        allocator.free(clean);
    } else {
        dir = cwd;
        while (true) {
            const path = try std.fs.path.join(allocator, &.{ dir, ".git" });
            defer allocator.free(path);
            const stat = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch null;
            if (stat != null) {
                const clean = try sanitize(allocator, std.fs.path.basename(dir));
                if (clean.len > 0) return clean;
                allocator.free(clean);
                break;
            }
            const parent = std.fs.path.dirname(dir) orelse break;
            if (std.mem.eql(u8, parent, dir)) break;
            dir = parent;
        }
    }
    const clean = try sanitize(allocator, std.fs.path.basename(cwd));
    if (clean.len == 0) {
        allocator.free(clean);
        return error.CannotInferName;
    }
    return clean;
}

fn branchPrefix(allocator: Allocator, branch: []const u8) !?[]u8 {
    if (branch.len == 0 or std.mem.eql(u8, branch, "main") or std.mem.eql(u8, branch, "master") or std.mem.eql(u8, branch, "HEAD")) return null;
    const prefix = try sanitize(allocator, std.fs.path.basename(branch));
    if (prefix.len == 0) {
        allocator.free(prefix);
        return null;
    }
    return prefix;
}

/// Only linked Git worktrees receive a prefix; ordinary feature branches do not.
pub fn worktreePrefix(allocator: Allocator, io: Io, start: []const u8) !?[]u8 {
    const cwd = try Io.Dir.cwd().realPathFileAlloc(io, if (start.len == 0) "." else start, allocator);
    defer allocator.free(cwd);
    // One git process: a linked worktree is exactly one whose git dir differs
    // from the common dir, which also implies more than one worktree exists.
    if (try git(allocator, io, cwd, &.{ "rev-parse", "--git-dir", "--git-common-dir", "--abbrev-ref", "HEAD" })) |out| {
        defer allocator.free(out);
        var lines = std.mem.splitScalar(u8, out, '\n');
        const gd = std.mem.trim(u8, lines.next() orelse return null, " \t\r");
        const cd = std.mem.trim(u8, lines.next() orelse return null, " \t\r");
        const branch = std.mem.trim(u8, lines.next() orelse return null, " \t\r");
        // Extra lines mean a path contained a newline; the fields cannot be trusted.
        if (std.mem.trim(u8, lines.rest(), "\n").len != 0) return null;
        const git_dir = try std.fs.path.resolve(allocator, &.{ cwd, gd });
        defer allocator.free(git_dir);
        const common_dir = try std.fs.path.resolve(allocator, &.{ cwd, cd });
        defer allocator.free(common_dir);
        if (std.mem.eql(u8, git_dir, common_dir)) return null;
        return branchPrefix(allocator, branch);
    }
    var dir: []const u8 = cwd;
    while (true) {
        const path = try std.fs.path.join(allocator, &.{ dir, ".git" });
        defer allocator.free(path);
        const stat = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch null;
        if (stat) |s| {
            if (s.kind != .file) return null;
            const text = (try readText(allocator, io, path, 16 * 1024)) orelse return null;
            defer allocator.free(text);
            const trimmed = std.mem.trim(u8, text, " \t\r\n");
            if (!std.mem.startsWith(u8, trimmed, "gitdir:")) return null;
            const gd = try std.fs.path.resolve(allocator, &.{ dir, std.mem.trim(u8, trimmed[7..], " \t") });
            defer allocator.free(gd);
            const parent = std.fs.path.dirname(gd) orelse return null;
            if (!std.mem.eql(u8, std.fs.path.basename(parent), "worktrees")) return null;
            const head_path = try std.fs.path.join(allocator, &.{ gd, "HEAD" });
            defer allocator.free(head_path);
            const head = (try readText(allocator, io, head_path, 16 * 1024)) orelse return null;
            defer allocator.free(head);
            const ref = std.mem.trim(u8, head, " \t\r\n");
            if (!std.mem.startsWith(u8, ref, "ref: refs/heads/")) return null;
            return branchPrefix(allocator, ref[16..]);
        }
        const parent = std.fs.path.dirname(dir) orelse return null;
        if (std.mem.eql(u8, parent, dir)) return null;
        dir = parent;
    }
}

pub fn applyWorktreePrefix(allocator: Allocator, name: []const u8, prefix: ?[]const u8) ![]u8 {
    if (prefix) |p| return std.fmt.allocPrint(allocator, "{s}.{s}", .{ p, name });
    return allocator.dupe(u8, name);
}
