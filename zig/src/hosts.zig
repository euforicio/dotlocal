const file_stat = @import("file_stat.zig");
const std = @import("std");
const c = @import("native");
const process = @import("process.zig");
const A = std.mem.Allocator;
pub const begin_marker = "# BEGIN DOTLOCAL MANAGED HOSTS";
pub const end_marker = "# END DOTLOCAL MANAGED HOSTS";
pub const Config = struct { path: []const u8 = "/etc/hosts", uid: u32 = 0, gid: u32 = 0, mode: u32 = 0o644, suffixes: []const []const u8 = &.{@import("routes.zig").default_tld} };
pub const Plan = struct {
    path: []u8,
    uid: u32,
    gid: u32,
    mode: u32,
    before_sha256: [32]u8,
    after_sha256: [32]u8,
    before_bytes: usize,
    desired: []u8,
    names: [][]const u8,
    suffixes: [][]const u8,
    changed: bool,
    pub fn deinit(self: Plan, a: A) void {
        a.free(self.path);
        a.free(self.desired);
        for (self.names) |n| a.free(n);
        a.free(self.names);
        for (self.suffixes) |suffix| a.free(suffix);
        a.free(self.suffixes);
    }
};
pub fn validateName(name: []const u8, suffix: []const u8) !void {
    if (name.len > 253 or !std.mem.endsWith(u8, name, suffix) or name.len <= suffix.len) return error.InvalidName;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return error.InvalidName;
        for (label) |ch| if (!(ch >= 'a' and ch <= 'z') and !std.ascii.isDigit(ch) and ch != '-') return error.InvalidName;
    }
}
pub fn normalizeName(a: A, name: []const u8) ![]u8 {
    const raw = if (std.mem.endsWith(u8, name, ".")) name[0 .. name.len - 1] else name;
    const normalized = try std.ascii.allocLowerString(a, raw);
    errdefer a.free(normalized);
    try validateName(normalized, @import("routes.zig").default_tld);
    return normalized;
}
/// Expand one logical route across explicit DNS suffixes; validate every resulting name.
pub fn expandNames(a: A, names: []const []const u8, suffixes: []const []const u8) ![][]const u8 {
    if (suffixes.len == 0 or suffixes.len > 32 or names.len > 4096) return error.InvalidSuffixes;
    var normalized_suffixes: std.ArrayList([]const u8) = .empty;
    defer {
        for (normalized_suffixes.items) |suffix| a.free(suffix);
        normalized_suffixes.deinit(a);
    }
    for (suffixes) |suffix| {
        const normalized = try @import("routes.zig").normalizeTld(a, suffix);
        errdefer a.free(normalized);
        try normalized_suffixes.append(a, normalized);
    }
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |name| a.free(name);
        out.deinit(a);
    }
    for (names) |input| {
        const raw = if (std.mem.endsWith(u8, input, ".")) input[0 .. input.len - 1] else input;
        const name = try std.ascii.allocLowerString(a, raw);
        defer a.free(name);
        // Canonical route records use the first (primary) suffix. Prefer it
        // when suffixes overlap so nested prefixes retain their full identity.
        const primary = normalized_suffixes.items[0];
        var matched: ?[]const u8 = if (std.mem.endsWith(u8, name, primary) and name.len > primary.len) primary else null;
        if (matched == null) for (normalized_suffixes.items[1..]) |suffix| {
            if (std.mem.endsWith(u8, name, suffix) and name.len > suffix.len and (matched == null or suffix.len > matched.?.len)) matched = suffix;
        };
        const suffix = matched orelse return error.InvalidName;
        try validateName(name, suffix);
        const prefix = name[0 .. name.len - suffix.len];
        for (normalized_suffixes.items) |target| {
            if (out.items.len >= 4096) return error.InvalidHostsFile;
            const alias = try std.mem.concat(a, u8, &.{ prefix, target });
            errdefer a.free(alias);
            try validateName(alias, target);
            try out.append(a, alias);
        }
    }
    if (out.items.len > 4096) return error.InvalidHostsFile;
    return out.toOwnedSlice(a);
}
pub fn render(a: A, current: []const u8, names: []const []const u8) ![]u8 {
    return renderWithSuffixes(a, current, names, &.{@import("routes.zig").default_tld});
}
pub fn renderWithSuffixes(a: A, current: []const u8, names: []const []const u8, suffixes: []const []const u8) ![]u8 {
    if (current.len > 4 << 20 or std.mem.findScalar(u8, current, 0) != null or names.len > 4096) return error.InvalidHostsFile;
    var start: ?usize = null;
    var finish: ?usize = null;
    var offset: usize = 0;
    while (offset < current.len) {
        const next = if (std.mem.findScalar(u8, current[offset..], '\n')) |n| offset + n + 1 else current.len;
        const line = std.mem.trimEnd(u8, current[offset..next], "\r\n");
        if (std.mem.eql(u8, line, begin_marker)) {
            if (start != null) return error.MalformedManagedBlock;
            start = offset;
        }
        if (std.mem.eql(u8, line, end_marker)) {
            if (start == null or finish != null) return error.MalformedManagedBlock;
            finish = next;
        }
        offset = next;
    }
    if ((start == null) != (finish == null)) return error.MalformedManagedBlock;
    const normalized = try expandNames(a, names, suffixes);
    defer {
        for (normalized) |name| a.free(name);
        a.free(normalized);
    }
    std.mem.sort([]const u8, normalized, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.less);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, current[0 .. start orelse current.len]);
    if (normalized.len > 0) {
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.append(a, '\n');
        try out.appendSlice(a, begin_marker ++ "\n# Generated by dotlocal; use the dotlocal hosts operation to change this block.\n");
        var previous: ?[]const u8 = null;
        for (normalized) |name| {
            if (previous) |p| if (std.mem.eql(u8, p, name)) continue;
            try out.print(a, "127.0.0.1\t{s}\n::1\t{s}\n", .{ name, name });
            previous = name;
        }
        try out.appendSlice(a, end_marker ++ "\n");
    }
    if (finish) |end| try out.appendSlice(a, current[end..]);
    if (out.items.len > 4 << 20) return error.InvalidHostsFile;
    return out.toOwnedSlice(a);
}
fn digest(bytes: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}
const Open = struct {
    parent: c_int,
    file: c_int,
    stat: c.struct_stat,
    base: [:0]u8,
    fn close(self: Open, a: A) void {
        _ = c.close(self.file);
        _ = c.close(self.parent);
        a.free(self.base);
    }
};
fn secureOpen(a: A, config: Config) !Open {
    if (!std.fs.path.isAbsolute(config.path) or std.mem.findScalar(u8, config.path, 0) != null or (config.mode & 0o022) != 0) return error.UnsafeHostsConfiguration;
    var parts = std.mem.splitScalar(u8, config.path, '/');
    while (parts.next()) |p| if (std.mem.eql(u8, p, "..") or std.mem.eql(u8, p, ".")) return error.UnsafeHostsConfiguration;
    const dirname = std.fs.path.dirname(config.path) orelse return error.UnsafeHostsConfiguration;
    const dir = try a.dupeSentinel(u8, dirname, 0);
    defer a.free(dir);
    const base = try a.dupeSentinel(u8, std.fs.path.basename(config.path), 0);
    errdefer a.free(base);
    const parent = c.open(dir, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    if (parent < 0) return error.HostsOpenFailed;
    errdefer _ = c.close(parent);
    var parentstat: c.struct_stat = undefined;
    if (file_stat.fstat(parent, &parentstat) != 0 or parentstat.st_uid != config.uid or (parentstat.st_mode & 0o022) != 0) return error.UnsafeHostsParent;
    const file = c.openat(parent, base, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (file < 0) return error.HostsOpenFailed;
    errdefer _ = c.close(file);
    var stat: c.struct_stat = undefined;
    if (file_stat.fstat(file, &stat) != 0 or (stat.st_mode & c.S_IFMT) != c.S_IFREG or (stat.st_mode & 0o777) != config.mode or stat.st_uid != config.uid or stat.st_gid != config.gid) return error.UnsafeHostsFile;
    return .{ .parent = parent, .file = file, .stat = stat, .base = base };
}
fn read(a: A, fd: c_int) ![]u8 {
    if (c.lseek(fd, 0, c.SEEK_SET) < 0) return error.HostsReadFailed;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = c.read(fd, &buf, buf.len);
        if (n < 0) return error.HostsReadFailed;
        if (n == 0) break;
        try out.appendSlice(a, buf[0..@intCast(n)]);
        if (out.items.len > 4 << 20) return error.InvalidHostsFile;
    }
    return out.toOwnedSlice(a);
}
pub fn plan(a: A, io: std.Io, config: Config, names: []const []const u8) !Plan {
    _ = io;
    const opened = try secureOpen(a, config);
    defer opened.close(a);
    const before = try read(a, opened.file);
    defer a.free(before);
    const desired = try renderWithSuffixes(a, before, names, config.suffixes);
    errdefer a.free(desired);
    const path = try a.dupe(u8, config.path);
    errdefer a.free(path);
    const copy = try a.alloc([]const u8, names.len);
    var count: usize = 0;
    errdefer {
        for (copy[0..count]) |n| a.free(n);
        a.free(copy);
    }
    for (names) |n| {
        copy[count] = try a.dupe(u8, n);
        count += 1;
    }
    const suffix_copy = try a.alloc([]const u8, config.suffixes.len);
    var suffix_count: usize = 0;
    errdefer {
        for (suffix_copy[0..suffix_count]) |suffix| a.free(suffix);
        a.free(suffix_copy);
    }
    for (config.suffixes) |suffix| {
        suffix_copy[suffix_count] = try a.dupe(u8, suffix);
        suffix_count += 1;
    }
    return .{ .path = path, .uid = config.uid, .gid = config.gid, .mode = config.mode, .suffixes = suffix_copy, .before_sha256 = digest(before), .after_sha256 = digest(desired), .before_bytes = before.len, .desired = desired, .names = copy, .changed = !std.mem.eql(u8, before, desired) };
}
pub fn apply(a: A, io: std.Io, config: Config, p: Plan) !bool {
    if (c.geteuid() != 0 and c.geteuid() != config.uid) return error.PrivilegeRequired;
    if (!std.mem.eql(u8, p.path, config.path) or p.uid != config.uid or p.gid != config.gid or p.mode != config.mode or !std.mem.eql(u8, &p.after_sha256, &digest(p.desired))) return error.InvalidPlan;
    const opened = try secureOpen(a, config);
    defer opened.close(a);
    const lock = c.openat(opened.parent, ".dotlocal-hosts.lock", c.O_RDWR | c.O_CREAT | c.O_NOFOLLOW | c.O_CLOEXEC, @as(c_uint, 0o600));
    if (lock < 0) return error.HostsLockFailed;
    defer _ = c.close(lock);
    var lockstat: c.struct_stat = undefined;
    if (file_stat.fstat(lock, &lockstat) != 0 or lockstat.st_uid != config.uid or lockstat.st_gid != config.gid or (lockstat.st_mode & 0o777) != 0o600 or (lockstat.st_mode & c.S_IFMT) != c.S_IFREG) return error.UnsafeHostsLock;
    if (c.flock(lock, c.LOCK_EX) != 0) return error.HostsLockFailed;
    var current_lock: c.struct_stat = undefined;
    var current_file: c.struct_stat = undefined;
    if (file_stat.fstatat(opened.parent, ".dotlocal-hosts.lock", &current_lock, c.AT_SYMLINK_NOFOLLOW) != 0 or current_lock.st_dev != lockstat.st_dev or current_lock.st_ino != lockstat.st_ino) return error.UnsafeHostsLock;
    if (file_stat.fstatat(opened.parent, opened.base, &current_file, c.AT_SYMLINK_NOFOLLOW) != 0 or current_file.st_dev != opened.stat.st_dev or current_file.st_ino != opened.stat.st_ino or current_file.st_uid != config.uid or current_file.st_gid != config.gid or (current_file.st_mode & 0o777) != config.mode) return error.StalePlan;

    const before = try read(a, opened.file);
    defer a.free(before);
    if (before.len != p.before_bytes or !std.mem.eql(u8, &digest(before), &p.before_sha256)) return error.StalePlan;
    if (p.suffixes.len != config.suffixes.len) return error.InvalidPlan;
    for (p.suffixes, config.suffixes) |actual, wanted| if (!std.mem.eql(u8, actual, wanted)) return error.InvalidPlan;
    const expected = try renderWithSuffixes(a, before, p.names, config.suffixes);
    defer a.free(expected);
    if (!std.mem.eql(u8, expected, p.desired)) return error.InvalidPlan;
    if (std.mem.eql(u8, before, p.desired)) return false;
    // Exclusive creation of a random name never follows or reuses a staging path.
    var name: [64]u8 = undefined;
    const staged = process.createStaging(io, opened.parent, ".dotlocal-hosts-", &name) catch return error.HostsWriteFailed;
    const fd = staged.fd;
    const temp = staged.name;
    defer _ = c.close(fd);
    defer _ = c.unlinkat(opened.parent, temp, 0);
    if (c.fchown(fd, config.uid, config.gid) != 0 or c.fchmod(fd, @intCast(config.mode)) != 0) return error.HostsWriteFailed;
    process.writeAll(fd, p.desired) catch return error.HostsWriteFailed;
    if (c.fsync(fd) != 0) return error.HostsWriteFailed;
    var latest: c.struct_stat = undefined;
    if (file_stat.fstatat(opened.parent, opened.base, &latest, c.AT_SYMLINK_NOFOLLOW) != 0 or latest.st_dev != opened.stat.st_dev or latest.st_ino != opened.stat.st_ino) return error.StalePlan;
    const content = try read(a, opened.file);
    defer a.free(content);
    if (!std.mem.eql(u8, &digest(content), &p.before_sha256)) return error.StalePlan;
    if (c.renameat(opened.parent, temp, opened.parent, opened.base) != 0 or c.fsync(opened.parent) != 0) return error.HostsWriteFailed;
    return true;
}
