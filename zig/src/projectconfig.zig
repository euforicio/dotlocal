const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
pub const filename = "dotlocal.json";
pub const AppConfig = struct {
    name: []const u8 = "",
    script: []const u8 = "",
    appPort: u16 = 0,
    proxy: bool = true,
    proxy_set: bool = false,
};
pub const Config = struct {
    name: []const u8 = "",
    script: []const u8 = "",
    command: []const []const u8 = &.{},
    appPort: u16 = 0,
    proxy: bool = true,
    proxy_set: bool = false,
    env: std.json.ArrayHashMap([]const u8) = .{},
    apps: ?std.json.ArrayHashMap(AppConfig) = null,
    turbo: bool = false,
    turbo_set: bool = false,
};

pub fn validateEnvironmentKey(key: []const u8) !void {
    if (key.len == 0 or key.len > 255) return error.InvalidEnvironmentKey;
    for (key, 0..) |byte, index| {
        if (std.ascii.isAlphabetic(byte) or byte == '_' or (index > 0 and std.ascii.isDigit(byte))) continue;
        return error.InvalidEnvironmentKey;
    }
}

pub fn validate(config: Config) !void {
    if (config.command.len > 256 or (config.command.len > 0 and config.command[0].len == 0)) return error.InvalidCommand;
    for (config.command) |arg| if (arg.len > 32 * 1024 or std.mem.findScalar(u8, arg, 0) != null) return error.InvalidArgument;
    if (config.env.map.count() > 256) return error.TooManyEnvironmentEntries;
    var it = config.env.map.iterator();
    while (it.next()) |entry| {
        try validateEnvironmentKey(entry.key_ptr.*);
        const value = entry.value_ptr.*;
        if (value.len > 32 * 1024 or std.mem.findScalar(u8, value, 0) != null) return error.InvalidEnvironmentValue;
    }
}

pub fn normalizeName(allocator: Allocator, input: []const u8, tld: []const u8) ![]u8 {
    return @import("routes.zig").normalizeName(allocator, input, tld);
}

fn validateFields(value: std.json.Value, top: bool) !void {
    if (value != .object) return error.InvalidConfig;
    const fields = value.object;
    for ([_][]const u8{ "name", "script" }) |key| if (fields.get(key)) |v| {
        if (v != .string or std.mem.trim(u8, v.string, " \t\r\n").len == 0 or std.mem.findScalar(u8, v.string, 0) != null) return error.InvalidConfig;
    };
    if (fields.get("appPort")) |v| switch (v) {
        .integer => |port| if (port < 1 or port > 65535) return error.InvalidPort,
        .float => |port| if (!(port >= 1 and port <= 65535) or @trunc(port) != port) return error.InvalidPort,
        else => return error.InvalidPort,
    };
    if (fields.get("proxy")) |v| if (v != .bool) return error.InvalidConfig;
    if (top) {
        if (fields.get("turbo")) |v| if (v != .bool) return error.InvalidConfig;
        if (fields.get("apps")) |v| {
            if (v != .object) return error.InvalidConfig;
            var it = v.object.iterator();
            while (it.next()) |entry| try validateFields(entry.value_ptr.*, false);
        }
    }
}

/// Bounded, no-follow metadata read. Missing files return null; malformed JSON is an error.
pub fn readJSON(allocator: Allocator, io: Io, path: []const u8) !?std.json.Parsed(std.json.Value) {
    if (!std.fs.path.isAbsolute(path)) return error.RelativeConfigPath;
    const file = Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    if ((try file.stat(io)).kind != .file) return error.InvalidConfigFile;
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const data = try reader.interface.allocRemaining(allocator, .limited(1024 * 1024));
    defer allocator.free(data);
    return try std.json.parseFromSlice(std.json.Value, allocator, data, .{ .allocate = .alloc_always });
}

pub fn packageJSON(allocator: Allocator, io: Io, directory: []const u8) !?std.json.Parsed(std.json.Value) {
    const path = try std.fs.path.join(allocator, &.{ directory, "package.json" });
    defer allocator.free(path);
    return readJSON(allocator, io, path) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
}

fn fromValue(allocator: Allocator, value: std.json.Value) !std.json.Parsed(Config) {
    try validateFields(value, true);
    // ArrayHashMap.jsonParseFromValue borrows keys; parse text to own every key.
    const data = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(data);
    var parsed = try std.json.parseFromSlice(Config, allocator, data, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
    errdefer parsed.deinit();
    try validate(parsed.value);
    parsed.value.proxy_set = value.object.contains("proxy");
    parsed.value.turbo_set = value.object.contains("turbo");
    if (parsed.value.apps) |*apps| {
        const entries = value.object.get("apps").?.object;
        var it = apps.map.iterator();
        while (it.next()) |entry| entry.value_ptr.proxy_set = entries.get(entry.key_ptr.*).?.object.contains("proxy");
    }
    if (parsed.value.name.len > 0) parsed.value.name = try normalizeName(parsed.arena.allocator(), parsed.value.name, @import("routes.zig").default_tld);
    return parsed;
}

pub fn load(allocator: Allocator, io: Io, path: []const u8) !std.json.Parsed(Config) {
    if (!std.fs.path.isAbsolute(path)) return error.RelativeConfigPath;
    const wire = (try readJSON(allocator, io, path)) orelse return error.FileNotFound;
    defer wire.deinit();
    if (!std.mem.eql(u8, std.fs.path.basename(path), "package.json")) return fromValue(allocator, wire.value);
    if (wire.value != .object) return error.InvalidConfig;
    const value = wire.value.object.get("dotlocal") orelse return error.NoProjectConfig;
    if (value == .string) {
        const trimmed = std.mem.trim(u8, value.string, " \t\r\n");
        if (trimmed.len == 0) return error.NoProjectConfig;
        var parsed = try std.json.parseFromSlice(Config, allocator, "{}", .{ .allocate = .alloc_always });
        errdefer parsed.deinit();
        parsed.value.name = try normalizeName(parsed.arena.allocator(), trimmed, @import("routes.zig").default_tld);
        return parsed;
    }
    if (value == .null) return error.NoProjectConfig;
    return fromValue(allocator, value);
}

/// Source-compatible current-directory configuration, with package.json fallback.
pub fn loadCurrent(allocator: Allocator, io: Io, directory: []const u8) !?std.json.Parsed(Config) {
    const path = try std.fs.path.join(allocator, &.{ directory, filename });
    defer allocator.free(path);
    return load(allocator, io, path) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const package_path = try std.fs.path.join(allocator, &.{ directory, "package.json" });
            defer allocator.free(package_path);
            break :blk load(allocator, io, package_path) catch |package_err| switch (package_err) {
                error.FileNotFound, error.NoProjectConfig, error.SyntaxError, error.UnexpectedToken, error.UnexpectedEndOfInput => null,
                else => return package_err,
            };
        },
        else => return err,
    };
}

/// Preserve the generic runner's ancestor configuration extension.
pub fn find(allocator: Allocator, io: Io, start: []const u8) !?[]u8 {
    const real = try Io.Dir.cwd().realPathFileAlloc(io, if (start.len == 0) "." else start, allocator);
    defer allocator.free(real);
    var directory: []const u8 = real;
    while (true) {
        const candidate = try std.fs.path.join(allocator, &.{ directory, filename });
        if (readJSON(allocator, io, candidate) catch |err| {
            allocator.free(candidate);
            return err;
        }) |wire| {
            wire.deinit();
            return candidate;
        }
        allocator.free(candidate);
        if (try packageJSON(allocator, io, directory)) |wire| {
            defer wire.deinit();
            if (wire.value == .object) if (wire.value.object.get("dotlocal")) |v| {
                if (v != .null and (v != .string or std.mem.trim(u8, v.string, " \t\r\n").len > 0)) return try std.fs.path.join(allocator, &.{ directory, "package.json" });
            };
        }
        const parent = std.fs.path.dirname(directory) orelse return null;
        if (std.mem.eql(u8, parent, directory)) return null;
        directory = parent;
    }
}

pub fn resolveAppConfig(config: Config, config_dir: []const u8, package_dir: []const u8) AppConfig {
    const apps = config.apps orelse return .{ .name = config.name, .script = config.script, .appPort = config.appPort, .proxy = config.proxy, .proxy_set = config.proxy_set };
    if (!std.fs.path.isAbsolute(config_dir) or !std.fs.path.isAbsolute(package_dir) or !std.mem.startsWith(u8, package_dir, config_dir)) return .{};
    const offset = config_dir.len + @intFromBool(!std.mem.endsWith(u8, config_dir, "/"));
    if (package_dir.len <= offset or (offset > config_dir.len and package_dir[config_dir.len] != '/')) return .{};
    var relative = package_dir[offset..];
    var segments = std.mem.splitScalar(u8, relative, '/');
    while (segments.next()) |segment| if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return .{};
    while (relative.len > 0) {
        if (apps.map.get(relative)) |app| return app;
        relative = std.fs.path.dirname(relative) orelse return .{};
    }
    return .{};
}

/// Closest metadata wins: package fields override the matching workspace app fields.
pub fn resolveEffectiveAppConfig(config: Config, config_dir: []const u8, package_dir: []const u8, package_config: ?Config) AppConfig {
    var result = resolveAppConfig(config, config_dir, package_dir);
    if (package_config) |package| {
        if (package.name.len > 0) result.name = package.name;
        if (package.script.len > 0) result.script = package.script;
        if (package.appPort != 0) result.appPort = package.appPort;
        if (package.proxy_set or !package.proxy) {
            result.proxy = package.proxy;
            result.proxy_set = true;
        }
    }
    return result;
}

pub fn detectPackageManager(allocator: Allocator, io: Io, cwd: []const u8) ![]const u8 {
    var directory = cwd;
    while (true) {
        if (try packageJSON(allocator, io, directory)) |wire| {
            defer wire.deinit();
            if (wire.value == .object) if (wire.value.object.get("packageManager")) |v| {
                if (v == .string) {
                    const name = v.string[0 .. std.mem.findScalar(u8, v.string, '@') orelse v.string.len];
                    for ([_][]const u8{ "npm", "pnpm", "yarn", "bun" }) |pm| if (std.mem.eql(u8, name, pm)) return pm;
                }
            };
        }
        const locks = [_][]const u8{ "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "package-lock.json" };
        const managers = [_][]const u8{ "pnpm", "yarn", "bun", "bun", "npm" };
        for (locks, managers) |lock, manager| {
            const path = try std.fs.path.join(allocator, &.{ directory, lock });
            defer allocator.free(path);
            const file = Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false, .allow_directory = false }) catch continue;
            file.close(io);
            return manager;
        }
        const parent = std.fs.path.dirname(directory) orelse return "npm";
        if (std.mem.eql(u8, parent, directory)) return "npm";
        directory = parent;
    }
}

pub fn resolveScriptRaw(allocator: Allocator, io: Io, cwd: []const u8, script: []const u8) !?[]u8 {
    const wire = (try packageJSON(allocator, io, cwd)) orelse return null;
    defer wire.deinit();
    if (wire.value != .object) return null;
    const scripts = wire.value.object.get("scripts") orelse return null;
    if (scripts != .object) return null;
    const value = scripts.object.get(script) orelse return null;
    if (value != .string) return null;
    return try allocator.dupe(u8, value.string);
}

/// Returns an owned argv whose slice and strings the caller frees, or null.
pub fn resolveCommand(allocator: Allocator, io: Io, cwd: []const u8, script: []const u8) !?[]const []const u8 {
    const name = if (script.len == 0) "dev" else script;
    const raw = (try resolveScriptRaw(allocator, io, cwd, name)) orelse return null;
    defer allocator.free(raw);
    const argv = try allocator.alloc([]const u8, 3);
    errdefer allocator.free(argv);
    var filled: usize = 0;
    errdefer for (argv[0..filled]) |arg| allocator.free(arg);
    for ([_][]const u8{ try detectPackageManager(allocator, io, cwd), "run", name }) |arg| {
        argv[filled] = try allocator.dupe(u8, arg);
        filled += 1;
    }
    return argv;
}

pub fn splitCommand(allocator: Allocator, command: []const u8) ![]const []const u8 {
    var args: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (args.items) |arg| allocator.free(arg);
        args.deinit(allocator);
    }
    var word: std.ArrayList(u8) = .empty;
    defer word.deinit(allocator);
    var single = false;
    var double = false;
    var escaped = false;
    for (command) |ch| {
        if (escaped) {
            try word.append(allocator, ch);
            escaped = false;
        } else if (ch == '\\' and !single) escaped = true else if (ch == '\'' and !double) single = !single else if (ch == '"' and !single) double = !double else if (std.ascii.isWhitespace(ch) and !single and !double) {
            if (word.items.len > 0) {
                try args.append(allocator, try allocator.dupe(u8, word.items));
                word.clearRetainingCapacity();
            }
        } else try word.append(allocator, ch);
    }
    if (word.items.len > 0) try args.append(allocator, try allocator.dupe(u8, word.items));
    return args.toOwnedSlice(allocator);
}

pub fn isServerCommand(argv: []const []const u8) bool {
    if (argv.len == 0) return false;
    const base = std.fs.path.basename(argv[0]);
    for ([_][]const u8{ "tsup", "tsc", "esbuild", "rollup", "babel", "swc", "unbuild", "pkgroll", "ncc", "microbundle" }) |build| if (std.mem.eql(u8, base, build)) return false;
    return true;
}

pub fn resolveName(allocator: Allocator, io: Io, explicit: []const u8, configured: []const u8, working_directory: []const u8) ![]u8 {
    if (explicit.len > 0) return normalizeName(allocator, explicit, @import("routes.zig").default_tld);
    if (configured.len > 0) return normalizeName(allocator, configured, @import("routes.zig").default_tld);
    const name = try @import("auto.zig").inferName(allocator, io, working_directory);
    defer allocator.free(name);
    return normalizeName(allocator, name, @import("routes.zig").default_tld);
}

test "strict config and portable environment" {
    try std.testing.expectError(error.InvalidEnvironmentKey, validateEnvironmentKey("9BAD"));
    try validateEnvironmentKey("_OK9");
    const name = try normalizeName(std.testing.allocator, " Sample-App ", @import("routes.zig").default_tld);
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("sample-app.local", name);
    try std.testing.expectError(error.DuplicateField, std.json.parseFromSlice(Config, std.testing.allocator, "{\"command\":[\"true\"],\"proxy\":true,\"proxy\":false}", .{}));
}
