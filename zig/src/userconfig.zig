//! ~/.dotlocal/config.json: user defaults below flags and DOTLOCAL_*
//! variables. Every key is optional.
const std = @import("std");
const Io = std.Io;
const A = std.mem.Allocator;

pub const Config = struct {
    auto_update: ?bool = null,
    channel: ?[]const u8 = null,
    pin: ?[]const u8 = null,
    tld: ?[]const u8 = null,
    https: ?bool = null,
    port: ?u16 = null,
    wildcard: ?bool = null,
    lan: ?bool = null,
    lan_ip: ?[]const u8 = null,
    tailscale: ?bool = null,
    funnel: ?bool = null,
    ngrok: ?bool = null,
    state_dir: ?[]const u8 = null,
    runner_state: ?[]const u8 = null,
    socket: ?[]const u8 = null,
};

/// Config key → environment variable it defaults.
pub const env_names = .{
    .{ "auto_update", "DOTLOCAL_AUTO_UPDATE" }, .{ "channel", "DOTLOCAL_CHANNEL" },
    .{ "pin", "DOTLOCAL_PIN" },                 .{ "tld", "DOTLOCAL_TLD" },
    .{ "https", "DOTLOCAL_HTTPS" },             .{ "port", "DOTLOCAL_PORT" },
    .{ "wildcard", "DOTLOCAL_WILDCARD" },       .{ "lan", "DOTLOCAL_LAN" },
    .{ "lan_ip", "DOTLOCAL_LAN_IP" },           .{ "tailscale", "DOTLOCAL_TAILSCALE" },
    .{ "funnel", "DOTLOCAL_FUNNEL" },           .{ "ngrok", "DOTLOCAL_NGROK" },
    .{ "state_dir", "DOTLOCAL_STATE_DIR" },     .{ "runner_state", "DOTLOCAL_RUNNER_STATE" },
    .{ "socket", "DOTLOCAL_SOCKET" },
};

pub fn defaultPath(a: A, environ: *const std.process.Environ.Map) ![]u8 {
    const home = environ.get("HOME") orelse return error.HomeMissing;
    return std.fs.path.join(a, &.{ home, ".dotlocal", "config.json" });
}

pub fn load(a: A, io: Io, path: []const u8) !std.json.Parsed(Config) {
    const bytes = readPrivate(a, io, path) catch |err| switch (err) {
        error.FileNotFound => return std.json.parseFromSlice(Config, a, "{}", .{}),
        else => return err,
    };
    defer a.free(bytes);
    const parsed = std.json.parseFromSlice(Config, a, bytes, .{ .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error", .allocate = .alloc_always }) catch |err| return switch (err) {
        error.UnknownField => error.UnknownConfigKey,
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidConfigFile,
    };
    errdefer parsed.deinit();
    try validate(parsed.value);
    return parsed;
}

fn validate(c: Config) !void {
    if (c.channel) |v| if (std.meta.stringToEnum(enum { stable, nightly }, v) == null) return error.InvalidConfigValue;
    if (c.pin) |v| _ = std.SemanticVersion.parse(v) catch return error.InvalidConfigValue;
    if (c.port) |v| if (v == 0) return error.InvalidConfigValue;
    if (c.tld) |v| if (v.len == 0 or v.len > 63) return error.InvalidConfigValue;
    inline for (.{ "state_dir", "runner_state", "socket" }) |field| if (@field(c, field)) |v| {
        if (!std.fs.path.isAbsolute(v)) return error.InvalidConfigValue;
    };
}

fn readPrivate(a: A, io: Io, path: []const u8) ![]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    @import("process.zig").validateUserFile(file.handle) catch |err| return switch (err) {
        error.UnsafeStateFile => error.UnsafeConfigFile,
        else => err,
    };
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(a, .limited(64 * 1024));
}

/// Parses VALUE for KEY, rewrites the file atomically (0600 temp + rename).
pub fn set(a: A, io: Io, path: []const u8, key: []const u8, value: []const u8) !void {
    var parsed = try load(a, io, path);
    defer parsed.deinit();
    var config = parsed.value;
    var matched = false;
    const info = @typeInfo(Config).@"struct";
    inline for (info.field_names, info.field_types) |name, T| if (std.mem.eql(u8, name, key)) {
        matched = true;
        @field(config, name) = try parseValue(@typeInfo(T).optional.child, value);
    };
    if (!matched) return error.UnknownConfigKey;
    try validate(config);
    try save(a, io, path, config);
}

pub fn unset(a: A, io: Io, path: []const u8, key: []const u8) !void {
    var parsed = try load(a, io, path);
    defer parsed.deinit();
    var config = parsed.value;
    var matched = false;
    inline for (@typeInfo(Config).@"struct".field_names) |name| if (std.mem.eql(u8, name, key)) {
        matched = true;
        @field(config, name) = null;
    };
    if (!matched) return error.UnknownConfigKey;
    try save(a, io, path, config);
}

fn parseValue(comptime T: type, text: []const u8) !T {
    return switch (T) {
        bool => if (std.mem.eql(u8, text, "true")) true else if (std.mem.eql(u8, text, "false")) false else error.InvalidConfigValue,
        u16 => std.fmt.parseInt(u16, text, 10) catch error.InvalidConfigValue,
        []const u8 => text,
        else => @compileError("unsupported config type"),
    };
}

fn save(a: A, io: Io, path: []const u8, config: Config) !void {
    const json = try std.json.Stringify.valueAlloc(a, config, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
    defer a.free(json);
    const dir_path = std.fs.path.dirname(path) orelse return error.InvalidConfigPath;
    try Io.Dir.cwd().createDirPath(io, dir_path);
    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    var atomic = try dir.createFileAtomic(io, std.fs.path.basename(path), .{ .permissions = .fromMode(0o600), .replace = true });
    defer atomic.deinit(io);
    try atomic.file.setPermissions(io, .fromMode(0o600));
    try atomic.file.writeStreamingAll(io, json);
    try atomic.file.writeStreamingAll(io, "\n");
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Fills DOTLOCAL_* variables that are not already set.
pub fn applyDefaults(config: Config, env: *std.process.Environ.Map) !void {
    inline for (env_names) |pair| if (@field(config, pair[0])) |value| {
        if (env.get(pair[1]) == null) {
            var buffer: [16]u8 = undefined;
            const text = switch (@TypeOf(value)) {
                bool => if (value) "1" else "0",
                u16 => try std.fmt.bufPrint(&buffer, "{d}", .{value}),
                else => value,
            };
            try env.put(pair[1], text);
        }
    };
}
