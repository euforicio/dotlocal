const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("projectconfig.zig");
const Spec = struct {
    strict: bool = false,
    servers: []const []const u8,
    default_server: bool = false,
    root_server: bool = false,
    values: ?[]const []const u8 = null,
};
fn contains(values: []const []const u8, key: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, key)) return true;
    return false;
}
fn spec(name: []const u8) ?Spec {
    if (std.mem.eql(u8, name, "vite")) return .{ .strict = true, .servers = &.{ "dev", "serve", "preview" }, .default_server = true, .root_server = true, .values = &.{ "--assetsDir", "--assetsInlineLimit", "--base", "--configLoader", "--host", "--manifest", "--minify", "--open", "--outDir", "--port", "--sourcemap", "--ssr", "--ssrManifest", "--target", "-c", "--config", "-d", "--debug", "-f", "--filter", "-l", "--logLevel", "-m", "--mode" } };
    if (contains(&.{ "vp", "react-router" }, name)) return .{ .strict = true, .servers = &.{"dev"} };
    if (std.mem.eql(u8, name, "rsbuild")) return .{ .servers = &.{ "dev", "preview" }, .default_server = true, .values = &.{ "--base", "--config-loader", "--dist-path", "--env-dir", "--env-mode", "--environment", "--host", "--log-level", "--output", "--port", "-c", "--config", "-m", "--mode", "-o", "--open", "-r", "--root" } };
    if (std.mem.eql(u8, name, "astro")) return .{ .servers = &.{ "dev", "preview" } };
    if (std.mem.eql(u8, name, "ng")) return .{ .servers = &.{ "serve", "dev", "s" } };
    if (std.mem.eql(u8, name, "react-native")) return .{ .servers = &.{"start"} };
    if (std.mem.eql(u8, name, "expo")) return .{ .servers = &.{ "start", "serve" }, .default_server = true };
    return null;
}
const Invocation = struct { name: []const u8, framework: Spec, args: []const []const u8, insertion: usize };
fn skipRunnerOptions(argv: []const []const u8, index: *usize, values: []const []const u8) void {
    while (index.* < argv.len and std.mem.startsWith(u8, argv[index.*], "-")) {
        const option = argv[index.*];
        index.* += 1;
        if (std.mem.eql(u8, option, "--")) break;
        if (std.mem.findScalar(u8, option, '=') == null and contains(values, option)) index.* += 1;
    }
}
fn invocation(argv: []const []const u8) ?Invocation {
    if (argv.len == 0) return null;
    const first = std.fs.path.basename(argv[0]);
    var index: usize = 0;
    if (spec(first) == null) {
        var values: []const []const u8 = &.{};
        var subcommands: []const []const u8 = &.{};
        if (std.mem.eql(u8, first, "npx")) values = &.{ "-c", "--call", "-p", "--package", "-w", "--workspace", "--allow-scripts" } else if (std.mem.eql(u8, first, "pnpx")) values = &.{ "-p", "--package" } else if (contains(&.{ "yarn", "pnpm" }, first)) subcommands = &.{ "dlx", "exec" } else if (!std.mem.eql(u8, first, "bunx")) return null;
        index = 1;
        skipRunnerOptions(argv, &index, values);
        if (index >= argv.len) return null;
        if (contains(subcommands, argv[index])) {
            index += 1;
            skipRunnerOptions(argv, &index, values);
        }
    }
    if (index >= argv.len) return null;
    const name = std.fs.path.basename(argv[index]);
    const framework = spec(name) orelse return null;
    var end = index + 1;
    while (end < argv.len and !std.mem.eql(u8, argv[end], "--")) : (end += 1) {}
    return .{ .name = name, .framework = framework, .args = argv[index + 1 .. end], .insertion = end };
}
fn server(inv: Invocation) bool {
    var i: usize = 0;
    while (i < inv.args.len) : (i += 1) {
        const arg = inv.args[i];
        if (!std.mem.startsWith(u8, arg, "-")) {
            if (contains(inv.framework.servers, arg)) return true;
            if (std.mem.eql(u8, inv.name, "vite") and contains(&.{ "build", "optimize" }, arg)) return false;
            return inv.framework.root_server;
        }
        if (std.mem.findScalar(u8, arg, '=') != null) continue;
        if (inv.framework.values) |values| {
            if (contains(values, arg)) i += 1;
        } else return false;
    }
    return inv.framework.default_server;
}
fn hasOption(argv: []const []const u8, option: []const u8) bool {
    for (argv) |arg| if (std.mem.eql(u8, arg, option) or (std.mem.startsWith(u8, arg, option) and arg.len > option.len and arg[option.len] == '=')) return true;
    return false;
}
fn addedFlags(allocator: Allocator, inv: Invocation, port: u16, lan: bool) ![]const []const u8 {
    var flags: std.ArrayList([]const u8) = .empty;
    errdefer flags.deinit(allocator);
    if (!server(inv)) return flags.toOwnedSlice(allocator);
    if (!hasOption(inv.args, "--port")) {
        try flags.appendSlice(allocator, &.{ "--port", try std.fmt.allocPrint(allocator, "{d}", .{port}) });
        if (inv.framework.strict) try flags.append(allocator, "--strictPort");
    }
    const expo = std.mem.eql(u8, inv.name, "expo");
    const host_choice = hasOption(inv.args, "--host") or (expo and (hasOption(inv.args, "--localhost") or hasOption(inv.args, "--lan") or hasOption(inv.args, "--tunnel")));
    if (!host_choice and !(expo and lan)) try flags.appendSlice(allocator, &.{ "--host", if (expo) "localhost" else "127.0.0.1" });
    return flags.toOwnedSlice(allocator);
}

/// Result borrows the original argv strings and partial allocations are not
/// freed on error; allocate from the caller's command arena.
pub fn injectFlags(allocator: Allocator, argv: []const []const u8, port: u16, lan: bool) ![]const []const u8 {
    const inv = invocation(argv) orelse return argv;
    const flags = try addedFlags(allocator, inv, port, lan);
    defer allocator.free(flags);
    if (flags.len == 0) return argv;
    const result = try allocator.alloc([]const u8, argv.len + flags.len);
    @memcpy(result[0..inv.insertion], argv[0..inv.insertion]);
    @memcpy(result[inv.insertion..][0..flags.len], flags);
    @memcpy(result[inv.insertion + flags.len ..], argv[inv.insertion..]);
    return result;
}

fn packageScript(argv: []const []const u8) bool {
    return argv.len >= 3 and contains(&.{ "npm", "pnpm", "yarn", "bun" }, std.fs.path.basename(argv[0])) and std.mem.eql(u8, argv[1], "run") and !std.mem.startsWith(u8, argv[2], "-");
}

pub fn unsafeToAppend(raw: []const u8) bool {
    var single = false;
    var double = false;
    var escaped = false;
    var word_start = true;
    for (raw, 0..) |ch, i| {
        if (escaped) {
            escaped = false;
            if (ch != '\n' and ch != '\r') word_start = false;
            continue;
        }
        if (ch == '\\' and !single) {
            escaped = true;
            continue;
        }
        if (ch == '\'' and !double) {
            single = !single;
            word_start = false;
            continue;
        }
        if (ch == '"' and !single) {
            double = !double;
            word_start = false;
            continue;
        }
        if (single or double) continue;
        if (ch == ';' or ch == '\n' or ch == '\r' or ch == '|') return true;
        if (ch == '#' and word_start) return true;
        if (ch == '&' and !(i > 0 and raw[i - 1] == '>' and i + 1 < raw.len and (std.ascii.isDigit(raw[i + 1]) or raw[i + 1] == '-'))) return true;
        word_start = ch == ' ' or ch == '\t';
    }
    return false;
}

pub fn resolveBasename(allocator: Allocator, io: std.Io, cwd: []const u8, argv: []const []const u8) !?[]u8 {
    if (invocation(argv)) |inv| return try allocator.dupe(u8, inv.name);
    if (!packageScript(argv)) return null;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = (try config.resolveScriptRaw(a, io, cwd, argv[2])) orelse return null;
    const tokens = try config.splitCommand(a, raw);
    const inv = invocation(tokens) orelse return null;
    return try allocator.dupe(u8, inv.name);
}

/// Result mixes borrowed argv strings with new allocations and partial
/// allocations are not freed on error; allocate from the caller's command arena.
pub fn injectScriptFlags(allocator: Allocator, io: std.Io, cwd: []const u8, argv: []const []const u8, port: u16, lan: bool) ![]const []const u8 {
    const direct = try injectFlags(allocator, argv, port, lan);
    if (direct.ptr != argv.ptr or !packageScript(argv)) return direct;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = (try config.resolveScriptRaw(a, io, cwd, argv[2])) orelse return argv;
    if (unsafeToAppend(raw)) return argv;
    const tokens = try config.splitCommand(a, raw);
    if (contains(tokens, "--")) return argv;
    var probe: std.ArrayList([]const u8) = .empty;
    try probe.appendSlice(a, tokens);
    for (argv[3..]) |arg| if (!std.mem.eql(u8, arg, "--")) try probe.append(a, arg);
    const inv = invocation(probe.items) orelse return argv;
    const flags = try addedFlags(a, inv, port, lan);
    if (flags.len == 0) return argv;
    const separator = std.mem.eql(u8, std.fs.path.basename(argv[0]), "npm") and !contains(argv, "--");
    const result = try allocator.alloc([]const u8, argv.len + flags.len + @intFromBool(separator));
    @memcpy(result[0..argv.len], argv);
    var i = argv.len;
    if (separator) {
        result[i] = "--";
        i += 1;
    }
    for (flags) |flag| {
        result[i] = try allocator.dupe(u8, flag);
        i += 1;
    }
    return result;
}
