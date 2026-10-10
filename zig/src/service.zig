const file_stat = @import("file_stat.zig");
const std = @import("std");
const builtin = @import("builtin");
const c = @import("native");
const A = std.mem.Allocator;
const Io = std.Io;
const profile_module = @import("profile.zig");
const pki_module = @import("pki.zig");
const process = @import("process.zig");
pub const Config = struct {
    profile: profile_module.Config = .{},
    container_cli: ?[]const u8 = null,
    redirect_listen: ?[]const u8 = null,
    ca_export: []const u8 = "/usr/local/share/dotlocal-zig/ca.pem",
    label: []const u8 = "com.euforicio.dotlocal-zig",
    executable: []const u8 = "/usr/local/libexec/dotlocal-zig",
    plist_path: []const u8 = "/Library/LaunchDaemons/com.euforicio.dotlocal-zig.plist",
    state_dir: []const u8 = "/Library/Application Support/dotlocal-zig",
    runtime_dir: []const u8 = "/var/run/dotlocal-zig",
    management_socket: []const u8 = "/var/run/dotlocal-zig/management.sock",
    management_group: []const u8 = "admin",
    stdout_path: []const u8 = "/Library/Logs/dotlocal-zig/dotlocal.log",
    stderr_path: []const u8 = "/Library/Logs/dotlocal-zig/dotlocal.error.log",
    /// Captured from the installing user's effective config.
    update: Update = .{},
};
/// Daemon self-update settings carried in the plist's ProgramArguments.
pub const Update = struct {
    auto_update: bool = true,
    channel: []const u8 = "stable",
    pin: ?[]const u8 = null,
    pub fn eql(x: Update, y: Update) bool {
        const pins = if (x.pin) |pin| y.pin != null and std.mem.eql(u8, pin, y.pin.?) else y.pin == null;
        return x.auto_update == y.auto_update and std.mem.eql(u8, x.channel, y.channel) and pins;
    }
};
fn validPath(path: []const u8) bool {
    if (!std.fs.path.isAbsolute(path) or std.mem.findScalar(u8, path, 0) != null or std.mem.indexOf(u8, path, "//") != null or (path.len > 1 and path[path.len - 1] == '/')) return false;
    for (path) |ch| if (ch < 32 or ch == 127) return false;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |p| if (std.mem.eql(u8, p, "..") or std.mem.eql(u8, p, ".")) return false;
    return true;
}
fn validate(a: A, config: Config) !void {
    try config.profile.validate(a);
    if (!validPath(config.ca_export)) return error.InvalidServicePath;
    if (config.profile.cert) |path| if (!validPath(path) or !validPath(config.profile.key.?)) return error.InvalidCertificatePath;
    if (config.container_cli) |path| if (!validPath(path)) return error.InvalidServicePath;
    if (redirect(config)) |listener| try (profile_module.Config{ .scheme = "http", .listen = listener }).validate(a);
    if (config.label.len == 0) return error.InvalidServiceLabel;
    for (config.label) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '-') return error.InvalidServiceLabel;
    for ([_][]const u8{ config.executable, config.plist_path, config.state_dir, config.runtime_dir, config.management_socket, config.stdout_path, config.stderr_path }) |path| if (!validPath(path)) return error.InvalidServicePath;
    if (!std.mem.eql(u8, std.fs.path.dirname(config.management_socket) orelse "", config.runtime_dir)) return error.InvalidSocketPath;
    if (std.mem.eql(u8, config.state_dir, "/") or std.mem.eql(u8, config.runtime_dir, "/") or beneath(config.ca_export, config.state_dir)) return error.InvalidServicePath;
    const files = [_][]const u8{ config.executable, config.plist_path, config.management_socket, config.ca_export, config.stdout_path, config.stderr_path };
    for (files, 0..) |path, index| for (files[index + 1 ..]) |other| {
        if (std.mem.eql(u8, path, other)) return error.InvalidServicePath;
    };
    if (config.management_group.len == 0) return error.InvalidManagementGroup;
    for (config.management_group) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return error.InvalidManagementGroup;
    if (!std.mem.eql(u8, config.update.channel, "stable") and !std.mem.eql(u8, config.update.channel, "nightly")) return error.InvalidChannel;
    if (config.update.pin) |pin| _ = std.SemanticVersion.parse(pin) catch return error.InvalidPin;
}
fn beneath(path: []const u8, directory: []const u8) bool {
    return std.mem.eql(u8, path, directory) or (std.mem.startsWith(u8, path, directory) and path.len > directory.len and path[directory.len] == '/');
}
fn redirect(config: Config) ?[]const u8 {
    if (config.redirect_listen) |listener| return listener;
    if (std.mem.eql(u8, config.profile.scheme, "https") and std.mem.eql(u8, config.profile.listen, "127.0.0.1:443")) return "127.0.0.1:80";
    return null;
}
fn appendString(a: A, out: *std.ArrayList(u8), value: []const u8) !void {
    try out.appendSlice(a, "<string>");
    for (value) |ch| try out.appendSlice(a, switch (ch) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => &.{ch},
    });
    try out.appendSlice(a, "</string>");
}
pub fn plist(a: A, config: Config) ![]u8 {
    try validate(a, config);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n");
    for ([_][2][]const u8{ .{ "Label", config.label }, .{ "Program", config.executable }, .{ "UserName", "root" }, .{ "GroupName", "wheel" }, .{ "WorkingDirectory", config.state_dir }, .{ "StandardOutPath", config.stdout_path }, .{ "StandardErrorPath", config.stderr_path } }) |kv| {
        try out.print(a, "<key>{s}</key>", .{kv[0]});
        try appendString(a, &out, kv[1]);
        try out.append(a, '\n');
    }
    try out.appendSlice(a, "<key>ProgramArguments</key><array>\n");
    var arguments: std.ArrayList([]const u8) = .empty;
    defer arguments.deinit(a);
    try arguments.appendSlice(a, &.{ config.executable, "daemon", "--state-dir", config.state_dir, "--management-socket", config.management_socket, "--management-group", config.management_group, "--scheme", config.profile.scheme, "--listen", config.profile.listen, "--tld", config.profile.tld });
    for (config.profile.tlds) |suffix| {
        if (!std.mem.eql(u8, suffix, config.profile.tld)) try arguments.appendSlice(a, &.{ "--tld", suffix });
    }
    if (config.profile.cert) |path| try arguments.appendSlice(a, &.{ "--cert", path, "--key", config.profile.key.? });
    try arguments.append(a, "--reconcile-profile");
    if (config.profile.wildcard) try arguments.append(a, "--wildcard");
    if (std.mem.eql(u8, config.profile.scheme, "https") and std.mem.eql(u8, config.profile.listen, "127.0.0.1:443")) try arguments.append(a, "--dual-loopback");
    if (config.container_cli) |path| try arguments.appendSlice(a, &.{ "--container-cli", path });
    if (redirect(config)) |listener| try arguments.appendSlice(a, &.{ "--redirect-listen", listener });
    // `--update-channel` enables the daemon updater; user proxies omit it.
    try arguments.appendSlice(a, &.{ "--update-channel", config.update.channel });
    if (!config.update.auto_update) try arguments.append(a, "--no-auto-update");
    if (config.update.pin) |pin| try arguments.appendSlice(a, &.{ "--update-pin", pin });
    for (arguments.items) |arg| {
        try appendString(a, &out, arg);
        try out.append(a, '\n');
    }
    try out.appendSlice(a, "</array>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ProcessType</key><string>Interactive</string>\n<key>Umask</key><integer>63</integer>\n<key>ThrottleInterval</key><integer>5</integer>\n<key>ExitTimeOut</key><integer>30</integer>\n</dict></plist>\n");
    return out.toOwnedSlice(a);
}
/// Update settings from a plist rendered by `plist`, or null when it has none
/// (installed before self-update). Values are validated, so no XML entities
/// occur; returned slices point into `bytes`.
pub fn parseUpdate(bytes: []const u8) ?Update {
    const open_tag = "<key>ProgramArguments</key><array>\n";
    const start = (std.mem.indexOf(u8, bytes, open_tag) orelse return null) + open_tag.len;
    const end = std.mem.indexOfPos(u8, bytes, start, "</array>") orelse return null;
    var result: Update = .{};
    var found = false;
    var previous: []const u8 = "";
    var lines = std.mem.splitScalar(u8, bytes[start..end], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, "<string>") or !std.mem.endsWith(u8, line, "</string>")) return null;
        const arg = line["<string>".len .. line.len - "</string>".len];
        if (std.mem.eql(u8, previous, "--update-channel")) {
            result.channel = arg;
            found = true;
        } else if (std.mem.eql(u8, previous, "--update-pin")) result.pin = arg;
        if (std.mem.eql(u8, arg, "--no-auto-update")) result.auto_update = false;
        previous = arg;
    }
    return if (found) result else null;
}

/// The installed plist's update settings; null when absent or pre-update.
/// Slices are owned by `a`.
pub fn installedUpdate(a: A, config: Config) !?Update {
    const bytes = readFile(a, config.plist_path, 1 << 20) catch |err| return if (err == error.FileNotFound) null else err;
    return parseUpdate(bytes);
}

/// Direct `install`/`upgrade` without update flags keep what the service
/// already runs with; `dotlocal init` passes the user's settings explicitly.
pub fn keepInstalledUpdate(a: A, config: *Config) !void {
    if (try installedUpdate(a, config.*)) |installed| config.update = installed;
}

fn command(a: A, io: Io, argv: []const []const u8) !void {
    const result = try std.process.run(a, io, .{ .argv = argv, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } } });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.ServiceCommandFailed;
}
pub fn loaded(a: A, io: Io, config: Config) !bool {
    try validate(a, config);
    const target = try std.fmt.allocPrint(a, "system/{s}", .{config.label});
    defer a.free(target);
    const result = try std.process.run(a, io, .{ .argv = &.{ "/bin/launchctl", "print", target }, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (result.term != .exited) return error.ServiceCommandFailed;
    return result.term.exited == 0;
}
fn root() !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;
    if (c.geteuid() != 0) return error.PrivilegeRequired;
}
fn safeDir(a: A, path: []const u8, mode: u32, gid: u32) !void {
    if (!validPath(path)) return error.InvalidServicePath;
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const ancestor = std.fs.path.dirname(path) orelse path;
    if (!std.mem.eql(u8, ancestor, path)) try safeDir(a, ancestor, 0o755, 0);
    var stat: c.struct_stat = undefined;
    if (file_stat.lstat(z, &stat) != 0) {
        const parent = std.fs.path.dirname(path) orelse return error.UnsafeArtifact;
        const parentz = try a.dupeSentinel(u8, parent, 0);
        defer a.free(parentz);
        const base = try a.dupeSentinel(u8, std.fs.path.basename(path), 0);
        defer a.free(base);
        const dir = c.open(parentz, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (dir < 0) return error.ServiceWriteFailed;
        defer _ = c.close(dir);
        if (c.mkdirat(dir, base, @intCast(mode)) != 0) return error.ServiceWriteFailed;
        const fd = c.openat(dir, base, c.O_RDONLY | c.O_DIRECTORY | c.O_NOFOLLOW | c.O_CLOEXEC);
        if (fd < 0) return error.UnsafeArtifact;
        defer _ = c.close(fd);
        if (file_stat.fstat(fd, &stat) != 0 or stat.st_uid != 0 or (stat.st_mode & c.S_IFMT) != c.S_IFDIR) return error.UnsafeArtifact;
        if (c.fchown(fd, 0, gid) != 0 or c.fchmod(fd, @intCast(mode)) != 0 or file_stat.fstat(fd, &stat) != 0) return error.ServiceWriteFailed;
    }
    // /var is an OS-owned symlink on macOS; canonicalize only this fixed parent.
    if (try systemAlias(path, z, stat)) return;
    // The system run directory is intentionally writable by the macOS daemon group.
    if (std.mem.eql(u8, path, "/var/run") and stat.st_uid == 0 and stat.st_gid == 1 and (stat.st_mode & 0o777) == 0o775 and (stat.st_mode & c.S_IFMT) == c.S_IFDIR) return;
    if ((stat.st_mode & c.S_IFMT) != c.S_IFDIR or stat.st_uid != 0 or (stat.st_mode & 0o022) != 0) return error.UnsafeArtifact;
}
/// Well-known shared directories are never chowned or chmodded, even when a
/// service path is configured to name one of them.
const shared_dirs = [_][]const u8{
    "/",               "/bin",               "/sbin",                "/usr",           "/usr/bin",                     "/usr/sbin",
    "/usr/lib",        "/usr/libexec",       "/usr/share",           "/usr/local",     "/usr/local/bin",               "/usr/local/sbin",
    "/usr/local/lib",  "/usr/local/libexec", "/usr/local/share",     "/usr/local/var", "/usr/local/etc",               "/opt",
    "/etc",            "/var",               "/var/run",             "/var/log",       "/var/lib",                     "/var/db",
    "/var/tmp",        "/var/folders",       "/run",                 "/tmp",           "/home",                        "/root",
    "/Users",          "/System",            "/Library",             "/Library/Logs",  "/Library/Application Support", "/Library/LaunchDaemons",
    "/Applications",   "/private",           "/private/etc",         "/private/var",   "/private/var/run",             "/private/var/log",
    "/private/var/db", "/private/var/tmp",   "/private/var/folders", "/private/tmp",
};
/// The service's own state, log and runtime directories survive uninstall, so
/// a reinstall with a different management group or an older mode repairs
/// them in place. Only a non-symlink directory already owned by `owner` and
/// not group/other-writable is repaired; shared system paths fail closed.
fn ownedDir(path: []const u8, mode: u32, gid: u32, owner: c.uid_t) !void {
    for (shared_dirs) |shared| if (std.mem.eql(u8, path, shared)) return error.UnmanagedServiceDirectory;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= buffer.len) return error.InvalidServicePath;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    const fd = c.open(buffer[0..path.len :0], c.O_RDONLY | c.O_DIRECTORY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return error.UnsafeArtifact;
    defer _ = c.close(fd);
    var stat: c.struct_stat = undefined;
    if (file_stat.fstat(fd, &stat) != 0 or (stat.st_mode & c.S_IFMT) != c.S_IFDIR) return error.UnsafeArtifact;
    if (stat.st_uid == owner and stat.st_gid == gid and (stat.st_mode & 0o7777) == mode) return;
    if (stat.st_uid != owner or (stat.st_mode & 0o022) != 0) return error.UnmanagedServiceDirectory;
    if (c.fchown(fd, owner, gid) != 0 or c.fchmod(fd, @intCast(mode)) != 0) return error.ServiceWriteFailed;
}
fn managedDir(a: A, path: []const u8, mode: u32, gid: u32) !void {
    try safeDir(a, path, mode, gid);
    try ownedDir(path, mode, gid, 0);
}
fn writeArtifact(a: A, io: Io, path: []const u8, data: []const u8, mode: u32) !bool {
    const parentpath = std.fs.path.dirname(path) orelse return error.UnsafeArtifact;
    try safeDir(a, parentpath, 0o755, 0);
    const dirz = try a.dupeSentinel(u8, parentpath, 0);
    defer a.free(dirz);
    const base = try a.dupeSentinel(u8, std.fs.path.basename(path), 0);
    defer a.free(base);
    const dir = c.open(dirz, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    if (dir < 0) return error.ServiceWriteFailed;
    defer _ = c.close(dir);
    var stat: c.struct_stat = undefined;
    if (file_stat.fstatat(dir, base, &stat, c.AT_SYMLINK_NOFOLLOW) == 0 and ((stat.st_mode & c.S_IFMT) != c.S_IFREG or stat.st_uid != 0 or stat.st_gid != 0 or (stat.st_mode & 0o022) != 0)) return error.UnsafeArtifact;
    if (file_stat.fstatat(dir, base, &stat, c.AT_SYMLINK_NOFOLLOW) == 0 and (stat.st_mode & 0o777) == mode) {
        const existing = try readFile(a, path, 128 << 20);
        defer a.free(existing);
        if (std.mem.eql(u8, existing, data)) return false;
    }
    var name: [64]u8 = undefined;
    const staged = process.createStaging(io, dir, ".dotlocal-install-", &name) catch return error.ServiceWriteFailed;
    const fd = staged.fd;
    const temp = staged.name;
    defer _ = c.close(fd);
    defer _ = c.unlinkat(dir, temp, 0);
    if (c.fchmod(fd, @intCast(mode)) != 0 or c.fchown(fd, 0, 0) != 0) return error.ServiceWriteFailed;
    process.writeAll(fd, data) catch return error.ServiceWriteFailed;
    if (c.fsync(fd) != 0 or c.renameat(dir, temp, dir, base) != 0 or c.fsync(dir) != 0) return error.ServiceWriteFailed;
    return true;
}
fn verifyArtifact(a: A, path: []const u8) !void {
    try safeDir(a, std.fs.path.dirname(path) orelse return error.UnsafeArtifact, 0o755, 0);
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const fd = c.open(z, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return error.UnsafeArtifact;
    defer _ = c.close(fd);
    var stat: c.struct_stat = undefined;
    if (file_stat.fstat(fd, &stat) != 0 or (stat.st_mode & c.S_IFMT) != c.S_IFREG or stat.st_uid != 0 or stat.st_gid != 0 or (stat.st_mode & 0o022) != 0) return error.UnsafeArtifact;
}
pub fn install(a: A, io: Io, config: Config, source: []const u8) !void {
    try validate(a, config);
    try root();
    if (!validPath(source)) return error.InvalidServicePath;
    if (config.profile.cert) |path| {
        const ctx = try pki_module.fileContext(a, path, config.profile.key.?);
        defer c.SSL_CTX_free(ctx);
    }
    const gid = try groupID(a, config.management_group);
    const bytes = try readFile(a, source, 128 << 20);
    defer a.free(bytes);
    const manifest = try plist(a, config);
    defer a.free(manifest);
    try managedDir(a, config.state_dir, 0o700, 0);
    try managedDir(a, config.runtime_dir, 0o750, gid);
    try managedDir(a, std.fs.path.dirname(config.stdout_path).?, 0o750, 0);
    try managedDir(a, std.fs.path.dirname(config.stderr_path).?, 0o750, 0);
    if (std.mem.eql(u8, config.profile.scheme, "https") and config.profile.cert == null) {
        const directory = try std.fmt.allocPrint(a, "{s}/pki", .{config.state_dir});
        defer a.free(directory);
        var authority = try pki_module.Authority.init(a, io, directory);
        defer authority.deinit();
        const certificate_path = try std.fmt.allocPrint(a, "{s}/ca.pem", .{directory});
        defer a.free(certificate_path);
        const certificate = try Io.Dir.cwd().readFileAlloc(io, certificate_path, a, .limited(1 << 20));
        defer a.free(certificate);
        _ = try writeArtifact(a, io, config.ca_export, certificate, 0o644);
        try trust(a, io, config.ca_export);
    } else {
        try removeGeneratedCA(a, io, config);
    }

    const binary_changed = try writeArtifact(a, io, config.executable, bytes, 0o755);
    const plist_changed = try writeArtifact(a, io, config.plist_path, manifest, 0o644);
    try command(a, io, &.{ "/usr/bin/plutil", "-lint", config.plist_path });
    const target = try std.fmt.allocPrint(a, "system/{s}", .{config.label});
    defer a.free(target);
    const already_loaded = try loaded(a, io, config);
    if (!binary_changed and !plist_changed and already_loaded and running(a, io, config)) return;
    if (already_loaded) try command(a, io, &.{ "/bin/launchctl", "bootout", target });
    try command(a, io, &.{ "/bin/launchctl", "bootstrap", "system", config.plist_path });
    try command(a, io, &.{ "/bin/launchctl", "enable", target });
    try command(a, io, &.{ "/bin/launchctl", "kickstart", "-k", target });
    if (!try loaded(a, io, config)) return error.ServiceNotLoaded;
    const deadline = Io.Clock.awake.now(io).nanoseconds + 10 * std.time.ns_per_s;
    while (Io.Clock.awake.now(io).nanoseconds < deadline) {
        if (running(a, io, config)) return;
        try Io.sleep(io, .fromMilliseconds(100), .awake);
    }
    return error.ServiceNotReady;
}
pub fn uninstall(a: A, io: Io, config: Config) !void {
    try validate(a, config);
    try root();
    const has_plist = try exists(a, config.plist_path);
    const has_binary = try exists(a, config.executable);
    const already_loaded = try loaded(a, io, config);
    if (!has_plist and (has_binary or already_loaded)) return error.ServiceOwnershipConflict;
    if (has_plist) {
        try verifyArtifact(a, config.plist_path);
        for ([_][2][]const u8{ .{ "Label", config.label }, .{ "Program", config.executable } }) |kv| {
            const result = try std.process.run(a, io, .{ .argv = &.{ "/usr/bin/plutil", "-extract", kv[0], "raw", "-o", "-", config.plist_path }, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
            defer a.free(result.stdout);
            defer a.free(result.stderr);
            if (!result.term.success() or !std.mem.eql(u8, std.mem.trimEnd(u8, result.stdout, "\r\n"), kv[1])) return error.ServiceOwnershipConflict;
        }
    }
    if (has_binary) try verifyArtifact(a, config.executable);
    if (already_loaded) {
        const target = try std.fmt.allocPrint(a, "system/{s}", .{config.label});
        defer a.free(target);
        try command(a, io, &.{ "/bin/launchctl", "bootout", target });
    }
    // Reconcile trust first so a failed command can be retried with the owned manifest intact.
    try removeGeneratedCA(a, io, config);
    for ([_][]const u8{ config.plist_path, config.executable }) |path| {
        if (!try exists(a, path)) continue;
        try verifyArtifact(a, path);
        const z = try a.dupeSentinel(u8, path, 0);
        defer a.free(z);
        if (c.unlink(z) != 0) return error.ServiceWriteFailed;
    }
    const socket = try a.dupeSentinel(u8, config.management_socket, 0);
    defer a.free(socket);
    var socket_stat: c.struct_stat = undefined;
    if (file_stat.lstat(socket, &socket_stat) == 0) {
        const gid = try groupID(a, config.management_group);
        try safeDir(a, config.runtime_dir, 0o750, gid);
        if ((socket_stat.st_mode & c.S_IFMT) != c.S_IFSOCK or socket_stat.st_uid != 0 or socket_stat.st_gid != gid) return error.UnsafeArtifact;
        if (c.unlink(socket) != 0) return error.ServiceWriteFailed;
    } else if (@import("net.zig").errno() != c.ENOENT) return error.ServiceWriteFailed;
    // Private certificates, route data, and logs intentionally survive uninstall.
}
fn exists(a: A, path: []const u8) !bool {
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    var st: c.struct_stat = undefined;
    if (file_stat.lstat(z, &st) == 0) return true;
    return if (@import("net.zig").errno() == c.ENOENT) false else error.UnsafeArtifact;
}
const system_keychain = "/Library/Keychains/System.keychain";

/// Read-only exact DER membership in the System keychain, independent of common names
/// and of certificates trusted only in a user's login keychain.
pub fn systemTrusted(a: A, io: Io, certificate_path: []const u8) !bool {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;
    const wanted = try certificateDER(a, certificate_path);
    defer a.free(wanted);
    const result = try std.process.run(a, io, .{ .argv = &.{ "/usr/bin/security", "find-certificate", "-a", "-p", system_keychain }, .stdout_limit = .limited(8 << 20), .stderr_limit = .limited(65536), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (!result.term.success()) return error.SystemKeychainInspectionFailed;
    return bundleContains(a, wanted, result.stdout);
}
/// Exact DER membership in a PEM bundle. One unparseable system entry must
/// not hide every other certificate, so invalid entries are skipped.
fn bundleContains(a: A, wanted: []const u8, bundle: []const u8) !bool {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var remaining = bundle;
    while (std.mem.indexOf(u8, remaining, begin)) |offset| {
        remaining = remaining[offset..];
        const finish = (std.mem.indexOf(u8, remaining, end) orelse return error.InvalidSystemCertificates) + end.len;
        defer remaining = remaining[finish..];
        const der = pemDER(a, remaining[0..finish]) catch |err| switch (err) {
            error.InvalidCertificate => continue,
            else => return err,
        };
        defer a.free(der);
        if (std.mem.eql(u8, wanted, der)) return true;
    }
    return false;
}
pub fn trusted(a: A, io: Io, certificate_path: []const u8) !bool {
    return systemTrusted(a, io, certificate_path);
}

/// Explicit root-only installation of exactly this CA in the admin trust store.
pub fn trust(a: A, io: Io, certificate_path: []const u8) !void {
    try root();
    if (!validPath(certificate_path)) return error.InvalidCertificatePath;
    try verifyArtifact(a, certificate_path);
    if (try systemTrusted(a, io, certificate_path)) return;
    try command(a, io, &.{ "/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", system_keychain, certificate_path });
    if (!try systemTrusted(a, io, certificate_path)) return error.TrustReconciliationFailed;
}

/// Exact certificate removal; an absent certificate is an idempotent no-op.
pub fn untrust(a: A, io: Io, certificate_path: []const u8) !void {
    try root();
    if (!validPath(certificate_path)) return error.InvalidCertificatePath;
    try verifyArtifact(a, certificate_path);
    if (!try systemTrusted(a, io, certificate_path)) return;
    try command(a, io, &.{ "/usr/bin/security", "remove-trusted-cert", "-d", certificate_path });
    if (try systemTrusted(a, io, certificate_path)) {
        // Some macOS versions retain the keychain item after removing its trust settings.
        // The DER fingerprint selects only the exact item in the fixed System keychain.
        const der = try certificateDER(a, certificate_path);
        defer a.free(der);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &digest, .{});
        const hash = std.fmt.bytesToHex(digest, .upper);
        try command(a, io, &.{ "/usr/bin/security", "delete-certificate", "-Z", &hash, system_keychain });
        if (try systemTrusted(a, io, certificate_path)) return error.TrustReconciliationFailed;
    }
}

fn pemDER(a: A, pem: []const u8) ![]u8 {
    const text = std.mem.trim(u8, pem, " \t\r\n");
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    if (!std.mem.startsWith(u8, text, begin) or !std.mem.endsWith(u8, text, end) or std.mem.indexOf(u8, text[begin.len..], begin) != null or (std.mem.indexOf(u8, text, end) orelse return error.InvalidCertificate) + end.len != text.len) return error.InvalidCertificate;
    const bio = c.BIO_new_mem_buf(text.ptr, @intCast(text.len)) orelse return error.InvalidCertificate;
    defer _ = c.BIO_free(bio);
    const cert = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidCertificate;
    defer c.X509_free(cert);
    const len = c.i2d_X509(cert, null);
    if (len <= 0) return error.InvalidCertificate;
    const der = try a.alloc(u8, @intCast(len));
    errdefer a.free(der);
    var cursor: [*c]u8 = der.ptr;
    if (c.i2d_X509(cert, &cursor) != len) return error.InvalidCertificate;
    return der;
}
fn certificateDER(a: A, path: []const u8) ![]u8 {
    if (!validPath(path)) return error.InvalidCertificatePath;
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const data = try readFile(a, path, 1 << 20);
    defer a.free(data);
    try pki_module.secureFile(z, false);
    const der = try pemDER(a, data);
    errdefer a.free(der);
    var cursor: [*c]const u8 = der.ptr;
    const cert = c.d2i_X509(null, &cursor, @intCast(der.len)) orelse return error.InvalidCertificate;
    defer c.X509_free(cert);
    if (c.X509_check_ca(cert) == 0) return error.InvalidAuthority;
    return der;
}
/// Check every directory component for symlinks. Fixed macOS /var
/// and /etc aliases are allowed only when they resolve to their OS-owned targets.
fn systemAlias(path: []const u8, z: [:0]const u8, st: c.struct_stat) !bool {
    if (!std.mem.eql(u8, path, "/var") and !std.mem.eql(u8, path, "/etc")) return false;
    if (st.st_uid != 0 or (st.st_mode & c.S_IFMT) != c.S_IFLNK) return false;
    var target: [128]u8 = undefined;
    const count = c.readlink(z, &target, target.len);
    if (count < 0) return error.UnsafeArtifact;
    const expected = if (std.mem.eql(u8, path, "/var")) "private/var" else "private/etc";
    if (!std.mem.eql(u8, target[0..@intCast(count)], expected) and !std.mem.eql(u8, target[0..@intCast(count)], if (std.mem.eql(u8, path, "/var")) "/private/var" else "/private/etc")) return error.UnsafeArtifact;
    return true;
}
/// Version reported by the installed service executable, or null when it is
/// absent. Only a root-owned, non-writable regular file is executed.
pub fn installedVersion(a: A, io: Io, config: Config) !?[]u8 {
    return executableVersion(a, io, config.executable, 0);
}
/// `installedVersion` with an explicit expected owner (tests use their own).
pub fn executableVersion(a: A, io: Io, path: []const u8, owner: c.uid_t) !?[]u8 {
    if (!validPath(path)) return error.InvalidServicePath;
    checkParents(a, path) catch |err| return if (err == error.FileNotFound) null else err;
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const fd = c.open(z, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return if (@import("net.zig").errno() == c.ENOENT) null else error.UnsafeArtifact;
    defer _ = c.close(fd);
    var st: c.struct_stat = undefined;
    if (file_stat.fstat(fd, &st) != 0 or (st.st_mode & c.S_IFMT) != c.S_IFREG or st.st_uid != owner or (st.st_mode & 0o022) != 0) return error.UnsafeArtifact;
    return try @import("update.zig").probeVersion(a, io, path);
}
fn checkParents(a: A, path: []const u8) !void {
    var parent = std.fs.path.dirname(path) orelse return error.UnsafeArtifact;
    while (true) {
        const z = try a.dupeSentinel(u8, parent, 0);
        defer a.free(z);
        var st: c.struct_stat = undefined;
        if (file_stat.lstat(z, &st) != 0) return if (@import("net.zig").errno() == c.ENOENT) error.FileNotFound else error.UnsafeArtifact;
        const alias = try systemAlias(parent, z, st);
        if (!alias and (st.st_mode & c.S_IFMT) != c.S_IFDIR) return error.UnsafeArtifact;
        if (std.mem.eql(u8, parent, "/")) break;
        const ancestor = std.fs.path.dirname(parent) orelse return error.UnsafeArtifact;
        if (std.mem.eql(u8, parent, ancestor)) break;
        parent = ancestor;
    }
}
fn readFile(a: A, path: []const u8, limit: usize) ![]u8 {
    if (!validPath(path)) return error.InvalidServicePath;
    try checkParents(a, path);
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const fd = c.open(z, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return if (@import("net.zig").errno() == c.ENOENT) error.FileNotFound else error.UnsafeArtifact;
    defer _ = c.close(fd);
    var st: c.struct_stat = undefined;
    if (file_stat.fstat(fd, &st) != 0 or (st.st_mode & c.S_IFMT) != c.S_IFREG or (st.st_mode & 0o022) != 0 or st.st_size < 0 or st.st_size > limit) return error.UnsafeArtifact;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(a);
    var buffer: [8192]u8 = undefined;
    while (true) {
        const n = c.read(fd, &buffer, buffer.len);
        if (n < 0) return error.ServiceReadFailed;
        if (n == 0) break;
        if (bytes.items.len + @as(usize, @intCast(n)) > limit) return error.UnsafeArtifact;
        try bytes.appendSlice(a, buffer[0..@intCast(n)]);
    }
    return bytes.toOwnedSlice(a);
}
fn removeGeneratedCA(a: A, io: Io, config: Config) !void {
    const ca = try std.fmt.allocPrint(a, "{s}/pki/ca.pem", .{config.state_dir});
    defer a.free(ca);
    const original = certificateDER(a, ca) catch |err| switch (err) {
        error.FileNotFound => {
            const exported = readFile(a, config.ca_export, 1 << 20) catch |export_error| switch (export_error) {
                error.FileNotFound => return,
                else => return export_error,
            };
            a.free(exported);
            return error.ServiceOwnershipConflict;
        },
        else => return err,
    };
    defer a.free(original);
    try verifyArtifact(a, ca);
    const exported = certificateDER(a, config.ca_export) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (exported) |der| a.free(der);
    if (exported) |der| {
        try verifyArtifact(a, config.ca_export);
        if (!std.mem.eql(u8, original, der)) return error.ServiceOwnershipConflict;
    }
    try untrust(a, io, ca);
    if (exported != null) {
        const z = try a.dupeSentinel(u8, config.ca_export, 0);
        defer a.free(z);
        if (c.unlink(z) != 0) return error.ServiceWriteFailed;
    }
}
fn running(a: A, io: Io, config: Config) bool {
    const client: @import("client.zig").Client = .{ .allocator = a, .io = io, .socket_path = config.management_socket };
    const response = client.call(.{ .operation = "status" }) catch return false;
    defer response.deinit();
    const status = response.value.status orelse return false;
    if (!profile_module.sameTlds(a, config.profile.tld, config.profile.tlds, status.tld, status.tlds orelse &.{})) return false;
    if (!status.running or !std.mem.eql(u8, status.socket_path, config.management_socket) or !std.mem.eql(u8, status.scheme, config.profile.scheme) or !std.mem.eql(u8, status.listen_address, config.profile.listen) or !std.mem.eql(u8, status.tld, config.profile.tld) or status.wildcard_fallback != config.profile.wildcard or !std.mem.eql(u8, status.certificate_file, config.profile.cert orelse "") or !std.mem.eql(u8, status.key_file, config.profile.key orelse "")) return false;
    const doctor = client.call(.{ .operation = "doctor" }) catch return false;
    defer doctor.deinit();
    const diagnostics = doctor.value.diagnostics orelse return false;
    if (diagnostics.len == 0) return false;
    for (diagnostics) |diagnostic| if (!std.mem.eql(u8, diagnostic.level, "ok")) return false;
    return true;
}

pub const applecontainer = @import("applecontainer.zig");
pub const tailscale = @import("tailscale.zig");
pub const lan = @import("lan.zig");
pub const mdns = @import("mdns.zig");
pub const hosts = @import("hosts.zig");

pub fn groupID(a: A, name: []const u8) !u32 {
    if (name.len == 0) return error.InvalidManagementGroup;
    for (name) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return error.InvalidManagementGroup;
    const z = try a.dupeSentinel(u8, name, 0);
    defer a.free(z);
    const group = c.getgrnam(z) orelse return error.InvalidManagementGroup;
    return group.*.gr_gid;
}

test "System keychain inspection skips an unparseable entry and still finds the CA" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "pki", .fromMode(0o700));
    const directory = try tmp.dir.realPathFileAlloc(io, "pki", a);
    defer a.free(directory);
    var authority = try pki_module.Authority.init(a, io, directory);
    defer authority.deinit();
    const pem = try tmp.dir.readFileAlloc(io, "pki/ca.pem", a, .limited(1 << 20));
    defer a.free(pem);
    const path = try std.fmt.allocPrint(a, "{s}/ca.pem", .{directory});
    defer a.free(path);
    const wanted = try certificateDER(a, path);
    defer a.free(wanted);
    const corrupt = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const bundle = try std.mem.concat(a, u8, &.{ corrupt, pem });
    defer a.free(bundle);
    try std.testing.expect(try bundleContains(a, wanted, bundle));
    try std.testing.expect(!try bundleContains(a, wanted, corrupt));
    try std.testing.expectError(error.InvalidSystemCertificates, bundleContains(a, wanted, "-----BEGIN CERTIFICATE-----\nAAAA"));
}

test "service directories never take ownership of preexisting system paths" {
    const a = std.testing.allocator;
    // Root-owned 0755 on macOS and Linux; a different mode or group must be
    // refused before any chown or chmod is attempted, even as root.
    try std.testing.expectError(error.UnmanagedServiceDirectory, managedDir(a, "/usr", 0o750, 0));
    var stat: c.struct_stat = undefined;
    try std.testing.expectEqual(@as(c_int, 0), file_stat.stat("/usr", &stat));
    try std.testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast(stat.st_mode & 0o7777)));
    if (builtin.os.tag == .macos) try std.testing.expectError(error.UnmanagedServiceDirectory, managedDir(a, "/var/run", 0o750, 0));
    for ([_][]const u8{ "/usr", "/var/run", "/usr/local/share", "/Library", "/tmp", "/" }) |path|
        try std.testing.expectError(error.UnmanagedServiceDirectory, ownedDir(path, 0o750, 0, c.geteuid()));
}

test "service directories left by uninstall are repaired in place" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const uid = c.geteuid();
    const gid: u32 = @intCast(c.getegid());
    try tmp.dir.createDir(io, "state", .fromMode(0o755));
    const state = try tmp.dir.realPathFileAlloc(io, "state", a);
    defer a.free(state);
    const statez = try a.dupeSentinel(u8, state, 0);
    defer a.free(statez);
    _ = c.chmod(statez, 0o755);
    // An older build's mode is tightened on reinstall.
    try ownedDir(state, 0o700, gid, uid);
    var stat: c.struct_stat = undefined;
    try std.testing.expectEqual(@as(c_int, 0), file_stat.stat(statez, &stat));
    try std.testing.expectEqual(@as(u32, 0o700), @as(u32, @intCast(stat.st_mode & 0o7777)));
    try std.testing.expectEqual(gid, @as(u32, @intCast(stat.st_gid)));
    try ownedDir(state, 0o700, gid, uid);
    // Group/other-writable directories are not trusted for repair.
    _ = c.chmod(statez, 0o775);
    try std.testing.expectError(error.UnmanagedServiceDirectory, ownedDir(state, 0o700, gid, uid));
    try std.testing.expectEqual(@as(c_int, 0), file_stat.stat(statez, &stat));
    try std.testing.expectEqual(@as(u32, 0o775), @as(u32, @intCast(stat.st_mode & 0o7777)));
    // A directory owned by someone else is refused.
    if (uid != 0) try std.testing.expectError(error.UnmanagedServiceDirectory, ownedDir(state, 0o700, gid, 0));
    // A symlink to a repairable directory is never followed.
    const link = try std.fmt.allocPrintSentinel(a, "{s}-link", .{state}, 0);
    defer a.free(link);
    _ = c.chmod(statez, 0o755);
    try std.testing.expectEqual(@as(c_int, 0), c.symlink(statez, link));
    defer _ = c.unlink(link);
    try std.testing.expectError(error.UnsafeArtifact, ownedDir(link, 0o700, gid, uid));
    try std.testing.expectEqual(@as(c_int, 0), file_stat.stat(statez, &stat));
    try std.testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast(stat.st_mode & 0o7777)));
}
