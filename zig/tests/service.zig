//! Real certificates/files and read-only native macOS lifecycle inspection.
const file_stat = @import("../src/file_stat.zig");
const std = @import("std");
const service = @import("../src/service.zig");
const pki = @import("../src/pki.zig");
const c = @import("native");
const a = std.testing.allocator;
const io = std.testing.io;

fn run(argv: []const []const u8) !std.process.RunResult {
    return std.process.run(a, io, .{ .argv = argv, .stdout_limit = .limited(8 << 20), .stderr_limit = .limited(65536), .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } } });
}

test "service profile manifests use native plutil and explicit production policy" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const configs = [_]service.Config{
        .{},
        .{ .profile = .{ .scheme = "http", .listen = "127.0.0.1:8080" } },
        .{ .profile = .{ .listen = "127.0.0.1:8443", .cert = "/private/cert&chain.pem", .key = "/private/key.pem", .wildcard = true }, .container_cli = "/usr/local/bin/container" },
    };
    for (configs) |config| {
        const manifest = try service.plist(a, config);
        defer a.free(manifest);
        try std.testing.expect(std.mem.indexOf(u8, manifest, "<key>RunAtLoad</key>") == null);
        try std.testing.expect(std.mem.indexOf(u8, manifest, "<key>SuccessfulExit</key><false/>") != null);
        try std.testing.expect(std.mem.indexOf(u8, manifest, "<key>ProcessType</key><string>Interactive</string>") != null);
        try std.testing.expect(std.mem.indexOf(u8, manifest, "<string>--reconcile-profile</string>") != null);
        try tmp.dir.writeFile(io, .{ .sub_path = "service.plist", .data = manifest });
        const path = try tmp.dir.realPathFileAlloc(io, "service.plist", a);
        defer a.free(path);
        const result = try run(&.{ "/usr/bin/plutil", "-lint", "--", path });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try std.testing.expect(result.term.success());
        const group = try run(&.{ "/usr/bin/plutil", "-extract", "ProgramArguments", "json", "-o", "-", path });
        defer a.free(group.stdout);
        defer a.free(group.stderr);
        try std.testing.expect(group.term.success());
        const arguments = try std.json.parseFromSlice([]const []const u8, a, group.stdout, .{});
        defer arguments.deinit();
        try std.testing.expectEqualStrings(config.executable, arguments.value[0]);
        try std.testing.expectEqualStrings("daemon", arguments.value[1]);
    }
    try std.testing.expectEqualStrings("admin", (service.Config{}).management_group);
    try std.testing.expectError(error.InvalidServicePath, service.plist(a, .{ .state_dir = "/private/../tmp" }));
}

test "service plist carries update settings to the daemon" {
    const enabled = try service.plist(a, .{});
    defer a.free(enabled);
    try std.testing.expect(std.mem.indexOf(u8, enabled, "<string>--update-channel</string>\n<string>stable</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, enabled, "--no-auto-update") == null);
    try std.testing.expect(std.mem.indexOf(u8, enabled, "--update-pin") == null);
    const plist = try service.plist(a, .{ .update = .{ .channel = "nightly", .auto_update = false, .pin = "0.2.0" } });
    defer a.free(plist);
    try std.testing.expect(std.mem.indexOf(u8, plist, "<string>--update-channel</string>\n<string>nightly</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, plist, "<string>--no-auto-update</string>") != null);
    try std.testing.expect(std.mem.indexOf(u8, plist, "<string>--update-pin</string>\n<string>0.2.0</string>") != null);
    try std.testing.expectError(error.InvalidChannel, service.plist(a, .{ .update = .{ .channel = "beta" } }));
    try std.testing.expectError(error.InvalidPin, service.plist(a, .{ .update = .{ .pin = "latest" } }));
    if (@import("builtin").os.tag != .macos) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "service.plist", .data = plist });
    const path = try tmp.dir.realPathFileAlloc(io, "service.plist", a);
    defer a.free(path);
    const lint = try run(&.{ "/usr/bin/plutil", "-lint", "--", path });
    defer a.free(lint.stdout);
    defer a.free(lint.stderr);
    try std.testing.expect(lint.term.success());
}

test "installed plist update settings round-trip and compare" {
    const settings = [_]service.Update{ .{}, .{ .channel = "nightly" }, .{ .auto_update = false }, .{ .pin = "0.2.0" }, .{ .channel = "nightly", .auto_update = false, .pin = "0.2.0-nightly.20261010" } };
    for (settings, 0..) |want, index| {
        const rendered = try service.plist(a, .{ .update = want, .profile = .{ .listen = "127.0.0.1:8443", .tlds = &.{ ".local", ".test" }, .wildcard = true }, .container_cli = "/opt/a&b/container" });
        defer a.free(rendered);
        const parsed = service.parseUpdate(rendered).?;
        try std.testing.expect(parsed.eql(want));
        for (settings, 0..) |other, other_index| try std.testing.expectEqual(index == other_index, parsed.eql(other));
    }
    // A plist from before self-update has no settings to compare.
    try std.testing.expect(service.parseUpdate("<plist><dict><key>ProgramArguments</key><array>\n<string>/x</string>\n<string>daemon</string>\n</array></dict></plist>") == null);
    try std.testing.expect(service.parseUpdate("not a plist") == null);
}

test "direct service install keeps the installed update settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "service.plist" });
    defer a.free(path);
    var config: service.Config = .{ .plist_path = path };
    try std.testing.expect((try service.installedUpdate(arena.allocator(), config)) == null);
    const installed: service.Update = .{ .channel = "nightly", .auto_update = false, .pin = "0.2.0" };
    const rendered = try service.plist(a, .{ .update = installed });
    defer a.free(rendered);
    try tmp.dir.writeFile(io, .{ .sub_path = "service.plist", .data = rendered, .flags = .{ .permissions = .fromMode(0o644) } });
    try std.testing.expect(!(config.update.eql(installed)));
    try service.keepInstalledUpdate(arena.allocator(), &config);
    try std.testing.expect(config.update.eql(installed));
    // A pre-update plist leaves the defaults in place.
    try tmp.dir.writeFile(io, .{ .sub_path = "service.plist", .data = "<plist></plist>", .flags = .{ .permissions = .fromMode(0o644) } });
    var fresh: service.Config = .{ .plist_path = path };
    try service.keepInstalledUpdate(arena.allocator(), &fresh);
    try std.testing.expect(fresh.update.eql(.{}));
}

test "fresh same-name roots are absent from the actual System keychain" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "one", .fromMode(0o700));
    try tmp.dir.createDir(io, "two", .fromMode(0o700));
    const one = try tmp.dir.realPathFileAlloc(io, "one", a);
    defer a.free(one);
    const two = try tmp.dir.realPathFileAlloc(io, "two", a);
    defer a.free(two);
    var first = try pki.Authority.init(a, io, one);
    defer first.deinit();
    var second = try pki.Authority.init(a, io, two);
    defer second.deinit();
    const first_path = try std.fmt.allocPrint(a, "{s}/ca.pem", .{one});
    defer a.free(first_path);
    const second_path = try std.fmt.allocPrint(a, "{s}/ca.pem", .{two});
    defer a.free(second_path);
    try std.testing.expect(!try service.systemTrusted(a, io, first_path));
    try std.testing.expect(!try service.trusted(a, io, second_path));
    if (c.geteuid() != 0) {
        try std.testing.expectError(error.PrivilegeRequired, service.trust(a, io, first_path));
        try std.testing.expectError(error.PrivilegeRequired, service.untrust(a, io, first_path));
    }
    const certificate = try tmp.dir.readFileAlloc(io, "one/ca.pem", a, .limited(1 << 20));
    defer a.free(certificate);
    const invalid = try std.fmt.allocPrint(a, "{s}\n{s}", .{ certificate, certificate });
    defer a.free(invalid);
    try tmp.dir.writeFile(io, .{ .sub_path = "two-certificates.pem", .data = invalid });
    const invalid_path = try tmp.dir.realPathFileAlloc(io, "two-certificates.pem", a);
    defer a.free(invalid_path);
    try std.testing.expectError(error.InvalidCertificate, service.systemTrusted(a, io, invalid_path));
    const trailing = try std.fmt.allocPrint(a, "{s}junk\n-----END CERTIFICATE-----", .{certificate});
    defer a.free(trailing);
    try tmp.dir.writeFile(io, .{ .sub_path = "trailing.pem", .data = trailing });
    const trailing_path = try tmp.dir.realPathFileAlloc(io, "trailing.pem", a);
    defer a.free(trailing_path);
    try std.testing.expectError(error.InvalidCertificate, service.systemTrusted(a, io, trailing_path));
    const leaf_context = try first.serverContext("leaf.local");
    defer c.SSL_CTX_free(leaf_context);
    const leaf = try std.fmt.allocPrint(a, "{s}/leaf-only.pem", .{one});
    defer a.free(leaf);
    try writeTLSFile(leaf, c.SSL_CTX_get0_certificate(leaf_context), null);
    try std.testing.expectError(error.InvalidAuthority, service.systemTrusted(a, io, leaf));
    try std.testing.expectError(error.InvalidCertificatePath, service.systemTrusted(a, io, "relative.pem"));
    const link = try std.fmt.allocPrintSentinel(a, "{s}/link.pem", .{one}, 0);
    defer a.free(link);
    const target = try a.dupeSentinel(u8, first_path, 0);
    defer a.free(target);
    try std.testing.expect(c.symlink(target, link) == 0);
    try std.testing.expectError(error.UnsafeArtifact, service.systemTrusted(a, io, link));
    const directory_link = try std.fmt.allocPrintSentinel(a, "{s}/directory-link", .{std.fs.path.dirname(one).?}, 0);
    defer a.free(directory_link);
    const directory_target = try a.dupeSentinel(u8, one, 0);
    defer a.free(directory_target);
    try std.testing.expect(c.symlink(directory_target, directory_link) == 0);
    const through_link = try std.fmt.allocPrint(a, "{s}/ca.pem", .{directory_link});
    defer a.free(through_link);
    try std.testing.expectError(error.UnsafeArtifact, service.systemTrusted(a, io, through_link));
}

test "System keychain DER inspection recognizes an actual exported CA" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const result = try run(&.{ "/usr/bin/security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain" });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try std.testing.expect(result.term.success());
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var remaining: []const u8 = result.stdout;
    while (std.mem.indexOf(u8, remaining, begin)) |offset| {
        remaining = remaining[offset..];
        const finish = (std.mem.indexOf(u8, remaining, end) orelse return error.InvalidCertificate) + end.len;
        try tmp.dir.writeFile(io, .{ .sub_path = "actual-system-ca.pem", .data = remaining[0..finish] });
        const path = try tmp.dir.realPathFileAlloc(io, "actual-system-ca.pem", a);
        defer a.free(path);
        const present = service.systemTrusted(a, io, path) catch |err| switch (err) {
            error.InvalidAuthority => {
                remaining = remaining[finish..];
                continue;
            },
            else => return err,
        };
        try std.testing.expect(present);
        return;
    }
    return error.SkipZigTest; // This host has no CA certificates in its System keychain.
}

test "service install and uninstall refuse unprivileged mutation" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    _ = try service.loaded(a, io, .{ .label = "com.euforicio.dotlocal-zig-test-absent" });
    if (c.geteuid() == 0) return error.SkipZigTest;
    try std.testing.expectError(error.PrivilegeRequired, service.install(a, io, .{}, "/usr/bin/true"));
    try std.testing.expectError(error.PrivilegeRequired, service.uninstall(a, io, .{}));
}

const PrivilegedFixture = struct {
    config: service.Config,
    allocator: std.mem.Allocator,
    fn init() !PrivilegedFixture {
        const label = try std.fmt.allocPrint(a, "com.euforicio.dotlocal-zig-integration-{d}", .{c.getpid()});
        const state = try std.fmt.allocPrint(a, "/Library/Application Support/dotlocal-zigIntegration-{d}", .{c.getpid()});
        const runtime = try std.fmt.allocPrint(a, "/var/run/dotlocal-zig-integration-{d}", .{c.getpid()});
        const logs = try std.fmt.allocPrint(a, "/Library/Logs/dotlocal-zigIntegration-{d}", .{c.getpid()});
        defer a.free(logs);
        const reserved = try @import("../src/net.zig").tcp(a, "127.0.0.1", 0, true);
        defer _ = c.close(reserved);
        var sock: c.struct_sockaddr_in = undefined;
        var len: c.socklen_t = @sizeOf(@TypeOf(sock));
        if (c.getsockname(reserved, @ptrCast(&sock), &len) != 0) return error.ListenerInspectionFailed;
        return .{ .allocator = a, .config = .{
            .label = label,
            .state_dir = state,
            .runtime_dir = runtime,
            .management_socket = try std.fmt.allocPrint(a, "{s}/management.sock", .{runtime}),
            .executable = try std.fmt.allocPrint(a, "/usr/local/libexec/dotlocal-zig-integration-{d}", .{c.getpid()}),
            .plist_path = try std.fmt.allocPrint(a, "/Library/LaunchDaemons/{s}.plist", .{label}),
            .stdout_path = try std.fmt.allocPrint(a, "{s}/daemon.log", .{logs}),
            .stderr_path = try std.fmt.allocPrint(a, "{s}/daemon.error.log", .{logs}),
            .ca_export = try std.fmt.allocPrint(a, "/usr/local/share/dotlocal-zig-integration-{d}/ca.pem", .{c.getpid()}),
            .profile = .{ .listen = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{std.mem.bigToNative(u16, sock.sin_port)}) },
        } };
    }
    fn deinit(self: PrivilegedFixture) void {
        for ([_][]const u8{ self.config.label, self.config.state_dir, self.config.runtime_dir, self.config.management_socket, self.config.executable, self.config.plist_path, self.config.stdout_path, self.config.stderr_path, self.config.ca_export, self.config.profile.listen }) |value| self.allocator.free(value);
    }
    fn absent(self: PrivilegedFixture) !void {
        if (try service.loaded(a, io, self.config)) return error.PreexistingService;
        for ([_][]const u8{ self.config.state_dir, self.config.runtime_dir, self.config.executable, self.config.plist_path, std.fs.path.dirname(self.config.stdout_path).?, std.fs.path.dirname(self.config.ca_export).? }) |path| {
            const z = try a.dupeSentinel(u8, path, 0);
            defer a.free(z);
            var st: c.struct_stat = undefined;
            if (file_stat.lstat(z, &st) == 0 or @import("../src/net.zig").errno() != c.ENOENT) return error.PreexistingServiceArtifact;
        }
    }
    /// Called only after absent() proves the isolated namespace was created by this gate.
    fn cleanup(self: PrivilegedFixture) !void {
        if (try service.loaded(a, io, self.config)) {
            const target = try std.fmt.allocPrint(a, "system/{s}", .{self.config.label});
            defer a.free(target);
            const result = try run(&.{ "/bin/launchctl", "bootout", target });
            defer a.free(result.stdout);
            defer a.free(result.stderr);
            if (!result.term.success()) return error.ServiceCleanupFailed;
        }
        const ca = try std.fmt.allocPrint(a, "{s}/pki/ca.pem", .{self.config.state_dir});
        defer a.free(ca);
        const caz = try a.dupeSentinel(u8, ca, 0);
        defer a.free(caz);
        var st: c.struct_stat = undefined;
        if (file_stat.lstat(caz, &st) == 0) {
            try service.untrust(a, io, ca);
            if (try service.systemTrusted(a, io, ca)) return error.ServiceCleanupFailed;
        } else if (@import("../src/net.zig").errno() != c.ENOENT) return error.ServiceCleanupFailed;
        for ([_][]const u8{ self.config.executable, self.config.plist_path }) |path| {
            const z = try a.dupeSentinel(u8, path, 0);
            defer a.free(z);
            if (file_stat.lstat(z, &st) == 0) {
                if ((st.st_mode & c.S_IFMT) != c.S_IFREG or st.st_uid != 0 or st.st_gid != 0) return error.UnsafeCleanupArtifact;
                if (c.unlink(z) != 0) return error.ServiceCleanupFailed;
            } else if (@import("../src/net.zig").errno() != c.ENOENT) return error.ServiceCleanupFailed;
        }
        for ([_][]const u8{ self.config.state_dir, self.config.runtime_dir, std.fs.path.dirname(self.config.stdout_path).?, std.fs.path.dirname(self.config.ca_export).? }) |path| {
            const z = try a.dupeSentinel(u8, path, 0);
            defer a.free(z);
            if (file_stat.lstat(z, &st) == 0) {
                if ((st.st_mode & c.S_IFMT) != c.S_IFDIR or st.st_uid != 0 or (st.st_mode & 0o022) != 0) return error.UnsafeCleanupArtifact;
                try std.Io.Dir.cwd().deleteTree(io, path);
            } else if (@import("../src/net.zig").errno() != c.ENOENT) return error.ServiceCleanupFailed;
        }
        try self.absent();
    }
};
fn fileStat(path: []const u8) !c.struct_stat {
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    var st: c.struct_stat = undefined;
    if (file_stat.lstat(z, &st) != 0) return error.FileNotFound;
    return st;
}
fn writeTLSFile(path: []const u8, cert: ?*c.X509, key: ?*c.EVP_PKEY) !void {
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    const fd = c.open(z, c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_NOFOLLOW | c.O_CLOEXEC, @as(c_uint, 0o600));
    if (fd < 0) return error.WriteFailed;
    defer _ = c.close(fd);
    const bio = c.BIO_new_fd(fd, c.BIO_NOCLOSE) orelse return error.WriteFailed;
    defer _ = c.BIO_free(bio);
    if (cert) |value| {
        if (c.PEM_write_bio_X509(bio, value) != 1) return error.WriteFailed;
    } else if (c.PEM_write_bio_PrivateKey(bio, key, null, null, 0, null, null) != 1) return error.WriteFailed;
    if (c.fsync(fd) != 0) return error.WriteFailed;
}

test "explicit isolated privileged service profile reconciliation and exact cleanup" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const confirmation = c.getenv("DOTLOCAL_ZIG_SERVICE_TEST") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(confirmation), "RUN-PRIVILEGED-DOTLOCAL-ZIG")) return error.InvalidPrivilegeConfirmation;
    if (c.geteuid() != 0) return error.PrivilegeRequired;
    const source = c.getenv("DOTLOCAL_ZIG_SERVICE_BINARY") orelse return error.MissingServiceBinary;
    const fixture = try PrivilegedFixture.init();
    defer fixture.deinit();
    try fixture.absent();
    var cleaned = false;
    defer if (!cleaned) fixture.cleanup() catch |err| std.debug.panic("isolated service cleanup failed: {s}; label={s}", .{ @errorName(err), fixture.config.label });
    var config = fixture.config;
    try service.install(a, io, config, std.mem.span(source));
    const first_binary = try fileStat(config.executable);
    const first_plist = try fileStat(config.plist_path);
    try service.install(a, io, config, std.mem.span(source));
    try std.testing.expectEqual(first_binary.st_ino, (try fileStat(config.executable)).st_ino);
    try std.testing.expectEqual(first_plist.st_ino, (try fileStat(config.plist_path)).st_ino);
    // A clean signal exit must stay stopped; explicit kickstart resumes it.
    const target = try std.fmt.allocPrint(a, "system/{s}", .{config.label});
    defer a.free(target);
    const stopped = try run(&.{ "/bin/launchctl", "kill", "SIGTERM", target });
    defer a.free(stopped.stdout);
    defer a.free(stopped.stderr);
    try std.testing.expect(stopped.term.success());
    try std.Io.sleep(io, .fromSeconds(6), .awake);
    const probe = @import("../src/client.zig").Client{ .allocator = a, .io = io, .socket_path = config.management_socket };
    if (probe.call(.{ .id = "stop-check", .operation = "status" })) |response| {
        response.deinit();
        return error.CleanExitRestarted;
    } else |_| {}
    try std.testing.expect(try service.loaded(a, io, config));
    try service.install(a, io, config, std.mem.span(source));
    const resumed = try probe.call(.{ .id = "resumed", .operation = "status" });
    defer resumed.deinit();
    try std.testing.expect(resumed.value.status.?.running);
    const exe = try a.dupeSentinel(u8, config.executable, 0);
    defer a.free(exe);
    try std.testing.expect(c.chmod(exe, 0o700) == 0);
    try service.install(a, io, config, std.mem.span(source));
    try std.testing.expectEqual(@as(c.mode_t, 0o755), (try fileStat(config.executable)).st_mode & 0o777);
    const directory = try std.fmt.allocPrint(a, "{s}/pki", .{config.state_dir});
    defer a.free(directory);
    const ca = try std.fmt.allocPrint(a, "{s}/ca.pem", .{directory});
    defer a.free(ca);
    const retained = try std.Io.Dir.cwd().readFileAlloc(io, ca, a, .limited(1 << 20));
    defer a.free(retained);
    try std.testing.expect(try service.systemTrusted(a, io, ca));
    config.profile.scheme = "http";
    try service.install(a, io, config, std.mem.span(source));
    try std.testing.expect(!try service.systemTrusted(a, io, ca));
    try std.testing.expectError(error.FileNotFound, fileStat(config.ca_export));
    var authority = try pki.Authority.init(a, io, directory);
    defer authority.deinit();
    const ctx = try authority.serverContext("manual.local");
    defer c.SSL_CTX_free(ctx);
    const certificate = try std.fmt.allocPrint(a, "{s}/manual-cert.pem", .{config.state_dir});
    defer a.free(certificate);
    const key = try std.fmt.allocPrint(a, "{s}/manual-key.pem", .{config.state_dir});
    defer a.free(key);
    try writeTLSFile(certificate, c.SSL_CTX_get0_certificate(ctx), null);
    try writeTLSFile(key, null, c.SSL_CTX_get0_privatekey(ctx));
    config.profile.scheme = "https";
    config.profile.cert = certificate;
    config.profile.key = key;
    try service.install(a, io, config, std.mem.span(source));
    try std.testing.expect(!try service.systemTrusted(a, io, ca));
    try std.testing.expectError(error.FileNotFound, fileStat(config.ca_export));
    config.profile.cert = null;
    config.profile.key = null;
    try service.install(a, io, config, std.mem.span(source));
    try std.testing.expect(try service.systemTrusted(a, io, ca));
    const restored = try std.Io.Dir.cwd().readFileAlloc(io, ca, a, .limited(1 << 20));
    defer a.free(restored);
    try std.testing.expectEqualStrings(retained, restored);
    try service.uninstall(a, io, config);
    try service.uninstall(a, io, config); // Exact retained-state cleanup is idempotent.
    try std.testing.expect(!try service.loaded(a, io, config));
    try std.testing.expect(!try service.systemTrusted(a, io, ca));
    const preserved = try std.Io.Dir.cwd().readFileAlloc(io, ca, a, .limited(1 << 20));
    defer a.free(preserved);
    try std.testing.expectEqualStrings(retained, preserved);
    try fixture.cleanup();
    cleaned = true;
}

test "installed service binary version is probed only from a protected file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "dotlocal-zig" });
    defer a.free(path);
    const owner = c.getuid();
    try std.testing.expect((try service.executableVersion(arena.allocator(), io, path, owner)) == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "dotlocal-zig", .data = "#!/bin/sh\n[ \"$1\" = version ] && echo 0.3.0\n", .flags = .{ .permissions = .fromMode(0o755) } });
    const version = (try service.executableVersion(arena.allocator(), io, path, owner)).?;
    try std.testing.expectEqualStrings("0.3.0", version);
    // A newer installed binary is kept; an older or equal one is replaced.
    try std.testing.expect(@import("../src/update.zig").newer(version, "0.2.0"));
    try std.testing.expect(!@import("../src/update.zig").newer(version, "0.3.0"));
    // Wrong owner or a writable file is never executed.
    try std.testing.expectError(error.UnsafeArtifact, service.executableVersion(arena.allocator(), io, path, owner + 1));
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    _ = std.c.chmod(z, 0o777);
    try std.testing.expectError(error.UnsafeArtifact, service.executableVersion(arena.allocator(), io, path, owner));
}
