//! Self-update end to end: real update-test CLI builds replace themselves from
//! signed releases served over local HTTPS with a test CA, and the installer
//! script installs from the same server.
const std = @import("std");
const t = @import("test_support.zig");
const lib = t.lib;
const Ed25519 = std.crypto.sign.Ed25519;

const Ctx = struct {
    f: *t.Fixture,
    v1: []const u8,
    v2: []const u8,
    home: []const u8,
    install: []const u8,
    www: []const u8,
    ca: []const u8,
    origin: []const u8,
    target: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.ExpectedTwoCliVersionsFixtureAndInstaller;
    var paths: [4][]const u8 = undefined;
    for (&paths, args[1..]) |*item, arg| item.* = try std.Io.Dir.cwd().realPathFileAlloc(init.io, arg, init.arena.allocator());

    var f = try t.Fixture.init(init, "", paths[2], "https");
    defer f.cleanup();
    const a = f.a;
    for ([_][]const u8{ "DOTLOCAL_AUTO_UPDATE", "DOTLOCAL_CHANNEL", "DOTLOCAL_PIN", "DOTLOCAL_INSTALL_BASE", "DOTLOCAL_INSTALL_DIR", "CURL_CA_BUNDLE", "SSL_CERT_FILE" }) |key| _ = f.env.swapRemove(key);
    const home = try dir(&f, "home");
    const install = try dir(&f, "bin");
    const www = try dir(&f, "www");
    f.binary = try std.fs.path.join(a, &.{ install, "dotlocal" });
    try f.env.put("HOME", home);

    const ca = try certificates(&f);
    const port = try t.port(a);
    var server_env = try f.env.clone(a);
    defer server_env.deinit();
    try server_env.put("PORT", try t.number(a, port));
    var server = try t.Child.start(f.io, &.{ f.server, "tls", try path(&f, "leaf.pem"), try path(&f, "leaf.key"), "static", www }, &server_env, f.base, f.log);
    defer server.cleanup();
    try ready(&f, port);

    var ctx: Ctx = .{ .f = &f, .v1 = paths[0], .v2 = paths[1], .home = home, .install = install, .www = www, .ca = ca, .origin = try std.fmt.allocPrint(a, "https://127.0.0.1:{d}/", .{port}), .target = lib.manifest.currentTarget() orelse return error.UnsupportedPlatform };
    const key = Ed25519.KeyPair.generate(f.io);
    try publish(&ctx, key);
    var key_text: [44]u8 = undefined;
    try f.env.put("DOTLOCAL_UPDATE_BASE_URL", try std.fmt.allocPrint(a, "{s}channels/", .{ctx.origin}));
    try f.env.put("DOTLOCAL_UPDATE_ASSET_PREFIX", ctx.origin);
    try f.env.put("DOTLOCAL_UPDATE_CA", ca);
    try f.env.put("DOTLOCAL_UPDATE_TEST_KEY", std.base64.standard.Encoder.encode(&key_text, &key.public_key.toBytes()));

    try manualUpdates(&ctx);
    try tampering(&ctx);
    try disabled(&ctx);
    try background(&ctx);
    try installer(&ctx, paths[3]);
    std.debug.print("PASS self-update and installer against signed local HTTPS releases\n", .{});
}

/// check, update, rollback with pin, pin blocks background, update unpins.
fn manualUpdates(ctx: *Ctx) !void {
    const f = ctx.f;
    try installVersion(ctx, ctx.v1);
    const check = try f.command(&.{ "update", "--check" }, 0);
    try t.check(std.mem.indexOf(u8, check.stdout, "0.2.0 available") != null, check.stdout);
    try t.equal(try version(ctx), "0.1.0");

    const updated = try f.command(&.{"update"}, 0);
    try t.check(std.mem.indexOf(u8, updated.stdout, "dotlocal updated 0.1.0 → 0.2.0") != null, updated.stdout);
    try t.equal(try version(ctx), "0.2.0");
    try onlyBinary(ctx);

    _ = try f.command(&.{ "update", "--version", "0.1.0" }, 0);
    try t.equal(try version(ctx), "0.1.0");
    try t.equal(try configGet(ctx, "pin"), "\"0.1.0\"");
    // A due check would normally start a background update; the pin blocks it.
    try forgetState(ctx);
    _ = try f.command(&.{"list"}, 1);
    try std.Io.sleep(f.io, .fromSeconds(2), .awake);
    try t.equal(try version(ctx), "0.1.0");
    try t.check(!try exists(ctx, "update.json"), "pinned run started a background check");

    _ = try f.command(&.{"update"}, 0);
    try t.equal(try version(ctx), "0.2.0");
    try t.equal(try configGet(ctx, "pin"), "null");
    std.debug.print("PASS update check, update, pinned rollback, pin blocks background, update unpins\n", .{});
}

/// A changed archive or a foreign signature fails and leaves the binary alone.
fn tampering(ctx: *Ctx) !void {
    const f = ctx.f;
    try installVersion(ctx, ctx.v1);
    for ([_][2][]const u8{ .{ "tampered", "ChecksumMismatch" }, .{ "foreign", "BadSignature" } }) |case| {
        try f.env.put("DOTLOCAL_UPDATE_BASE_URL", try std.fmt.allocPrint(f.a, "{s}{s}/channels/", .{ ctx.origin, case[0] }));
        const result = try f.command(&.{"update"}, 1);
        try t.check(std.mem.indexOf(u8, result.stderr, case[1]) != null, result.stderr);
        try sameBinary(ctx, ctx.v1);
        try onlyBinary(ctx);
    }
    try f.env.put("DOTLOCAL_UPDATE_BASE_URL", try std.fmt.allocPrint(f.a, "{s}channels/", .{ctx.origin}));
    std.debug.print("PASS tampered archive and foreign signature leave the binary unchanged\n", .{});
}

/// DOTLOCAL_AUTO_UPDATE=0 never starts a background update, even when due.
fn disabled(ctx: *Ctx) !void {
    const f = ctx.f;
    try installVersion(ctx, ctx.v1);
    const stale = "{\"last_check\":0}";
    try writeState(ctx, stale);
    try f.env.put("DOTLOCAL_AUTO_UPDATE", "0");
    defer _ = f.env.swapRemove("DOTLOCAL_AUTO_UPDATE");
    _ = try f.command(&.{"list"}, 1);
    try std.Io.sleep(f.io, .fromSeconds(2), .awake);
    try sameBinary(ctx, ctx.v1);
    try t.equal(try readState(ctx), stale);
    std.debug.print("PASS DOTLOCAL_AUTO_UPDATE=0 skips due background updates\n", .{});
}

/// An ordinary command starts a detached update; the next run reports it once.
fn background(ctx: *Ctx) !void {
    const f = ctx.f;
    try installVersion(ctx, ctx.v1);
    try forgetState(ctx);
    _ = try f.command(&.{"list"}, 1);
    var state: []const u8 = "";
    for (0..200) |_| {
        state = readState(ctx) catch "";
        if (std.mem.indexOf(u8, state, "\"notice_to\":\"0.2.0\"") != null) break;
        try std.Io.sleep(f.io, .fromMilliseconds(50), .awake);
    } else {
        std.debug.print("update.json: {s}\n", .{state});
        return error.BackgroundUpdateMissing;
    }
    try t.equal(try version(ctx), "0.2.0");
    try onlyBinary(ctx);
    const next = try f.command(&.{"list"}, 1);
    try t.check(std.mem.indexOf(u8, next.stderr, "dotlocal updated 0.1.0 → 0.2.0") != null, next.stderr);
    const after = try f.command(&.{"list"}, 1);
    try t.check(std.mem.indexOf(u8, after.stderr, "dotlocal updated") == null, "update notice repeated");
    std.debug.print("PASS background update and one-time notice\n", .{});
}

/// release/install.sh installs the newest release for this platform.
fn installer(ctx: *Ctx, script: []const u8) !void {
    const f = ctx.f;
    _ = try run(f, &.{ "sh", "-n", script }, &f.env);
    var env = try f.env.clone(f.a);
    defer env.deinit();
    try env.put("DOTLOCAL_INSTALL_BASE", try std.fmt.allocPrint(f.a, "{s}channels", .{ctx.origin}));
    try env.put("CURL_CA_BUNDLE", ctx.ca);
    // Reinstalling stable after nightly returns to the stable channel.
    for ([_][]const u8{ "stable", "nightly", "stable" }) |channel| {
        const target = try std.fs.path.join(f.a, &.{ f.base, "installed", channel });
        try env.put("DOTLOCAL_INSTALL_DIR", target);
        const result = try run(f, &.{ "sh", script, try std.fmt.allocPrint(f.a, "--{s}", .{channel}) }, &env);
        const binary = try std.fs.path.join(f.a, &.{ target, "dotlocal" });
        try t.check(std.mem.indexOf(u8, result.stdout, try std.fmt.allocPrint(f.a, "Installed dotlocal 0.2.0 ({s}) to {s}", .{ channel, binary })) != null, result.stdout);
        try t.check(std.mem.indexOf(u8, result.stdout, "Add ") != null and std.mem.indexOf(u8, result.stdout, "to your PATH") != null, "installer printed no PATH hint");
        try t.equal(std.mem.trim(u8, (try run(f, &.{ binary, "version" }, &env)).stdout, "\n"), "0.2.0");
        try t.check(try mode(f, binary) == 0o755, "installed binary mode is not 0755");
        try t.equal(std.mem.trim(u8, (try run(f, &.{ binary, "config", "get", "channel" }, &env)).stdout, "\n"), if (std.mem.eql(u8, channel, "nightly")) "\"nightly\"" else "null");
    }
    std.debug.print("PASS installer: stable and nightly install, checksum, mode, PATH hint, channel recorded\n", .{});
}

/// Archives for 0.1.0 and 0.2.0 plus signed stable/nightly manifests, a
/// tampered copy and one signed by a foreign key.
fn publish(ctx: *Ctx, key: Ed25519.KeyPair) !void {
    const a = ctx.f.a;
    const sums = .{ try archive(ctx, ctx.v1, "0.1.0", "assets"), try archive(ctx, ctx.v2, "0.2.0", "assets") };
    const releases = [_]lib.manifest.RenderRelease{
        try release(ctx, "0.2.0", "assets", sums[1]),
        try release(ctx, "0.1.0", "assets", sums[0]),
    };
    try sign(ctx, "channels", .stable, &releases, key);
    try sign(ctx, "channels", .nightly, releases[0..1], key);

    const tampered_sum = try archive(ctx, ctx.v2, "0.2.0", "tampered");
    const name = try std.fmt.allocPrint(a, "tampered/dotlocal-0.2.0-{s}.tar.gz", .{ctx.target});
    const bytes = try std.Io.Dir.cwd().readFileAlloc(ctx.f.io, try std.fs.path.join(a, &.{ ctx.www, name }), a, .limited(128 << 20));
    bytes[bytes.len - 1] ^= 0xff;
    try std.Io.Dir.cwd().writeFile(ctx.f.io, .{ .sub_path = try std.fs.path.join(a, &.{ ctx.www, name }), .data = bytes });
    try sign(ctx, "tampered/channels", .stable, &.{try release(ctx, "0.2.0", "tampered", tampered_sum)}, key);
    try sign(ctx, "foreign/channels", .stable, &releases, Ed25519.KeyPair.generate(ctx.f.io));
}

fn release(ctx: *Ctx, v: []const u8, folder: []const u8, sum: [64]u8) !lib.manifest.RenderRelease {
    const a = ctx.f.a;
    const assets = try a.alloc(lib.manifest.RenderAsset, 1);
    assets[0] = .{ .target = ctx.target, .url = try std.fmt.allocPrint(a, "{s}{s}/dotlocal-{s}-{s}.tar.gz", .{ ctx.origin, folder, v, ctx.target }), .sha256 = try a.dupe(u8, &sum) };
    return .{ .version = v, .commit = "0000000000000000000000000000000000000000", .published = "2026-10-10T00:00:00Z", .assets = assets };
}

fn sign(ctx: *Ctx, folder: []const u8, channel: lib.manifest.Channel, releases: []const lib.manifest.RenderRelease, key: Ed25519.KeyPair) !void {
    const a = ctx.f.a;
    const body = try lib.manifest.render(a, channel, releases);
    const signature = try lib.manifest.sign(body, key);
    const base = try std.fmt.allocPrint(a, "{s}/{s}/{t}.json", .{ ctx.www, folder, channel });
    try std.Io.Dir.cwd().createDirPath(ctx.f.io, std.fs.path.dirname(base).?);
    try std.Io.Dir.cwd().writeFile(ctx.f.io, .{ .sub_path = base, .data = body });
    try std.Io.Dir.cwd().writeFile(ctx.f.io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}.sig", .{base}), .data = &signature });
}

/// Packages `binary` as the release archive layout: a single `dotlocal` entry.
fn archive(ctx: *Ctx, binary: []const u8, v: []const u8, folder: []const u8) ![64]u8 {
    const f = ctx.f;
    const stage = try std.fs.path.join(f.a, &.{ f.base, "stage", folder, v });
    try std.Io.Dir.cwd().createDirPath(f.io, stage);
    try std.Io.Dir.copyFileAbsolute(binary, try std.fs.path.join(f.a, &.{ stage, "dotlocal" }), f.io, .{ .replace = true });
    const out = try std.fs.path.join(f.a, &.{ ctx.www, folder, try std.fmt.allocPrint(f.a, "dotlocal-{s}-{s}.tar.gz", .{ v, ctx.target }) });
    try std.Io.Dir.cwd().createDirPath(f.io, std.fs.path.dirname(out).?);
    _ = try run(f, &.{ "tar", "-czf", out, "-C", stage, "dotlocal" }, &f.env);
    return digest(f, out);
}

/// A test CA and an IP-address leaf for 127.0.0.1; returns the CA path.
fn certificates(f: *t.Fixture) ![]const u8 {
    const ca_key = try path(f, "ca.key");
    const ca = try path(f, "ca.pem");
    try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = try path(f, "leaf.ext"), .data = "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" });
    _ = try run(f, &.{ "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", ca_key, "-out", ca, "-days", "2", "-subj", "/CN=dotlocal update test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign" }, &f.env);
    _ = try run(f, &.{ "openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", try path(f, "leaf.key"), "-out", try path(f, "leaf.csr"), "-subj", "/CN=127.0.0.1" }, &f.env);
    _ = try run(f, &.{ "openssl", "x509", "-req", "-in", try path(f, "leaf.csr"), "-CA", ca, "-CAkey", ca_key, "-set_serial", "7", "-days", "2", "-extfile", try path(f, "leaf.ext"), "-out", try path(f, "leaf.pem") }, &f.env);
    return ca;
}

fn ready(f: *t.Fixture, port: u16) !void {
    for (0..200) |_| {
        if (t.net.tcp(f.a, "127.0.0.1", port, false)) |fd| {
            t.net.close(fd);
            return;
        } else |_| {}
        try std.Io.sleep(f.io, .fromMilliseconds(25), .awake);
    }
    try f.diagnostics();
    return error.ServerNotReady;
}

/// Replaces the installed binary with a fresh copy (new inode) of `binary`.
fn installVersion(ctx: *Ctx, binary: []const u8) !void {
    try std.Io.Dir.copyFileAbsolute(binary, ctx.f.binary, ctx.f.io, .{ .replace = true });
}

fn version(ctx: *Ctx) ![]const u8 {
    return std.mem.trim(u8, (try ctx.f.command(&.{"version"}, 0)).stdout, " \r\n");
}

fn configGet(ctx: *Ctx, name: []const u8) ![]const u8 {
    return std.mem.trim(u8, (try ctx.f.command(&.{ "config", "get", name }, 0)).stdout, " \r\n");
}

fn sameBinary(ctx: *Ctx, expected: []const u8) !void {
    try t.check(std.mem.eql(u8, &try digest(ctx.f, ctx.f.binary), &try digest(ctx.f, expected)), "installed binary changed");
}

/// No staging files remain beside the installed binary.
fn onlyBinary(ctx: *Ctx) !void {
    var d = try std.Io.Dir.cwd().openDir(ctx.f.io, ctx.install, .{ .iterate = true });
    defer d.close(ctx.f.io);
    var it = d.iterate();
    while (try it.next(ctx.f.io)) |entry| try t.check(std.mem.eql(u8, entry.name, "dotlocal"), entry.name);
}

fn statePath(ctx: *Ctx, name: []const u8) ![]const u8 {
    return std.fs.path.join(ctx.f.a, &.{ ctx.home, ".dotlocal", name });
}

fn exists(ctx: *Ctx, name: []const u8) !bool {
    std.Io.Dir.cwd().access(ctx.f.io, try statePath(ctx, name), .{}) catch |err| return if (err == error.FileNotFound) false else err;
    return true;
}

fn forgetState(ctx: *Ctx) !void {
    std.Io.Dir.cwd().deleteFile(ctx.f.io, try statePath(ctx, "update.json")) catch |err| if (err != error.FileNotFound) return err;
}

fn readState(ctx: *Ctx) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(ctx.f.io, try statePath(ctx, "update.json"), ctx.f.a, .limited(4096));
}

fn writeState(ctx: *Ctx, bytes: []const u8) !void {
    const state = try statePath(ctx, "update.json");
    try std.Io.Dir.cwd().createDirPath(ctx.f.io, std.fs.path.dirname(state).?);
    try std.Io.Dir.cwd().writeFile(ctx.f.io, .{ .sub_path = state, .data = bytes, .flags = .{ .permissions = .fromMode(0o600) } });
}

fn digest(f: *t.Fixture, file: []const u8) ![64]u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(f.io, file, f.a, .limited(128 << 20));
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sum, .{});
    return std.fmt.bytesToHex(sum, .lower);
}

fn mode(f: *t.Fixture, file: []const u8) !c_uint {
    var stat: t.c.struct_stat = undefined;
    if (t.c.lstat(try f.a.dupeSentinel(u8, file, 0), &stat) != 0) return error.StatFailed;
    return @intCast(stat.st_mode & 0o777);
}

fn path(f: *t.Fixture, name: []const u8) ![]const u8 {
    return std.fs.path.join(f.a, &.{ f.base, name });
}

/// A private directory beneath the fixture base.
fn dir(f: *t.Fixture, name: []const u8) ![]const u8 {
    const full = try path(f, name);
    try std.Io.Dir.cwd().createDirPath(f.io, full);
    if (t.c.chmod(try f.a.dupeSentinel(u8, full, 0), 0o700) != 0) return error.PermissionsFailed;
    return full;
}

fn run(f: *t.Fixture, argv: []const []const u8, env: *const std.process.Environ.Map) !std.process.RunResult {
    const result = try std.process.run(f.a, f.io, .{ .argv = argv, .environ_map = env, .cwd = .{ .path = f.base }, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20), .timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } } });
    if (!result.term.success()) {
        std.debug.print("{s}: {f}\n{s}\n{s}\n", .{ argv[0], result.term, result.stdout, result.stderr });
        return error.CommandFailed;
    }
    return result;
}
