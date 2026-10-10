const std = @import("std");
const manifest = @import("../src/manifest.zig");
const a = std.testing.allocator;
const Ed25519 = std.crypto.sign.Ed25519;

const sample =
    \\{"schema":1,"channel":"stable","releases":[
    \\{"version":"0.2.0","commit":"abc","published":"2026-10-10T06:00:00Z","assets":{
    \\"aarch64-macos":{"url":"https://github.com/euforicio/dotlocal/releases/download/v0.2.0/dotlocal-0.2.0-macos-aarch64.tar.gz","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}},
    \\{"version":"0.1.9","commit":"def","published":"2026-10-01T06:00:00Z","assets":{
    \\"aarch64-macos":{"url":"https://github.com/euforicio/dotlocal/releases/download/v0.1.9/dotlocal-0.1.9-macos-aarch64.tar.gz","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}}]}
;
const prefix = "https://github.com/euforicio/dotlocal/releases/download/";

test "manifest parses strictly and rejects unsafe content" {
    var parsed = try manifest.parse(a, sample, .stable, prefix);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.releases.len);
    try std.testing.expectError(error.ChannelMismatch, manifest.parse(a, sample, .nightly, prefix));
    try std.testing.expectError(error.UntrustedAssetUrl, manifest.parse(a, sample, .stable, "https://example.com/"));
    for ([_][]const u8{ "../../evil", "v0.2.0/%2e%2e/x", "v0.2.0/x?y", "v0.2.0/x#y", "v0.2.0\\\\x", "v0.2.0/a b" }) |bad| {
        const url = try std.mem.concat(a, u8, &.{ prefix, bad });
        defer a.free(url);
        const tampered = try std.mem.replaceOwned(u8, a, sample, prefix ++ "v0.2.0/dotlocal-0.2.0-macos-aarch64.tar.gz", url);
        defer a.free(tampered);
        try std.testing.expectError(error.UntrustedAssetUrl, manifest.parse(a, tampered, .stable, prefix));
    }
    const unknown = try std.mem.replaceOwned(u8, a, sample, "\"schema\":1", "\"schema\":1,\"extra\":true");
    defer a.free(unknown);
    try std.testing.expectError(error.UnknownField, manifest.parse(a, unknown, .stable, prefix));
    const big = try a.alloc(u8, manifest.max_bytes + 1);
    defer a.free(big);
    @memset(big, ' ');
    try std.testing.expectError(error.ManifestTooLarge, manifest.parse(a, big, .stable, prefix));
}

test "signatures verify only against a trusted key" {
    const trusted = Ed25519.KeyPair.generate(std.testing.io);
    const other = Ed25519.KeyPair.generate(std.testing.io);
    const sig = try trusted.sign(sample, null);
    var encoded: [manifest.signature_text_len]u8 = undefined;
    const text = std.base64.standard.Encoder.encode(&encoded, &sig.toBytes());
    try manifest.verify(sample, text, &.{trusted.public_key.toBytes()});
    try std.testing.expectError(error.BadSignature, manifest.verify(sample, text, &.{other.public_key.toBytes()}));
    try std.testing.expectError(error.BadSignature, manifest.verify(sample[1..], text, &.{trusted.public_key.toBytes()}));
}

test "selection follows channel, downgrade and rollback rules" {
    var parsed = try manifest.parse(a, sample, .stable, prefix);
    defer parsed.deinit();
    const releases = parsed.value.releases;
    try std.testing.expectEqualStrings("0.2.0", (try manifest.select(releases, "0.1.9", .automatic)).?.version);
    try std.testing.expect((try manifest.select(releases, "0.2.0", .automatic)) == null);
    try std.testing.expect((try manifest.select(releases, "0.3.0", .automatic)) == null); // never downgrade
    try std.testing.expectEqualStrings("0.1.9", (try manifest.select(releases, "0.2.0", .{ .exact = "0.1.9" })).?.version);
    try std.testing.expectError(error.VersionNotAvailable, manifest.select(releases, "0.2.0", .{ .exact = "0.1.0" }));
    try std.testing.expectEqualStrings("0.2.0", (try manifest.select(releases, "0.2.1-nightly.20261010", .channel_switch)).?.version);
}

test "target names match release archive naming" {
    try std.testing.expectEqualStrings("aarch64-macos", manifest.targetName(.aarch64, .macos).?);
    try std.testing.expectEqualStrings("x86_64-linux", manifest.targetName(.x86_64, .linux).?);
    try std.testing.expect(manifest.targetName(.riscv64, .linux) == null);
}

test "rendered manifests round-trip through parse and verify" {
    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const assets = [_]manifest.RenderAsset{.{ .target = "aarch64-macos", .url = prefix ++ "v0.2.0/dotlocal-0.2.0-macos-aarch64.tar.gz", .sha256 = "0000000000000000000000000000000000000000000000000000000000000000" }};
    const json = try manifest.render(a, .stable, &.{.{ .version = "0.2.0", .commit = "abc", .published = "2026-10-10T06:00:00Z", .assets = &assets }});
    defer a.free(json);
    const sig = try manifest.sign(json, kp);
    try manifest.verify(json, &sig, &.{kp.public_key.toBytes()});
    var parsed = try manifest.parse(a, json, .stable, prefix);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("abc", parsed.value.releases[0].commit);
}

const userconfig = @import("../src/userconfig.zig");

test "user config is strict, private and round-trips edits atomically" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(dir);
    const path = try std.fs.path.join(a, &.{ dir, "config.json" });
    defer a.free(path);
    var empty = try userconfig.load(a, io, path);
    defer empty.deinit();
    try std.testing.expect(empty.value.auto_update == null);
    try userconfig.set(a, io, path, "auto_update", "false");
    try userconfig.set(a, io, path, "tld", ".test");
    try userconfig.set(a, io, path, "channel", "nightly");
    var loaded = try userconfig.load(a, io, path);
    defer loaded.deinit();
    try std.testing.expectEqual(false, loaded.value.auto_update.?);
    try std.testing.expectEqualStrings(".test", loaded.value.tld.?);
    try std.testing.expectError(error.UnknownConfigKey, userconfig.set(a, io, path, "nope", "1"));
    try std.testing.expectError(error.InvalidConfigValue, userconfig.set(a, io, path, "port", "70000"));
    try std.testing.expectError(error.InvalidConfigValue, userconfig.set(a, io, path, "channel", "beta"));
    try userconfig.unset(a, io, path, "tld");
    var after = try userconfig.load(a, io, path);
    defer after.deinit();
    try std.testing.expect(after.value.tld == null);
    // Group/world-writable files are refused.
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    _ = std.c.chmod(z, 0o666);
    try std.testing.expectError(error.UnsafeConfigFile, userconfig.load(a, io, path));
}

test "user config fills only missing environment defaults" {
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    try env.put("DOTLOCAL_TLD", ".flag");
    const config: userconfig.Config = .{ .tld = ".file", .https = false, .auto_update = false };
    try userconfig.applyDefaults(config, &env);
    try std.testing.expectEqualStrings(".flag", env.get("DOTLOCAL_TLD").?);
    try std.testing.expectEqualStrings("0", env.get("DOTLOCAL_HTTPS").?);
    try std.testing.expectEqualStrings("0", env.get("DOTLOCAL_AUTO_UPDATE").?);
}

const update = @import("../src/update.zig");

fn writeExecutable(dir: std.Io.Dir, name: []const u8, version: []const u8) !void {
    const script = try std.fmt.allocPrint(a, "#!/bin/sh\n[ \"$1\" = version ] && echo {s}\n", .{version});
    defer a.free(script);
    try dir.writeFile(std.testing.io, .{ .sub_path = name, .data = script, .flags = .{ .permissions = .fromMode(0o755) } });
}

test "archives extract, verify version and replace the target atomically" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    try tmp.dir.createDirPath(io, "pkg");
    var pkg = try tmp.dir.openDir(io, "pkg", .{});
    defer pkg.close(io);
    try writeExecutable(pkg, "dotlocal", "0.2.0");
    const archive = try std.fs.path.join(a, &.{ root, "dotlocal.tar.gz" });
    defer a.free(archive);
    const pkg_path = try std.fs.path.join(a, &.{ root, "pkg" });
    defer a.free(pkg_path);
    const tar = try std.process.run(a, io, .{ .argv = &.{ "tar", "-czf", archive, "-C", pkg_path, "dotlocal" } });
    defer a.free(tar.stdout);
    defer a.free(tar.stderr);
    try std.testing.expect(tar.term == .exited and tar.term.exited == 0);
    try writeExecutable(tmp.dir, "installed", "0.1.0");
    const target = try std.fs.path.join(a, &.{ root, "installed" });
    defer a.free(target);
    const bytes = try tmp.dir.readFileAlloc(io, "dotlocal.tar.gz", a, .limited(1 << 20));
    defer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectError(error.ChecksumMismatch, update.install(a, io, bytes, &@as([64]u8, @splat('0')), "0.2.0", target));
    try std.testing.expectError(error.VersionMismatch, update.install(a, io, bytes, &hex, "0.3.0", target));
    try update.install(a, io, bytes, &hex, "0.2.0", target);
    const installed = try update.probeVersion(a, io, target);
    defer a.free(installed);
    try std.testing.expectEqualStrings("0.2.0", installed);
    // No temp files are left beside the target.
    var it = tmp.dir.iterate();
    while (try it.next(io)) |entry| try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".dotlocal-update-"));
}

test "update state throttles checks to once per interval" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "update.json" });
    defer a.free(path);
    try std.testing.expect(try update.due(a, io, path, 1_000_000));
    try update.recordCheck(a, io, path, 1_000_000, null);
    try std.testing.expect(!(try update.due(a, io, path, 1_000_000 + 3600)));
    try std.testing.expect(try update.due(a, io, path, 1_000_000 + update.interval_seconds));
    try update.recordCheck(a, io, path, 1_000_000, .{ .from = "0.1.0", .to = "0.2.0" });
    const note = (try update.takeNotice(a, io, path)).?;
    defer a.free(note);
    try std.testing.expectEqualStrings("dotlocal updated 0.1.0 → 0.2.0", note);
    try std.testing.expect((try update.takeNotice(a, io, path)) == null);
}

test "update lock admits one updater at a time" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "update.lock" });
    defer a.free(path);
    const held = try update.lock(io, path);
    try std.testing.expectError(error.WouldBlock, update.lock(io, path));
    held.close(io);
    const again = try update.lock(io, path);
    again.close(io);
    // Network paths are exercised by the integration suite; keep them analysed here.
    _ = &update.check;
    _ = &update.apply;
}

test "key decoding requires exactly 32 bytes" {
    _ = try manifest.decodeKey(" 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n");
    try std.testing.expectError(error.InvalidKey, manifest.decodeKey("AAAA"));
    try std.testing.expectError(error.InvalidKey, manifest.decodeKey("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURoAAAA="));
    try std.testing.expectError(error.InvalidKey, manifest.decodeKey("not base64!"));
}

test "public key files hold one key per line and check the signing key" {
    const old = Ed25519.KeyPair.generate(std.testing.io);
    const new = Ed25519.KeyPair.generate(std.testing.io);
    const other = Ed25519.KeyPair.generate(std.testing.io);
    var text: [3][44]u8 = undefined;
    for ([_]Ed25519.KeyPair{ old, new, other }, &text) |kp, *out| _ = std.base64.standard.Encoder.encode(out, &kp.public_key.toBytes());
    var seeds: [3][44]u8 = undefined;
    for ([_]Ed25519.KeyPair{ old, new, other }, &seeds) |kp, *out| _ = std.base64.standard.Encoder.encode(out, &kp.secret_key.seed());
    const file = try std.fmt.allocPrint(a, "{s}\n\n  {s}\r\n", .{ &text[0], &text[1] });
    defer a.free(file);
    var buffer: [8][32]u8 = undefined;
    const keys = try manifest.decodeKeys(file, &buffer);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualSlices(u8, &new.public_key.toBytes(), &keys[1]);
    try manifest.checkSigningKey(&seeds[0], file);
    try manifest.checkSigningKey(&seeds[1], file);
    try std.testing.expectError(error.BadSignature, manifest.checkSigningKey(&seeds[2], file));
    try std.testing.expectError(error.InvalidKey, manifest.decodeKeys("\n \n", &buffer));
    var one: [1][32]u8 = undefined;
    try std.testing.expectError(error.InvalidKey, manifest.decodeKeys(file, &one));
    try std.testing.expect(@import("../src/release_keys.zig").keys.len >= 1);
}

test "a stalled server times out instead of holding the update lock" {
    const io = std.testing.io;
    // The kernel completes the handshake on the backlog; nothing ever replies.
    var server = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer server.deinit(io);
    const base = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/", .{server.socket.address.ip4.port});
    defer a.free(base);
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, update.check(a, io, .{ .manifest_base_url = base, .manifest_timeout_ms = 200 }, .stable, "0.1.0", .automatic));
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try std.testing.expect(elapsed >= 200 and elapsed < 5_000);
}

fn tarArchive(root: []const u8, out: []const u8, entries: []const []const u8) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);
    const archive = try std.fs.path.join(a, &.{ root, out });
    errdefer a.free(archive);
    try argv.appendSlice(a, &.{ "tar", "-czf", archive, "-C", root });
    try argv.appendSlice(a, entries);
    const result = try std.process.run(a, std.testing.io, .{ .argv = argv.items });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try std.testing.expect(result.term == .exited and result.term.exited == 0);
    return archive;
}

test "archives must hold exactly one top-level dotlocal" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    try tmp.dir.createDirPath(io, "docs");
    var docs = try tmp.dir.openDir(io, "docs", .{});
    defer docs.close(io);
    try writeExecutable(docs, "dotlocal", "0.2.0");
    try writeExecutable(tmp.dir, "dotlocal", "0.2.0");
    try writeExecutable(tmp.dir, "installed", "0.1.0");
    const target = try std.fs.path.join(a, &.{ root, "installed" });
    defer a.free(target);
    const cases = [_]struct { name: []const u8, entries: []const []const u8, err: ?anyerror }{
        .{ .name = "nested.tar.gz", .entries = &.{"docs/dotlocal"}, .err = error.BinaryMissingFromArchive },
        // Two distinct files: GNU tar stores a repeated path as a hard link.
        .{ .name = "twice.tar.gz", .entries = &.{ "dotlocal", "-C", "docs", "./dotlocal" }, .err = error.AmbiguousArchive },
        .{ .name = "mixed.tar.gz", .entries = &.{ "docs/dotlocal", "./dotlocal" }, .err = null },
    };
    for (cases) |case| {
        const archive = try tarArchive(root, case.name, case.entries);
        defer a.free(archive);
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, archive, a, .limited(1 << 20));
        defer a.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        if (case.err) |err| {
            try std.testing.expectError(err, update.install(a, io, bytes, &hex, "0.2.0", target));
        } else try update.install(a, io, bytes, &hex, "0.2.0", target);
        var it = tmp.dir.iterate();
        while (try it.next(io)) |entry| try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".dotlocal-update-"));
    }
    const installed = try update.probeVersion(a, io, target);
    defer a.free(installed);
    try std.testing.expectEqualStrings("0.2.0", installed);
}

test "install refuses a directory others can write" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try writeExecutable(tmp.dir, "installed", "0.1.0");
    try tmp.dir.setPermissions(io, .fromMode(0o777));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const target = try std.fs.path.join(a, &.{ root, "installed" });
    defer a.free(target);
    const archive = "not reached";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectError(error.UnsafeInstallDirectory, update.install(a, io, archive, &hex, "0.2.0", target));
}

test "update state counts failures and tolerates clock skew" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "update.json" });
    defer a.free(path);
    try std.testing.expectEqual(@as(u32, 0), try update.failures(a, io, path));
    try update.recordFailure(a, io, path, 1_000, error.BadSignature);
    try update.recordFailure(a, io, path, 2_000, error.ChecksumMismatch);
    try std.testing.expectEqual(@as(u32, 2), try update.failures(a, io, path));
    try std.testing.expect(!(try update.due(a, io, path, 2_001)));
    // A check recorded in the future (clock moved back) does not stall checks.
    try std.testing.expect(try update.due(a, io, path, 1_500));
    try update.recordCheck(a, io, path, std.math.maxInt(i64), null);
    try std.testing.expectEqual(@as(u32, 0), try update.failures(a, io, path));
    try std.testing.expect(try update.due(a, io, path, std.math.minInt(i64)));
}

test "repeated check failures warn once per new failure" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "update.json" });
    defer a.free(path);
    try std.testing.expect((try update.takeFailureWarning(a, io, path)) == null);
    for (0..update.failure_warning_threshold - 1) |i| try update.recordFailure(a, io, path, @intCast(i), error.BadSignature);
    // Offline checks throttle but never count toward the warning.
    try update.recordFailure(a, io, path, 5, error.ConnectionRefused);
    try update.recordFailure(a, io, path, 6, error.Timeout);
    try std.testing.expect(!(try update.due(a, io, path, 7)));
    try std.testing.expectEqual(update.failure_warning_threshold - 1, try update.failures(a, io, path));
    try std.testing.expect((try update.takeFailureWarning(a, io, path)) == null);
    try update.recordFailure(a, io, path, 10, error.VersionMismatch);
    try std.testing.expectEqual(update.failure_warning_threshold, (try update.takeFailureWarning(a, io, path)).?);
    try std.testing.expect((try update.takeFailureWarning(a, io, path)) == null);
    try update.recordFailure(a, io, path, 20, error.UntrustedAssetUrl);
    try std.testing.expectEqual(update.failure_warning_threshold + 1, (try update.takeFailureWarning(a, io, path)).?);
    try std.testing.expect((try update.takeFailureWarning(a, io, path)) == null);
    try update.recordCheck(a, io, path, 30, null);
    try std.testing.expectEqual(@as(u32, 0), try update.failures(a, io, path));
}

test "update settings resolve from config-filled environment" {
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    const defaults = try update.settings(&env);
    try std.testing.expect(defaults.enabled and defaults.channel == .stable and defaults.pin == null);
    // User config values arrive as DOTLOCAL_* defaults; the environment wins.
    try env.put("DOTLOCAL_CHANNEL", "nightly");
    try userconfig.applyDefaults(.{ .auto_update = false, .channel = "stable", .pin = "0.2.0" }, &env);
    const configured = try update.settings(&env);
    try std.testing.expect(!configured.enabled);
    try std.testing.expectEqual(manifest.Channel.nightly, configured.channel);
    try std.testing.expectEqualStrings("0.2.0", configured.pin.?);
    try env.put("DOTLOCAL_AUTO_UPDATE", "1");
    try env.put("DOTLOCAL_PIN", "");
    const enabled = try update.settings(&env);
    try std.testing.expect(enabled.enabled and enabled.pin == null);
    try env.put("DOTLOCAL_CHANNEL", "beta");
    try std.testing.expectError(error.InvalidChannel, update.settings(&env));
    try env.put("DOTLOCAL_CHANNEL", "stable");
    try env.put("DOTLOCAL_PIN", "latest");
    try std.testing.expectError(error.InvalidPin, update.settings(&env));
}

test "release builds ignore update source overrides" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    try env.put("DOTLOCAL_UPDATE_BASE_URL", "https://127.0.0.1:1/channels/");
    try env.put("DOTLOCAL_UPDATE_TEST_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    const source = try update.sourceFromEnv(arena.allocator(), &env);
    if (@import("../src/release_keys.zig").test_overrides) {
        try std.testing.expectEqualStrings("https://127.0.0.1:1/channels/", source.manifest_base_url);
        try std.testing.expectEqual(@as(usize, 1), source.keys.len);
    } else {
        try std.testing.expectEqualStrings(@import("../src/release_keys.zig").manifest_base_url, source.manifest_base_url);
        try std.testing.expectEqual(@import("../src/release_keys.zig").keys.ptr, source.keys.ptr);
        try std.testing.expect(source.ca_file == null);
    }
}

test "package-managed executables and version ordering" {
    for ([_][]const u8{ "/opt/homebrew/bin/dotlocal", "/usr/local/Cellar/dotlocal/0.2.0/bin/dotlocal", "/nix/store/abc-dotlocal/bin/dotlocal", "/usr/local/Homebrew/bin/dotlocal", "/home/linuxbrew/.linuxbrew/bin/dotlocal" }) |path| try std.testing.expect(update.packageManaged(path));
    for ([_][]const u8{ "/usr/local/bin/dotlocal", "/home/me/.local/bin/dotlocal", "/usr/local/libexec/dotlocal-zig" }) |path| try std.testing.expect(!update.packageManaged(path));
    try std.testing.expect(update.newer("0.2.0", "0.1.9"));
    try std.testing.expect(update.newer("0.2.0", "0.0.0-dev"));
    try std.testing.expect(!update.newer("0.1.9", "0.2.0"));
    try std.testing.expect(!update.newer("0.2.0", "0.2.0"));
    try std.testing.expect(!update.newer("garbage", "0.1.0"));
    try std.testing.expect(update.keepServiceBinary("0.2.0", "0.1.0", null, false));
    try std.testing.expect(!update.keepServiceBinary("0.2.0", "0.1.0", null, true));
    try std.testing.expect(!update.keepServiceBinary("0.2.0", "0.1.0", "0.1.0", false));
    try std.testing.expect(update.keepServiceBinary("0.2.0", "0.1.0", "0.1.5", false));
    try std.testing.expect(!update.keepServiceBinary("0.1.0", "0.2.0", null, false));
    try std.testing.expect(update.isVerificationFailure(error.BadSignature));
    try std.testing.expect(!update.isVerificationFailure(error.ConnectionRefused));
}
