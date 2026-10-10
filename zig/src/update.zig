//! Self-update: fetch a signed channel manifest, download and verify the
//! archive, extract `dotlocal`, probe its version, and atomically replace the
//! target executable. Every failure leaves the target unchanged.
const std = @import("std");
const Io = std.Io;
const A = std.mem.Allocator;
const manifest = @import("manifest.zig");
const release_keys = @import("release_keys.zig");
const process = @import("process.zig");

pub const interval_seconds: i64 = 24 * 60 * 60;
const max_archive = 64 << 20;

/// Effective update policy after user config defaults are applied to the
/// environment (`DOTLOCAL_AUTO_UPDATE`, `DOTLOCAL_CHANNEL`, `DOTLOCAL_PIN`).
pub const Settings = struct { enabled: bool = true, channel: manifest.Channel = .stable, pin: ?[]const u8 = null };

pub fn settings(env: *const std.process.Environ.Map) !Settings {
    const flag = env.get("DOTLOCAL_AUTO_UPDATE");
    const disabled = if (flag) |v| std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "false") else false;
    const channel = std.meta.stringToEnum(manifest.Channel, env.get("DOTLOCAL_CHANNEL") orelse "stable") orelse return error.InvalidChannel;
    const pin = env.get("DOTLOCAL_PIN");
    if (pin) |v| if (v.len != 0) {
        _ = std.SemanticVersion.parse(v) catch return error.InvalidPin;
    };
    return .{ .enabled = !disabled, .channel = channel, .pin = if (pin != null and pin.?.len != 0) pin else null };
}

/// The release source; only `-Dupdate-test` builds read the
/// `DOTLOCAL_UPDATE_*` overrides. Allocations belong to `a` (an arena).
pub fn sourceFromEnv(a: A, env: *const std.process.Environ.Map) !Source {
    var source: Source = .{};
    if (!release_keys.test_overrides) return source;
    if (env.get("DOTLOCAL_UPDATE_BASE_URL")) |v| source.manifest_base_url = v;
    if (env.get("DOTLOCAL_UPDATE_ASSET_PREFIX")) |v| source.asset_url_prefix = v;
    if (env.get("DOTLOCAL_UPDATE_CA")) |v| source.ca_file = v;
    if (env.get("DOTLOCAL_UPDATE_TEST_KEY")) |text| {
        const keys = try a.alloc([std.crypto.sign.Ed25519.PublicKey.encoded_length]u8, 1);
        keys[0] = try manifest.decodeKey(text);
        source.keys = keys;
    }
    return source;
}

pub const Source = struct {
    manifest_base_url: []const u8 = release_keys.manifest_base_url,
    asset_url_prefix: []const u8 = release_keys.asset_url_prefix,
    keys: []const [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8 = release_keys.keys,
    /// Extra PEM CA file trusted for HTTPS (tests only).
    ca_file: ?[]const u8 = null,
    /// Whole-request deadlines; a stalled server must not hold update.lock.
    manifest_timeout_ms: i64 = 5_000,
    archive_timeout_ms: i64 = 120_000,
};

pub const Plan = struct {
    parsed: std.json.Parsed(manifest.Manifest),
    release: manifest.Release,
    asset: manifest.Asset,
    pub fn deinit(self: *Plan) void {
        self.parsed.deinit();
    }
};

/// Returns null when nothing should be installed.
pub fn check(a: A, io: Io, source: Source, channel: manifest.Channel, current: []const u8, selection: manifest.Selection) !?Plan {
    const target = manifest.currentTarget() orelse return error.UnsupportedPlatform;
    var client: std.http.Client = .{ .allocator = a, .io = io };
    defer client.deinit();
    try trustSource(&client, source);
    const base = try std.fmt.allocPrint(a, "{s}{t}.json", .{ source.manifest_base_url, channel });
    defer a.free(base);
    const body = try getWithin(a, &client, base, manifest.max_bytes, source.manifest_timeout_ms);
    defer a.free(body);
    const sig_url = try std.fmt.allocPrint(a, "{s}.sig", .{base});
    defer a.free(sig_url);
    const sig = try getWithin(a, &client, sig_url, 256, source.manifest_timeout_ms);
    defer a.free(sig);
    try manifest.verify(body, sig, source.keys);
    var parsed = try manifest.parse(a, body, channel, source.asset_url_prefix);
    errdefer parsed.deinit();
    const release = (try manifest.select(parsed.value.releases, current, selection)) orelse {
        parsed.deinit();
        return null;
    };
    const asset = release.asset(target) orelse return error.UnsupportedPlatform;
    return .{ .parsed = parsed, .release = release, .asset = asset };
}

/// Downloads the planned asset and installs it over `target_path`.
pub fn apply(a: A, io: Io, source: Source, plan: Plan, target_path: []const u8) !void {
    var client: std.http.Client = .{ .allocator = a, .io = io };
    defer client.deinit();
    try trustSource(&client, source);
    const bytes = try getWithin(a, &client, plan.asset.url, max_archive, source.archive_timeout_ms);
    defer a.free(bytes);
    try install(a, io, bytes, plan.asset.sha256, plan.release.version, target_path);
}

/// A test CA replaces the system roots so tests never reach real hosts.
fn trustSource(client: *std.http.Client, source: Source) !void {
    const ca = source.ca_file orelse return;
    const now = Io.Clock.real.now(client.io);
    try client.ca_bundle.addCertsFromFilePathAbsolute(client.allocator, client.io, now, ca);
    client.now = now;
}

const GetResult = @typeInfo(@TypeOf(get)).@"fn".return_type.?;
const Race = union(enum) { body: GetResult, timer: Io.Cancelable!void };

/// `get` raced against a timer; the loser is canceled and its result freed.
fn getWithin(a: A, client: *std.http.Client, url: []const u8, limit: usize, timeout_ms: i64) ![]u8 {
    const io = client.io;
    var buffer: [2]Race = undefined;
    var race: Io.Select(Race) = .init(io, &buffer);
    try race.concurrent(.body, get, .{ a, client, url, limit });
    race.concurrent(.timer, Io.sleep, .{ io, .fromMilliseconds(timeout_ms), .awake }) catch |err| {
        while (race.cancel()) |rest| discard(a, rest);
        return err;
    };
    const first = race.await() catch |err| {
        while (race.cancel()) |rest| discard(a, rest);
        return err;
    };
    while (race.cancel()) |rest| discard(a, rest);
    return switch (first) {
        .body => |result| result,
        .timer => error.Timeout,
    };
}

fn discard(a: A, result: Race) void {
    switch (result) {
        .body => |body| if (body) |bytes| a.free(bytes) else |_| {},
        .timer => {},
    }
}

/// GET `url` with redirects; refuses non-200 responses and bodies over `limit`.
fn get(a: A, client: *std.http.Client, url: []const u8, limit: usize) ![]u8 {
    var req = try client.request(.GET, try std.Uri.parse(url), .{ .keep_alive = false });
    defer req.deinit();
    try req.sendBodiless();
    var redirect_buffer: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buffer);
    if (response.head.status != .ok) return error.DownloadFailed;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .deflate, .gzip => &window,
        .zstd, .compress => return error.UnsupportedCompressionMethod,
    };
    var transfer_buffer: [64 * 1024]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
    return reader.allocRemaining(a, .limited(limit)) catch |err| switch (err) {
        error.StreamTooLong => error.DownloadTooLarge,
        error.ReadFailed => response.bodyErr() orelse error.ReadFailed,
        else => |e| e,
    };
}

/// Verifies `archive`, extracts `dotlocal` beside `target_path`, checks its
/// reported version, then renames it over the target.
pub fn install(a: A, io: Io, archive: []const u8, sha256_hex: []const u8, version: []const u8, target_path: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(archive, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, sha256_hex)) return error.ChecksumMismatch;
    const dir_path = std.fs.path.dirname(target_path) orelse return error.InvalidTarget;
    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    process.validateInstallDirectory(dir.handle) catch |err| return switch (err) {
        error.UnsafeStateFile => error.UnsafeInstallDirectory,
        else => err,
    };
    var random: [8]u8 = undefined;
    io.random(&random);
    const staging = try std.fmt.allocPrint(a, ".dotlocal-update-{x}", .{std.mem.readInt(u64, &random, .little)});
    defer a.free(staging);
    try extractBinary(io, archive, dir, staging);
    errdefer dir.deleteFile(io, staging) catch {};
    const staged_path = try std.fs.path.join(a, &.{ dir_path, staging });
    defer a.free(staged_path);
    const reported = try probeVersion(a, io, staged_path);
    defer a.free(reported);
    if (!std.mem.eql(u8, reported, version)) return error.VersionMismatch;
    try dir.rename(staging, dir, std.fs.path.basename(target_path), io);
}

fn extractBinary(io: Io, archive: []const u8, dir: Io.Dir, name: []const u8) !void {
    var input: Io.Reader = .fixed(archive);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gzip: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&gzip.reader, .{ .file_name_buffer = &file_name_buffer, .link_name_buffer = &link_name_buffer });
    var found = false;
    errdefer if (found) dir.deleteFile(io, name) catch {};
    while (try it.next()) |entry| {
        if (entry.kind != .file or !(std.mem.eql(u8, entry.name, "dotlocal") or std.mem.eql(u8, entry.name, "./dotlocal"))) continue;
        if (found) return error.AmbiguousArchive;
        if (entry.size > max_archive) return error.DownloadTooLarge;
        var out = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o755) });
        defer out.close(io);
        found = true;
        var buffer: [64 * 1024]u8 = undefined;
        var writer = out.writer(io, &buffer);
        try it.streamRemaining(entry, &writer.interface);
        try writer.interface.flush();
        try out.sync(io);
    }
    if (!found) return error.BinaryMissingFromArchive;
}

const probe_timeout: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } };

/// Runs `<path> version` and returns its trimmed output.
pub fn probeVersion(a: A, io: Io, path: []const u8) ![]u8 {
    const result = try std.process.run(a, io, .{ .argv = &.{ path, "version" }, .stdout_limit = .limited(256), .stderr_limit = .limited(4096), .timeout = probe_timeout.toDeadline(io) });
    defer a.free(result.stderr);
    defer a.free(result.stdout);
    if (result.term != .exited or result.term.exited != 0) return error.VersionProbeFailed;
    return a.dupe(u8, std.mem.trim(u8, result.stdout, " \r\n"));
}

// --- check throttling and post-update notice -------------------------------

const State = struct { last_check: i64 = 0, consecutive_failures: u32 = 0, warned_failures: u32 = 0, notice_from: ?[]const u8 = null, notice_to: ?[]const u8 = null };
/// Repeated failed checks before the CLI prints a one-line warning.
pub const failure_warning_threshold: u32 = 3;
pub const Notice = struct { from: []const u8, to: []const u8 };

pub fn due(a: A, io: Io, path: []const u8, now: i64) !bool {
    var parsed = readState(a, io, path) catch return true;
    defer parsed.deinit();
    const last = parsed.value.last_check;
    // A future timestamp (clock moved back) must not stall checks.
    return last > now or now -| last >= interval_seconds;
}

/// Errors that mean a release failed verification, as opposed to the network
/// or the machine being unavailable. Only these count toward the warning.
pub fn isVerificationFailure(err: anyerror) bool {
    return switch (err) {
        error.BadSignature, error.ChecksumMismatch, error.VersionMismatch, error.UntrustedAssetUrl, error.InvalidManifest, error.UnknownField, error.UnsupportedSchema, error.ChannelMismatch, error.ManifestTooLarge, error.AmbiguousArchive, error.BinaryMissingFromArchive => true,
        else => false,
    };
}

/// Records a failed check: throttles the next attempt; verification failures
/// also count toward the repeated-failure warning.
pub fn recordFailure(a: A, io: Io, path: []const u8, now: i64, err: anyerror) !void {
    const counted: u32 = @intFromBool(isVerificationFailure(err));
    var state: State = .{ .last_check = now, .consecutive_failures = counted };
    var parsed = readState(a, io, path) catch null;
    defer if (parsed) |*p| p.deinit();
    if (parsed) |p| {
        state.consecutive_failures = p.value.consecutive_failures +| counted;
        state.warned_failures = p.value.warned_failures;
        state.notice_from = p.value.notice_from;
        state.notice_to = p.value.notice_to;
    }
    try writeState(a, io, path, state);
}

/// Executables under a package manager are updated by that package manager.
pub fn packageManaged(path: []const u8) bool {
    if (std.mem.indexOf(u8, path, "/Cellar/") != null) return true;
    for ([_][]const u8{ "/nix/store/", "/opt/homebrew/", "/usr/local/Homebrew/", "/home/linuxbrew/" }) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

/// True when `candidate` is a strictly newer semantic version than `current`;
/// unparsable versions are never newer.
pub fn newer(candidate: []const u8, current: []const u8) bool {
    const x = std.SemanticVersion.parse(candidate) catch return false;
    const y = std.SemanticVersion.parse(current) catch return false;
    return std.SemanticVersion.order(x, y) == .gt;
}

/// Whether service installation keeps the installed binary instead of this
/// CLI's: a newer service binary is never downgraded unless forced or the user
/// pinned exactly this CLI's version (an explicit rollback).
pub fn keepServiceBinary(service_version: []const u8, cli_version: []const u8, pin: ?[]const u8, force: bool) bool {
    if (force) return false;
    if (pin) |v| if (std.mem.eql(u8, v, cli_version)) return false;
    return newer(service_version, cli_version);
}

/// Consecutive failed checks since the last success.
pub fn failures(a: A, io: Io, path: []const u8) !u32 {
    var parsed = readState(a, io, path) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer parsed.deinit();
    return parsed.value.consecutive_failures;
}

pub fn recordCheck(a: A, io: Io, path: []const u8, now: i64, notice: ?Notice) !void {
    try writeState(a, io, path, .{ .last_check = now, .notice_from = if (notice) |n| n.from else null, .notice_to = if (notice) |n| n.to else null });
}

/// Returns and clears the one-line notice from the last background update.
pub fn takeNotice(a: A, io: Io, path: []const u8) !?[]u8 {
    var parsed = readState(a, io, path) catch return null;
    defer parsed.deinit();
    const from = parsed.value.notice_from orelse return null;
    const to = parsed.value.notice_to orelse return null;
    const text = try std.fmt.allocPrint(a, "dotlocal updated {s} → {s}", .{ from, to });
    errdefer a.free(text);
    try writeState(a, io, path, .{ .last_check = parsed.value.last_check, .consecutive_failures = parsed.value.consecutive_failures, .warned_failures = parsed.value.warned_failures });
    return text;
}

/// Returns the failure count once each time it grows past the threshold, so
/// a broken update path warns once per failed check rather than every run.
pub fn takeFailureWarning(a: A, io: Io, path: []const u8) !?u32 {
    var parsed = readState(a, io, path) catch return null;
    defer parsed.deinit();
    const state = parsed.value;
    if (state.consecutive_failures < failure_warning_threshold or state.consecutive_failures == state.warned_failures) return null;
    var next = state;
    next.warned_failures = state.consecutive_failures;
    try writeState(a, io, path, next);
    return state.consecutive_failures;
}

fn readState(a: A, io: Io, path: []const u8) !std.json.Parsed(State) {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, a, .limited(4096));
    defer a.free(bytes);
    return std.json.parseFromSlice(State, a, bytes, .{ .allocate = .alloc_always });
}

fn writeState(a: A, io: Io, path: []const u8, state: State) !void {
    const json = try std.json.Stringify.valueAlloc(a, state, .{ .emit_null_optional_fields = false });
    defer a.free(json);
    const dir_path = std.fs.path.dirname(path) orelse return error.InvalidStatePath;
    try Io.Dir.cwd().createDirPath(io, dir_path);
    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    var atomic = try dir.createFileAtomic(io, std.fs.path.basename(path), .{ .permissions = .fromMode(0o600), .replace = true });
    defer atomic.deinit(io);
    try atomic.file.setPermissions(io, .fromMode(0o600));
    try atomic.file.writeStreamingAll(io, json);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Serializes updaters; held for the duration of check + apply.
pub fn lock(io: Io, path: []const u8) !Io.File {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .permissions = .fromMode(0o600), .lock = .exclusive, .lock_nonblocking = true });
    return file;
}
