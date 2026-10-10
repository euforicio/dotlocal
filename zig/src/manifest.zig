//! Signed release channel manifests: strict parsing, signature checks and
//! release selection. Pure; no I/O.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const max_bytes = 64 * 1024;
pub const signature_text_len = std.base64.standard.Encoder.calcSize(Ed25519.Signature.encoded_length);
pub const Channel = enum { stable, nightly };

pub const Asset = struct { url: []const u8, sha256: []const u8 };
pub const Release = struct {
    version: []const u8,
    commit: []const u8,
    published: []const u8,
    assets: std.json.ArrayHashMap(Asset),

    pub fn asset(self: Release, target: []const u8) ?Asset {
        return self.assets.map.get(target);
    }
};
pub const Manifest = struct { schema: u32, channel: Channel, releases: []const Release };

pub fn parse(a: std.mem.Allocator, bytes: []const u8, channel: Channel, url_prefix: []const u8) !std.json.Parsed(Manifest) {
    if (bytes.len > max_bytes) return error.ManifestTooLarge;
    const parsed = std.json.parseFromSlice(Manifest, a, bytes, .{ .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error", .allocate = .alloc_always }) catch |err| return switch (err) {
        error.UnknownField => error.UnknownField,
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidManifest,
    };
    errdefer parsed.deinit();
    const m = parsed.value;
    if (m.schema != 1) return error.UnsupportedSchema;
    if (m.channel != channel) return error.ChannelMismatch;
    if (m.releases.len == 0 or m.releases.len > 8) return error.InvalidManifest;
    for (m.releases) |release| {
        _ = std.SemanticVersion.parse(release.version) catch return error.InvalidManifest;
        if (release.assets.map.count() == 0 or release.assets.map.count() > 16) return error.InvalidManifest;
        for (release.assets.map.values()) |item| {
            if (!std.mem.startsWith(u8, item.url, url_prefix)) return error.UntrustedAssetUrl;
            const rest = item.url[url_prefix.len..];
            if (std.mem.indexOf(u8, rest, "..") != null or std.mem.indexOfAny(u8, rest, "%?#\\ \t\r\n\x0b\x0c") != null) return error.UntrustedAssetUrl;
            if (item.sha256.len != 64) return error.InvalidManifest;
            for (item.sha256) |ch| if (!std.ascii.isHex(ch) or std.ascii.isUpper(ch)) return error.InvalidManifest;
        }
    }
    return parsed;
}

/// `signature` is base64 of the 64-byte Ed25519 signature over `bytes`.
pub fn verify(bytes: []const u8, signature: []const u8, keys: []const [Ed25519.PublicKey.encoded_length]u8) !void {
    const text = std.mem.trim(u8, signature, " \r\n");
    var raw: [Ed25519.Signature.encoded_length]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.BadSignature;
    if (size != raw.len) return error.BadSignature;
    std.base64.standard.Decoder.decode(&raw, text) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(raw);
    for (keys) |key| {
        const public_key = Ed25519.PublicKey.fromBytes(key) catch continue;
        if (sig.verifyStrict(bytes, public_key)) |_| return else |_| {}
    }
    return error.BadSignature;
}

/// Decodes base64 `text` (surrounding whitespace ignored) into exactly 32 bytes.
pub fn decodeKey(text: []const u8) error{InvalidKey}![32]u8 {
    const trimmed = std.mem.trim(u8, text, " \r\n");
    var out: [32]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidKey;
    if (size != out.len) return error.InvalidKey;
    std.base64.standard.Decoder.decode(&out, trimmed) catch return error.InvalidKey;
    return out;
}

/// Decodes one base64 key per non-empty line of `text` into `out`.
pub fn decodeKeys(text: []const u8, out: [][32]u8) error{InvalidKey}![]const [32]u8 {
    var count: usize = 0;
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) continue;
        if (count == out.len) return error.InvalidKey;
        out[count] = try decodeKey(trimmed);
        count += 1;
    }
    if (count == 0) return error.InvalidKey;
    return out[0..count];
}

/// Fails unless the signing key `seed_text` pairs with one of the public keys
/// in `public_text`, by signing and verifying a fixed message.
pub fn checkSigningKey(seed_text: []const u8, public_text: []const u8) !void {
    const kp = try Ed25519.KeyPair.generateDeterministic(try decodeKey(seed_text));
    var buffer: [8][32]u8 = undefined;
    const message = "dotlocal release key check";
    try verify(message, &(try sign(message, kp)), try decodeKeys(public_text, &buffer));
}

pub const Selection = union(enum) {
    /// Newest release, only when newer than the running version.
    automatic,
    /// Newest release regardless of order (explicit channel switch).
    channel_switch,
    /// A specific retained release (rollback); may be older.
    exact: []const u8,
};

pub fn select(releases: []const Release, current: []const u8, selection: Selection) !?Release {
    const running = try std.SemanticVersion.parse(current);
    var newest: ?Release = null;
    for (releases) |release| {
        const v = std.SemanticVersion.parse(release.version) catch unreachable; // checked by parse
        switch (selection) {
            .exact => |want| if (std.mem.eql(u8, release.version, want)) return release,
            else => if (newest == null or std.SemanticVersion.order(v, std.SemanticVersion.parse(newest.?.version) catch unreachable) == .gt) {
                newest = release;
            },
        }
    }
    return switch (selection) {
        .exact => error.VersionNotAvailable,
        .channel_switch => if (newest) |r| (if (std.mem.eql(u8, r.version, current)) null else r) else null,
        .automatic => if (newest) |r| (if (std.SemanticVersion.order(std.SemanticVersion.parse(r.version) catch unreachable, running) == .gt) r else null) else null,
    };
}

pub fn targetName(arch: std.Target.Cpu.Arch, os: std.Target.Os.Tag) ?[]const u8 {
    return switch (os) {
        .macos => switch (arch) {
            .aarch64 => "aarch64-macos",
            .x86_64 => "x86_64-macos",
            else => null,
        },
        .linux => switch (arch) {
            .aarch64 => "aarch64-linux",
            .x86_64 => "x86_64-linux",
            else => null,
        },
        else => null,
    };
}

pub fn currentTarget() ?[]const u8 {
    const builtin = @import("builtin");
    return targetName(builtin.cpu.arch, builtin.os.tag);
}

pub const RenderAsset = struct { target: []const u8, url: []const u8, sha256: []const u8 };
pub const RenderRelease = struct { version: []const u8, commit: []const u8, published: []const u8, assets: []const RenderAsset };

/// Deterministic JSON for signing: newest release first, as given.
pub fn render(a: std.mem.Allocator, channel: Channel, releases: []const RenderRelease) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    const w = &out.writer;
    try w.print("{{\"schema\":1,\"channel\":\"{t}\",\"releases\":[", .{channel});
    for (releases, 0..) |release, i| {
        if (i != 0) try w.writeByte(',');
        try w.writeAll("{\"version\":");
        try std.json.Stringify.value(release.version, .{}, w);
        try w.writeAll(",\"commit\":");
        try std.json.Stringify.value(release.commit, .{}, w);
        try w.writeAll(",\"published\":");
        try std.json.Stringify.value(release.published, .{}, w);
        try w.writeAll(",\"assets\":{");
        for (release.assets, 0..) |item, j| {
            if (j != 0) try w.writeByte(',');
            try std.json.Stringify.value(item.target, .{}, w);
            try w.writeAll(":{\"url\":");
            try std.json.Stringify.value(item.url, .{}, w);
            try w.writeAll(",\"sha256\":");
            try std.json.Stringify.value(item.sha256, .{}, w);
            try w.writeByte('}');
        }
        try w.writeAll("}}");
    }
    try w.writeAll("]}\n");
    return out.toOwnedSlice();
}

pub fn sign(bytes: []const u8, key_pair: Ed25519.KeyPair) ![signature_text_len]u8 {
    const sig = try key_pair.sign(bytes, null);
    var text: [signature_text_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&text, &sig.toBytes());
    return text;
}
