//! Trust anchors for self-update: one base64 Ed25519 public key per line of
//! release/public-key. To rotate, add the new key as a second line and ship a
//! release; then switch DOTLOCAL_SIGNING_KEY to the new seed; remove the old
//! line once no supported release needs it.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const build_options = @import("build_options");

pub const asset_url_prefix = "https://github.com/euforicio/dotlocal/releases/download/";
pub const manifest_base_url = "https://raw.githubusercontent.com/euforicio/dotlocal/channels/";

pub const keys: []const [Ed25519.PublicKey.encoded_length]u8 = decode(@embedFile("release-public-key"));

fn decode(comptime text: []const u8) []const [Ed25519.PublicKey.encoded_length]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var buffer: [8][Ed25519.PublicKey.encoded_length]u8 = undefined;
        const found = @import("manifest.zig").decodeKeys(text, &buffer) catch @compileError("release/public-key must hold 1-8 lines of base64 32-byte keys");
        const final = found[0..found.len].*;
        return &final;
    }
}

/// Test builds (-Dupdate-test) may trust an extra key and prefix from the
/// environment; release builds never read these variables.
pub const test_overrides = build_options.update_test;
