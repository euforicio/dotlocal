//! Release helper for CI.
//!   keygen                                   print SEED=<b64> and PUBLIC=<b64>
//!   manifest CHANNEL OUT [VERSION COMMIT PUBLISHED TARGET=URL@SHA256...]...
//!            releases separated by "--", newest first; writes OUT and OUT.sig
//!   verify FILE PUBLIC_KEY_FILE              any key line in PUBLIC_KEY_FILE
//!   check-key PUBLIC_KEY_FILE                DOTLOCAL_SIGNING_KEY pairs with a key
const std = @import("std");
const dotlocal = @import("dotlocal");
const manifest = dotlocal.manifest;
const Ed25519 = std.crypto.sign.Ed25519;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 2) return error.Usage;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout.interface;
    if (std.mem.eql(u8, args[1], "keygen")) {
        const kp = Ed25519.KeyPair.generate(io);
        var seed_text: [44]u8 = undefined;
        var public_text: [44]u8 = undefined;
        try out.print("SEED={s}\nPUBLIC={s}\n", .{
            std.base64.standard.Encoder.encode(&seed_text, &kp.secret_key.seed()),
            std.base64.standard.Encoder.encode(&public_text, &kp.public_key.toBytes()),
        });
        return out.flush();
    }
    if (std.mem.eql(u8, args[1], "manifest")) {
        if (args.len < 4) return error.Usage;
        const channel = std.meta.stringToEnum(manifest.Channel, args[2]) orelse return error.Usage;
        var releases: std.ArrayList(manifest.RenderRelease) = .empty;
        var i: usize = 4;
        while (i < args.len) {
            if (i + 3 > args.len) return error.Usage;
            var assets: std.ArrayList(manifest.RenderAsset) = .empty;
            const version = args[i];
            const commit = args[i + 1];
            const published = args[i + 2];
            i += 3;
            while (i < args.len and !std.mem.eql(u8, args[i], "--")) : (i += 1) {
                const eq = std.mem.indexOfScalar(u8, args[i], '=') orelse return error.Usage;
                const at = eq + 1 + (std.mem.lastIndexOfScalar(u8, args[i][eq + 1 ..], '@') orelse return error.Usage);
                try assets.append(a, .{ .target = args[i][0..eq], .url = args[i][eq + 1 .. at], .sha256 = args[i][at + 1 ..] });
            }
            if (i < args.len) i += 1; // skip "--"
            try releases.append(a, .{ .version = version, .commit = commit, .published = published, .assets = assets.items });
        }
        const json = try manifest.render(a, channel, releases.items);
        _ = try manifest.parse(a, json, channel, dotlocal.release_keys.asset_url_prefix);
        const seed_text = init.environ_map.get("DOTLOCAL_SIGNING_KEY") orelse return error.MissingSigningKey;
        const seed = try manifest.decodeKey(seed_text);
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        const sig = try manifest.sign(json, kp);
        const dir = std.Io.Dir.cwd();
        try dir.writeFile(io, .{ .sub_path = args[3], .data = json });
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}.sig", .{args[3]}), .data = &sig });
        return;
    }
    if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len != 4) return error.Usage;
        const dir = std.Io.Dir.cwd();
        const json = try dir.readFileAlloc(io, args[2], a, .limited(manifest.max_bytes));
        const sig = try dir.readFileAlloc(io, try std.fmt.allocPrint(a, "{s}.sig", .{args[2]}), a, .limited(256));
        const key_text = try dir.readFileAlloc(io, args[3], a, .limited(4096));
        var keys: [8][32]u8 = undefined;
        try manifest.verify(json, sig, try manifest.decodeKeys(key_text, &keys));
        try out.writeAll("ok\n");
        return out.flush();
    }
    if (std.mem.eql(u8, args[1], "check-key")) {
        if (args.len != 3) return error.Usage;
        const seed_text = init.environ_map.get("DOTLOCAL_SIGNING_KEY") orelse return error.MissingSigningKey;
        const key_text = try std.Io.Dir.cwd().readFileAlloc(io, args[2], a, .limited(4096));
        manifest.checkSigningKey(seed_text, key_text) catch |err| {
            std.log.err("DOTLOCAL_SIGNING_KEY does not pair with {s}: {s}", .{ args[2], @errorName(err) });
            return err;
        };
        try out.writeAll("ok\n");
        return out.flush();
    }
    return error.Usage;
}
