const std = @import("std");
const pki = @import("../src/pki.zig");
const net = @import("../src/net.zig");
const c = net.c;
const a = std.testing.allocator;
const io = std.testing.io;
fn directory(tmp: std.testing.TmpDir) ![]u8 {
    const base = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    return std.fs.path.join(a, &.{ base, "authority" });
}
fn digest(cert: *c.X509) ![32]u8 {
    var output: [32]u8 = undefined;
    var size: c_uint = 0;
    if (c.X509_digest(cert, c.EVP_sha256(), &output, &size) != 1 or size != 32) return error.CertificateDigestFailed;
    return output;
}
fn write(dir: std.Io.Dir, name: []const u8, data: []const u8, mode: u16) !void {
    const file = try dir.createFile(io, name, .{ .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.sync(io);
}
fn exists(dir: std.Io.Dir, name: []const u8) bool {
    dir.access(io, name, .{}) catch return false;
    return true;
}
fn countLeaves(authority: *pki.Authority) !usize {
    var iterator = authority.leaves_dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |_| count += 1;
    return count;
}

test "owned root and exact host leaf persist across restart with bounded cache" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.initWithOptions(a, io, path, .{ .max_leaf_certificates = 2 });
    const root = try authority.rootFingerprint();
    const first = try authority.serverContext("one.local");
    defer c.SSL_CTX_free(first);
    const leaf = try digest(c.SSL_CTX_get0_certificate(first).?);
    const second = try authority.serverContext("two.local");
    c.SSL_CTX_free(second);
    authority.deinit();
    authority = try pki.Authority.initWithOptions(a, io, path, .{ .max_leaf_certificates = 2 });
    defer authority.deinit();
    try std.testing.expectEqualSlices(u8, &root, &(try authority.rootFingerprint()));
    const reused = try authority.serverContext("one.local");
    defer c.SSL_CTX_free(reused);
    try std.testing.expectEqualSlices(u8, &leaf, &(try digest(c.SSL_CTX_get0_certificate(reused).?)));
    const third = try authority.serverContext("three.local");
    c.SSL_CTX_free(third);
    try std.testing.expectEqual(@as(usize, 2), try countLeaves(&authority));
    try std.testing.expect(authority.leaves.count() <= 2);
    try std.testing.expect(exists(authority.leaves_dir, "three.local.pem"));
    try std.testing.expectError(error.InvalidCertificateHost, authority.serverContext(""));
    try std.testing.expectError(error.InvalidCertificateHost, authority.serverContext("one.local:443"));
    if (authority.serverContext("*.local")) |ctx| {
        c.SSL_CTX_free(ctx);
        return error.ExpectedHostRejection;
    } else |_| {}
    if (authority.serverContext("one.example.com")) |ctx| {
        c.SSL_CTX_free(ctx);
        return error.ExpectedHostRejection;
    } else |_| {}
}

test "leaf renews using real time and never exceeds issuer lifetime" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.initWithOptions(a, io, path, .{ .root_validity_seconds = 20, .leaf_validity_seconds = 3, .renew_before_seconds = 2 });
    defer authority.deinit();
    const first = try authority.serverContext("renew.local");
    defer c.SSL_CTX_free(first);
    const before = try digest(c.SSL_CTX_get0_certificate(first).?);
    try std.Io.sleep(io, .fromSeconds(2), .awake);
    try std.testing.expect(authority.contextNeedsRenewal(first, "renew.local"));
    const second = try authority.serverContext("renew.local");
    defer c.SSL_CTX_free(second);
    try std.testing.expect(!std.mem.eql(u8, &before, &(try digest(c.SSL_CTX_get0_certificate(second).?))));
    try std.testing.expect(c.ASN1_TIME_compare(c.X509_get0_notAfter(c.SSL_CTX_get0_certificate(second)), c.X509_get0_notAfter(authority.certificate)) <= 0);
    authority.options.leaf_validity_seconds = 20;
    const bounded = try authority.serverContext("bounded.local");
    defer c.SSL_CTX_free(bounded);
    try std.testing.expectEqual(@as(c_int, 0), c.ASN1_TIME_compare(c.X509_get0_notAfter(c.SSL_CTX_get0_certificate(bounded)), c.X509_get0_notAfter(authority.certificate)));
    try std.testing.expect(authority.rootNeedsRotation(100));
    try std.testing.expect(authority.rootNeedsRotation(std.math.maxInt(i64)));
}

test "staged fingerprint activation preserves previous public root until finalize" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const original = try authority.rootFingerprint();
    const old_public = try authority.dir.readFileAlloc(io, "ca.pem", a, .limited(65536));
    defer a.free(old_public);
    const old_ctx = try authority.serverContext("rotate.local");
    defer c.SSL_CTX_free(old_ctx);
    const rotation = try authority.prepareRootRotation();
    defer rotation.deinit(a);
    const same = try authority.prepareRootRotation();
    defer same.deinit(a);
    try std.testing.expectEqualSlices(u8, &rotation.fingerprint, &same.fingerprint);
    try std.testing.expectError(error.RootFingerprintMismatch, authority.activateRoot(&original));
    try std.testing.expectEqualSlices(u8, &original, &(try authority.rootFingerprint()));
    const previous = try authority.activateRoot(&rotation.fingerprint);
    defer a.free(previous);
    try std.testing.expectEqualSlices(u8, &rotation.fingerprint, &(try authority.rootFingerprint()));
    try std.testing.expect(authority.contextNeedsRenewal(old_ctx, "rotate.local"));
    try std.testing.expectEqual(@as(usize, 0), try countLeaves(&authority));
    const saved = try authority.dir.readFileAlloc(io, "previous-ca.pem", a, .limited(65536));
    defer a.free(saved);
    try std.testing.expectEqualSlices(u8, old_public, saved);
    const retry = try authority.activateRoot(&rotation.fingerprint);
    defer a.free(retry);
    try std.testing.expectError(error.RotationNotFinalized, authority.prepareRootRotation());
    try authority.finalizeRootRotation();
    try authority.finalizeRootRotation();
    try std.testing.expect(!exists(authority.dir, "previous-ca.pem"));
}

test "restart repairs interrupted promotion and preserves new issuer leaves" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    const old_ctx = try authority.serverContext("old.local");
    c.SSL_CTX_free(old_ctx);
    const old_leaf = try authority.leaves_dir.readFileAlloc(io, "old.local.pem", a, .limited(65536));
    defer a.free(old_leaf);
    const rotation = try authority.prepareRootRotation();
    defer rotation.deinit(a);
    const public = try authority.dir.readFileAlloc(io, "ca.pem", a, .limited(65536));
    defer a.free(public);
    const pending = try authority.dir.readFileAlloc(io, "pending-root.pem", a, .limited(65536));
    defer a.free(pending);
    try write(authority.dir, "previous-ca.pem", public, 0o644);
    // The process died after archiving the previous root but before promotion.
    const previous_path = try authority.activateRoot(&rotation.fingerprint);
    a.free(previous_path);
    authority.deinit();
    authority = try pki.Authority.init(a, io, path);
    const current = try authority.serverContext("new.local");
    c.SSL_CTX_free(current);
    // Recreate the durable files present after root promotion but before cleanup.
    try write(authority.leaves_dir, "old.local.pem", old_leaf, 0o600);
    try write(authority.dir, "pending-root.pem", pending, 0o600);
    const current_public = try authority.dir.readFileAlloc(io, "ca.pem", a, .limited(65536));
    defer a.free(current_public);
    try write(authority.dir, "pending-ca.pem", current_public, 0o644);
    authority.deinit();
    authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    try std.testing.expectEqualSlices(u8, &rotation.fingerprint, &(try authority.rootFingerprint()));
    try std.testing.expect(exists(authority.leaves_dir, "new.local.pem"));
    try std.testing.expect(!exists(authority.leaves_dir, "old.local.pem"));
    try std.testing.expect(!exists(authority.dir, "pending-root.pem"));
    try std.testing.expect(!exists(authority.dir, "pending-ca.pem"));
    try std.testing.expect(exists(authority.dir, "previous-ca.pem"));
}

fn allow(_: ?*anyopaque, host: []const u8) bool {
    return std.mem.eql(u8, host, "allowed.local");
}
test "registration restriction and unsafe persisted files fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.initWithOptions(a, io, path, .{ .allowed_suffix = ".local", .allow_host = allow });
    try std.testing.expectError(error.UnregisteredHost, authority.serverContext("other.local"));
    const ctx = try authority.serverContext("allowed.local");
    c.SSL_CTX_free(ctx);
    try authority.leaves_dir.symLink(io, "allowed.local.pem", "symlink.local.pem", .{});
    authority.deinit();
    if (pki.Authority.initWithOptions(a, io, path, .{ .allowed_suffix = ".local" })) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.ExpectedUnsafeCache;
    } else |_| {}
    const dir = try std.Io.Dir.openDirAbsolute(io, path, .{});
    defer dir.close(io);
    const leaves = try dir.openDir(io, "leaf", .{});
    defer leaves.close(io);
    try leaves.deleteFile(io, "symlink.local.pem");
    try write(leaves, "allowed.local.pem", "corrupt certificate", 0o600);
    try std.testing.expectError(error.InvalidCertificate, pki.Authority.initWithOptions(a, io, path, .{ .allowed_suffix = ".local" }));
    try leaves.deleteFile(io, "allowed.local.pem");
    try write(dir, "root.pem", "corrupt root", 0o600);
    try std.testing.expectError(error.InvalidCertificate, pki.Authority.init(a, io, path));
}

fn serveTLS(listener: c_int, ctx: *c.SSL_CTX) !void {
    const fd = c.accept(listener, null, null);
    if (fd < 0) return error.AcceptFailed;
    defer net.close(fd);
    net.configure(fd, 3);
    const ssl = c.SSL_new(ctx) orelse return error.TLSFailed;
    defer c.SSL_free(ssl);
    if (c.SSL_set_fd(ssl, fd) != 1 or c.SSL_accept(ssl) != 1 or c.SSL_write(ssl, "verified", 8) != 8) return error.TLSFailed;
}
test "real loopback TLS handshake verifies persisted root and exact hostname" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const server_ctx = try authority.serverContext("tls.local");
    defer c.SSL_CTX_free(server_ctx);
    const listener = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(listener);
    net.configure(listener, 3);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(@as(c_int, 0), c.getsockname(listener, @ptrCast(&address), &length));
    var server = try io.concurrent(serveTLS, .{ listener, server_ctx });
    defer server.cancel(io) catch {};
    const fd = try net.tcp(a, "127.0.0.1", std.mem.bigToNative(u16, address.sin_port), false);
    defer net.close(fd);
    net.configure(fd, 3);
    const client_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TLSFailed;
    defer c.SSL_CTX_free(client_ctx);
    c.SSL_CTX_set_verify(client_ctx, c.SSL_VERIFY_PEER, null);
    try std.testing.expectEqual(@as(c_int, 1), c.X509_STORE_add_cert(c.SSL_CTX_get_cert_store(client_ctx), authority.certificate));
    const client = c.SSL_new(client_ctx) orelse return error.TLSFailed;
    defer c.SSL_free(client);
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_set1_host(client, "tls.local"));
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_set_fd(client, fd));
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_connect(client));
    try std.testing.expectEqual(@as(c_long, c.X509_V_OK), c.SSL_get_verify_result(client));
    var reply: [8]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 8), c.SSL_read(client, &reply, reply.len));
    try std.testing.expectEqualStrings("verified", &reply);
    try server.await(io);
}

test "existing public certificate and private key migrate without root replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    const original = try authority.rootFingerprint();
    const bundle = try authority.dir.readFileAlloc(io, "root.pem", a, .limited(65536));
    defer a.free(bundle);
    const split = std.mem.indexOf(u8, bundle, "-----BEGIN PRIVATE KEY-----") orelse return error.InvalidBundle;
    try write(authority.dir, "ca-key.pem", bundle[split..], 0o600);
    try authority.dir.deleteFile(io, "root.pem");
    authority.deinit();
    authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    try std.testing.expectEqualSlices(u8, &original, &(try authority.rootFingerprint()));
    try std.testing.expect(exists(authority.dir, "root.pem"));
    try std.testing.expect(!exists(authority.dir, "ca-key.pem"));
}

fn verifiedHandshake(listener: c_int, ctx: *c.SSL_CTX, root: *c.X509, host: [:0]const u8) !void {
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    if (c.getsockname(listener, @ptrCast(&address), &length) != 0) return error.SocketFailed;
    var server = try io.concurrent(serveTLS, .{ listener, ctx });
    defer server.cancel(io) catch {};
    const fd = try net.tcp(a, "127.0.0.1", std.mem.bigToNative(u16, address.sin_port), false);
    defer net.close(fd);
    net.configure(fd, 3);
    const client_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TLSFailed;
    defer c.SSL_CTX_free(client_ctx);
    c.SSL_CTX_set_verify(client_ctx, c.SSL_VERIFY_PEER, null);
    if (c.X509_STORE_add_cert(c.SSL_CTX_get_cert_store(client_ctx), root) != 1) return error.TLSFailed;
    const client = c.SSL_new(client_ctx) orelse return error.TLSFailed;
    defer c.SSL_free(client);
    if (c.SSL_set1_host(client, host) != 1 or c.SSL_set_tlsext_host_name(client, host) != 1 or c.SSL_set_fd(client, fd) != 1 or c.SSL_connect(client) != 1 or c.SSL_get_verify_result(client) != c.X509_V_OK) return error.TLSFailed;
    var reply: [8]u8 = undefined;
    if (c.SSL_read(client, &reply, reply.len) != 8) return error.TLSFailed;
    try std.testing.expectEqualStrings("verified", &reply);
    try server.await(io);
}
test "daemon SNI uses actual namespace registration predicate and renews cached contexts" {
    const daemon = @import("../src/daemon.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state = try directory(tmp);
    defer a.free(state);
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const socket = try std.fmt.allocPrint(a, "/tmp/dotlocal-pki-{s}.sock", .{std.fmt.bytesToHex(nonce, .lower)});
    defer a.free(socket);
    const socket_z = try a.dupeSentinel(u8, socket, 0);
    defer a.free(socket_z);
    defer _ = c.unlink(socket_z);
    const reservation = try net.tcp(a, "127.0.0.1", 0, true);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    const got = c.getsockname(reservation, @ptrCast(&address), &length);
    net.close(reservation);
    if (got != 0) return error.SocketFailed;
    const listen = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{std.mem.bigToNative(u16, address.sin_port)});
    defer a.free(listen);
    const runtime = try daemon.Runtime.init(a, io, .{ .state_dir = state, .socket_path = socket, .legacy_listeners = false, .profile_explicit = true, .profile = .{ .listen = listen, .tld = ".dev" } });
    defer runtime.deinit();
    try std.testing.expectError(error.UnregisteredHost, runtime.authority.?.serverContext("unknown.dev"));
    if (try runtime.registry.mutate(.{ .id = "real-test", .operation = "add", .match = "absent", .route = .{ .name = "tls.dev", .scheme = "http", .host = "127.0.0.1", .port = 3000 } })) |route| route.deinit(a);
    try verifiedHandshake(runtime.public, runtime.base_ctx.?, runtime.authority.?.certificate, "tls.dev");
    const before_ctx = runtime.certificates.get("tls.dev").?;
    const before = try digest(c.SSL_CTX_get0_certificate(before_ctx).?);
    // Keep an outstanding reference while the runtime replaces its cache entry.
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_CTX_up_ref(before_ctx));
    defer c.SSL_CTX_free(before_ctx);
    runtime.authority.?.options.renew_before_seconds = std.math.maxInt(i64);
    try verifiedHandshake(runtime.public, runtime.base_ctx.?, runtime.authority.?.certificate, "tls.dev");
    const after = try digest(c.SSL_CTX_get0_certificate(runtime.certificates.get("tls.dev").?).?);
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
    try std.testing.expectEqualSlices(u8, &before, &(try digest(c.SSL_CTX_get0_certificate(before_ctx).?)));
}

test "owned authority rejects wrong issuer leaf, unsafe private mode and symlink ancestor" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    const ctx = try authority.serverContext("issuer.local");
    c.SSL_CTX_free(ctx);
    const leaf = try authority.leaves_dir.readFileAlloc(io, "issuer.local.pem", a, .limited(65536));
    defer a.free(leaf);
    const root_file = try authority.dir.openFile(io, "root.pem", .{});
    try root_file.setPermissions(io, .fromMode(0o644));
    root_file.close(io);
    authority.deinit();
    try std.testing.expectError(error.UnsafeStateFile, pki.Authority.init(a, io, path));
    const other_path = try std.fmt.allocPrint(a, "{s}-other", .{path});
    defer a.free(other_path);
    var other = try pki.Authority.init(a, io, other_path);
    try write(other.leaves_dir, "issuer.local.pem", leaf, 0o600);
    other.deinit();
    try std.testing.expectError(error.InvalidLeafCertificate, pki.Authority.init(a, io, other_path));
    try tmp.dir.symLink(io, "authority-other", "redirect", .{});
    const base = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    const redirected = try std.fs.path.join(a, &.{ base, "redirect", "child" });
    defer a.free(redirected);
    if (pki.Authority.init(a, io, redirected)) |value| {
        var invalid = value;
        invalid.deinit();
        return error.ExpectedSymlinkRejection;
    } else |_| {}
}

test "cached leaf still detects replacement corruption and requested path symlink" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const first = try authority.serverContext("cached.local");
    c.SSL_CTX_free(first);
    const bytes = try authority.leaves_dir.readFileAlloc(io, "cached.local.pem", a, .limited(65536));
    defer a.free(bytes);
    const unchanged = try authority.serverContext("cached.local");
    c.SSL_CTX_free(unchanged);
    try write(authority.leaves_dir, "cached.local.pem", "corrupt", 0o600);
    try std.testing.expectError(error.InvalidCertificate, authority.serverContext("cached.local"));
    try write(authority.leaves_dir, "cached.local.pem", bytes, 0o600);
    const restored = try authority.serverContext("cached.local");
    c.SSL_CTX_free(restored);
    try authority.leaves_dir.deleteFile(io, "cached.local.pem");
    try authority.leaves_dir.symLink(io, "../root.pem", "cached.local.pem", .{});
    if (authority.serverContext("cached.local")) |ctx| {
        c.SSL_CTX_free(ctx);
        return error.ExpectedSymlinkRejection;
    } else |_| {}
}

fn permissions(dir: std.Io.Dir, name: []const u8, mode: u16) !void {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(mode));
}
test "custom descriptor PEM context preserves real certificate chain and validates files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const issued = try authority.serverContext("custom.local");
    c.SSL_CTX_free(issued);
    const bundle = try authority.leaves_dir.readFileAlloc(io, "custom.local.pem", a, .limited(65536));
    defer a.free(bundle);
    const split = std.mem.indexOf(u8, bundle, "-----BEGIN PRIVATE KEY-----") orelse return error.InvalidBundle;
    const root = try authority.dir.readFileAlloc(io, "ca.pem", a, .limited(65536));
    defer a.free(root);
    const chain = try std.mem.concat(a, u8, &.{ bundle[0..split], root });
    defer a.free(chain);
    try write(authority.dir, "custom-cert.pem", chain, 0o644);
    try write(authority.dir, "custom-key.pem", bundle[split..], 0o600);
    const certpath = try std.fs.path.join(a, &.{ path, "custom-cert.pem" });
    defer a.free(certpath);
    const keypath = try std.fs.path.join(a, &.{ path, "custom-key.pem" });
    defer a.free(keypath);
    const context = try pki.fileContext(a, certpath, keypath);
    defer c.SSL_CTX_free(context);
    var certificates: ?*c.stack_st_X509 = null;
    try std.testing.expectEqual(@as(c_long, 1), c.SSL_CTX_get_extra_chain_certs(context, @as(?*anyopaque, @ptrCast(&certificates))));
    try std.testing.expectEqual(@as(c_int, 1), c.OPENSSL_sk_num(@ptrCast(certificates)));
    const listener = try net.tcp(a, "127.0.0.1", 0, true);
    defer net.close(listener);
    net.configure(listener, 3);
    try verifiedHandshake(listener, context, authority.certificate, "custom.local");
    // Mutating the source files cannot affect objects already retained by SSL_CTX.
    try write(authority.dir, "custom-cert.pem", "corrupt certificate", 0o644);
    try std.testing.expectError(error.InvalidCertificate, pki.fileContext(a, certpath, keypath));
    try verifiedHandshake(listener, context, authority.certificate, "custom.local");
    const trailing = try std.mem.concat(a, u8, &.{ chain, "trailing data" });
    defer a.free(trailing);
    try write(authority.dir, "custom-cert.pem", trailing, 0o644);
    try std.testing.expectError(error.InvalidCertificate, pki.fileContext(a, certpath, keypath));
    try write(authority.dir, "custom-cert.pem", chain, 0o644);
    const bad_key = try std.mem.concat(a, u8, &.{ bundle[split..], "trailing data" });
    defer a.free(bad_key);
    try write(authority.dir, "custom-key.pem", bad_key, 0o600);
    try std.testing.expectError(error.InvalidKey, pki.fileContext(a, certpath, keypath));
    try write(authority.dir, "custom-key.pem", "corrupt key", 0o600);
    try std.testing.expectError(error.InvalidKey, pki.fileContext(a, certpath, keypath));
    const other = try authority.serverContext("other.local");
    c.SSL_CTX_free(other);
    const other_bundle = try authority.leaves_dir.readFileAlloc(io, "other.local.pem", a, .limited(65536));
    defer a.free(other_bundle);
    const other_split = std.mem.indexOf(u8, other_bundle, "-----BEGIN PRIVATE KEY-----") orelse return error.InvalidBundle;
    try write(authority.dir, "custom-key.pem", other_bundle[other_split..], 0o600);
    try std.testing.expectError(error.InvalidKey, pki.fileContext(a, certpath, keypath));
    try write(authority.dir, "custom-key.pem", bundle[split..], 0o600);
    try permissions(authority.dir, "custom-key.pem", 0o644);
    try std.testing.expectError(error.UnsafeCertificatePath, pki.fileContext(a, certpath, keypath));
    try permissions(authority.dir, "custom-key.pem", 0o600);
    try permissions(authority.dir, "custom-cert.pem", 0o666);
    try std.testing.expectError(error.UnsafeCertificatePath, pki.fileContext(a, certpath, keypath));
    try permissions(authority.dir, "custom-cert.pem", 0o644);
    try authority.dir.symLink(io, "custom-cert.pem", "cert-link.pem", .{});
    const linkpath = try std.fs.path.join(a, &.{ path, "cert-link.pem" });
    defer a.free(linkpath);
    try std.testing.expectError(error.UnsafeCertificatePath, pki.fileContext(a, linkpath, keypath));
    try authority.dir.symLink(io, "custom-key.pem", "key-link.pem", .{});
    const keylink = try std.fs.path.join(a, &.{ path, "key-link.pem" });
    defer a.free(keylink);
    try std.testing.expectError(error.UnsafeCertificatePath, pki.fileContext(a, certpath, keylink));
    try tmp.dir.symLink(io, "authority", "alias", .{});
    const base = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    const alias = try std.fs.path.join(a, &.{ base, "alias", "custom-cert.pem" });
    defer a.free(alias);
    try std.testing.expectError(error.UnsafeCertificatePath, pki.fileContext(a, alias, keypath));
}

test "public authority PEM permissions remain exact under launchd umask" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    const old_mask = c.umask(0o077);
    defer _ = c.umask(old_mask);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const public = try authority.dir.openFile(io, "ca.pem", .{});
    defer public.close(io);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o644), (try public.stat(io)).permissions.toMode() & 0o7777);
    const rotation = try authority.prepareRootRotation();
    defer rotation.deinit(a);
    const previous = try authority.activateRoot(&rotation.fingerprint);
    a.free(previous);
    try authority.finalizeRootRotation();
}

test "real CLI child persists public CA under restrictive umask and reopens it" {
    const client_module = @import("../src/client.zig");
    const executable = std.Io.Dir.cwd().realPathFileAlloc(io, "zig-out/bin/dotlocal", a) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer a.free(executable);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state = try directory(tmp);
    defer a.free(state);
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const socket = try std.fmt.allocPrint(a, "/tmp/dotlocal-pki-mask-{s}.sock", .{std.fmt.bytesToHex(nonce, .lower)});
    defer a.free(socket);
    const socket_z = try a.dupeSentinel(u8, socket, 0);
    defer a.free(socket_z);
    defer _ = c.unlink(socket_z);
    const reservation = try net.tcp(a, "127.0.0.1", 0, true);
    var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var length: c.socklen_t = @sizeOf(@TypeOf(address));
    const got = c.getsockname(reservation, @ptrCast(&address), &length);
    net.close(reservation);
    if (got != 0) return error.SocketFailed;
    const listen = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{std.mem.bigToNative(u16, address.sin_port)});
    defer a.free(listen);
    const log = try tmp.dir.createFile(io, "child.log", .{ .read = true });
    defer log.close(io);
    for (0..2) |_| {
        // The fixed shell wrapper only sets the child's umask and execs argv.
        var child = try std.process.spawn(io, .{ .argv = &.{ "/bin/sh", "-c", "umask 077; exec \"$@\"", "dotlocal", executable, "daemon", "--state-dir", state, "--management-socket", socket, "--listen", listen }, .stdin = .ignore, .stdout = .ignore, .stderr = .{ .file = log } });
        defer child.kill(io);
        const client: client_module.Client = .{ .allocator = a, .io = io, .socket_path = socket };
        var ready = false;
        for (0..100) |_| {
            if (client.call(.{ .id = "umask-real-child", .operation = "status" })) |response| {
                defer response.deinit();
                ready = response.value.ok;
                if (ready) break;
            } else |_| {}
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
        try std.testing.expect(ready);
        const ca_path = try std.fs.path.join(a, &.{ state, "pki", "ca.pem" });
        defer a.free(ca_path);
        const ca = try std.Io.Dir.openFileAbsolute(io, ca_path, .{ .follow_symlinks = false });
        defer ca.close(io);
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o644), (try ca.stat(io)).permissions.toMode() & 0o7777);
        // The unreaped child PID remains anchored until wait returns.
        try std.testing.expectEqual(@as(c_int, 0), c.kill(child.id.?, c.SIGTERM));
        try std.testing.expect((try child.wait(io)).success());
    }
}

test "issuance evicts retained leaves by age while startup still validates every leaf" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.initWithOptions(a, io, path, .{ .max_leaf_certificates = 2 });
    errdefer authority.deinit();
    const first = try authority.serverContext("first.local");
    c.SSL_CTX_free(first);
    try write(authority.leaves_dir, "corrupt.local.pem", "corrupt certificate", 0o600);
    // Coarse filesystem clocks can give both files the same mtime; make the age explicit.
    const old: [2]c.struct_timespec = .{ .{ .tv_sec = 0, .tv_nsec = c.UTIME_OMIT }, .{ .tv_sec = 1, .tv_nsec = 0 } };
    if (c.utimensat(authority.leaves_dir.handle, "first.local.pem", &old, 0) != 0) return error.TimestampFailed;
    // Issuance does not depend on unrelated retained material; the oldest file is evicted.
    const second = try authority.serverContext("second.local");
    defer c.SSL_CTX_free(second);
    try std.testing.expectEqual(@as(usize, 2), try countLeaves(&authority));
    try std.testing.expect(exists(authority.leaves_dir, "second.local.pem"));
    try std.testing.expect(!exists(authority.leaves_dir, "first.local.pem"));
    // The per-handshake check still binds a cached context to its exact name.
    try std.testing.expect(!authority.contextNeedsRenewal(second, "second.local"));
    try std.testing.expect(authority.contextNeedsRenewal(second, "first.local"));
    authority.deinit();
    try std.testing.expectError(error.InvalidCertificate, pki.Authority.initWithOptions(a, io, path, .{ .max_leaf_certificates = 2 }));
}

test "planted FIFOs fail closed without blocking open" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    // A FIFO has no writer, so a blocking open() would hang here forever.
    if (c.mkfifoat(authority.leaves_dir.handle, "fifo.local.pem", 0o600) != 0) return error.FifoCreateFailed;
    try std.testing.expectError(error.UnsafeStateFile, authority.serverContext("fifo.local"));
    try authority.leaves_dir.deleteFile(io, "fifo.local.pem");
    const cached = try authority.serverContext("cached.local");
    c.SSL_CTX_free(cached);
    try authority.leaves_dir.deleteFile(io, "cached.local.pem");
    if (c.mkfifoat(authority.leaves_dir.handle, "cached.local.pem", 0o600) != 0) return error.FifoCreateFailed;
    try std.testing.expectError(error.UnsafeStateFile, authority.serverContext("cached.local"));
    try authority.leaves_dir.deleteFile(io, "cached.local.pem");
    try authority.dir.deleteFile(io, "root.pem");
    if (c.mkfifoat(authority.dir.handle, "root.pem", 0o600) != 0) return error.FifoCreateFailed;
    try std.testing.expectError(error.UnsafeStateFile, pki.Authority.init(a, io, path));
}

test "foreign, misnamed and corrupt retained leaves are never served after unvalidated issuance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try directory(tmp);
    defer a.free(path);
    var authority = try pki.Authority.init(a, io, path);
    defer authority.deinit();
    const other_path = try std.fmt.allocPrint(a, "{s}-other", .{path});
    defer a.free(other_path);
    var other = try pki.Authority.init(a, io, other_path);
    defer other.deinit();
    const foreign_ctx = try other.serverContext("foreign.local");
    c.SSL_CTX_free(foreign_ctx);
    const foreign = try other.leaves_dir.readFileAlloc(io, "foreign.local.pem", a, .limited(65536));
    defer a.free(foreign);
    const own_ctx = try authority.serverContext("own.local");
    c.SSL_CTX_free(own_ctx);
    const own = try authority.leaves_dir.readFileAlloc(io, "own.local.pem", a, .limited(65536));
    defer a.free(own);
    try write(authority.leaves_dir, "foreign.local.pem", foreign, 0o600);
    try write(authority.leaves_dir, "alias.local.pem", own, 0o600);
    try write(authority.leaves_dir, "corrupt.local.pem", "corrupt certificate", 0o600);
    // Issuance scans the planted files for eviction without validating them.
    const fresh = try authority.serverContext("fresh.local");
    c.SSL_CTX_free(fresh);
    try std.testing.expectError(error.InvalidLeafCertificate, authority.serverContext("foreign.local"));
    try std.testing.expectError(error.InvalidLeafCertificate, authority.serverContext("alias.local"));
    try std.testing.expectError(error.InvalidCertificate, authority.serverContext("corrupt.local"));
}
