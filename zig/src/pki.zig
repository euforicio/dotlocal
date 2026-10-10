//! Durable exact-host local authorities. Trust changes remain an explicit caller operation.
const std = @import("std");
const net = @import("net.zig");
const osprocess = @import("process.zig");
const c = net.c;
const A = std.mem.Allocator;
const Io = std.Io;
const max_bundle = 64 * 1024;

pub const Options = struct {
    allowed_suffix: []const u8 = @import("routes.zig").default_tld,
    allowed_suffixes: []const []const u8 = &.{},
    root_common_name: []const u8 = "dotlocal Local Root CA",
    root_validity_seconds: i64 = 10 * 365 * 86400,
    leaf_validity_seconds: i64 = 30 * 86400,
    renew_before_seconds: i64 = 7 * 86400,
    max_leaf_certificates: usize = 1024,
    allow_host: ?*const fn (?*anyopaque, []const u8) bool = null,
    allow_context: ?*anyopaque = null,
};
pub const Rotation = struct {
    fingerprint: [64]u8,
    certificate_path: []u8,
    not_after: i64,
    pub fn deinit(self: Rotation, a: A) void {
        a.free(self.certificate_path);
    }
};
const Material = struct {
    certificate: *c.X509,
    key: *c.EVP_PKEY,
    fn deinit(self: Material) void {
        c.X509_free(self.certificate);
        c.EVP_PKEY_free(self.key);
    }
};
const CachedMaterial = struct { material: Material, stat: Io.File.Stat };
const CacheEntry = struct { host: []u8, mtime: i96 };

pub const Authority = struct {
    allocator: A,
    io: Io,
    directory: []const u8,
    certificate: *c.X509,
    key: *c.EVP_PKEY,
    options: Options,
    dir: Io.Dir,
    leaves_dir: Io.Dir,
    leaves: std.StringHashMapUnmanaged(CachedMaterial) = .empty,
    mutex: Io.Mutex = .init,

    pub fn init(a: A, io: Io, directory: []const u8) !Authority {
        return initWithOptions(a, io, directory, .{});
    }
    pub fn initWithOptions(a: A, io: Io, directory: []const u8, options: Options) !Authority {
        if (!std.fs.path.isAbsolute(directory)) return error.InvalidStatePath;
        if (options.root_validity_seconds <= 0 or options.root_validity_seconds > 100 * 365 * 86400 or options.leaf_validity_seconds <= 0 or options.leaf_validity_seconds > options.root_validity_seconds or options.renew_before_seconds < 0 or options.max_leaf_certificates == 0 or options.max_leaf_certificates > 65536 or options.root_common_name.len == 0 or options.root_common_name.len > 64 or std.mem.findScalar(u8, options.root_common_name, 0) != null) return error.InvalidAuthorityOptions;
        const suffix = try @import("routes.zig").normalizeTld(a, options.allowed_suffix);
        errdefer a.free(suffix);
        const suffixes = try @import("routes.zig").cloneTlds(a, suffix, options.allowed_suffixes);
        errdefer {
            for (suffixes) |value| a.free(value);
            a.free(suffixes);
        }
        const common_name = try a.dupe(u8, options.root_common_name);
        errdefer a.free(common_name);
        const owned_directory = try a.dupe(u8, directory);
        errdefer a.free(owned_directory);
        const dir = try openPrivateDirectory(io, directory);
        errdefer dir.close(io);
        try osprocess.validateOwned(dir.handle, 0o700, true);
        dir.createDir(io, "leaf", .fromMode(0o700)) catch |err| if (err != error.PathAlreadyExists) return err;
        const leaf_dir = try dir.openDir(io, "leaf", .{ .follow_symlinks = false, .iterate = true });
        errdefer leaf_dir.close(io);
        try osprocess.validateOwned(leaf_dir.handle, 0o700, true);
        var effective = options;
        effective.allowed_suffix = suffix;
        effective.allowed_suffixes = suffixes;
        effective.root_common_name = common_name;
        const material = if (try readOwned(a, io, dir, "root.pem", 0o600)) |bundle| blk: {
            defer a.free(bundle);
            break :blk try parseBundle(bundle, true);
        } else try loadOrCreateRoot(a, io, dir, effective);
        errdefer material.deinit();
        if (!validNow(material.certificate, now(io))) return error.InvalidAuthority;
        const public = try certificatePEM(a, material.certificate);
        defer a.free(public);
        try atomicOwnedWrite(a, io, dir, "ca.pem", public, 0o644);
        var self: Authority = .{ .allocator = a, .io = io, .directory = owned_directory, .certificate = material.certificate, .key = material.key, .options = effective, .dir = dir, .leaves_dir = leaf_dir };
        // Each persisted entry is validated before serving any TLS client.
        try self.recoverRotation();
        try self.enforceLeafBound("", true);
        return self;
    }
    pub fn deinit(self: *Authority) void {
        self.clearMemory();
        self.leaves.deinit(self.allocator);
        c.X509_free(self.certificate);
        c.EVP_PKEY_free(self.key);
        self.leaves_dir.close(self.io);
        self.dir.close(self.io);
        self.allocator.free(self.directory);
        self.allocator.free(self.options.allowed_suffix);
        for (self.options.allowed_suffixes) |suffix| self.allocator.free(suffix);
        self.allocator.free(self.options.allowed_suffixes);
        self.allocator.free(self.options.root_common_name);
    }
    fn clearMemory(self: *Authority) void {
        var it = self.leaves.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.material.deinit();
        }
        self.leaves.clearRetainingCapacity();
    }
    pub fn rootCertificatePath(self: *const Authority) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.directory, "ca.pem" });
    }
    pub fn rootFingerprint(self: *Authority) ![64]u8 {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        return fingerprint(self.certificate);
    }
    pub fn rootNeedsRotation(self: *Authority, window_seconds: i64) bool {
        if (window_seconds < 0) return false;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return expiry(self.certificate) <= now(self.io) +| window_seconds;
    }
    pub fn serverContext(self: *Authority, input: []const u8) !*c.SSL_CTX {
        const host = try normalizeHost(self.allocator, input, self.options);
        defer self.allocator.free(host);
        if (self.options.allow_host) |allow| if (!allow(self.options.allow_context, host)) return error.UnregisteredHost;
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (!validNow(self.certificate, now(self.io))) return error.InvalidAuthority;
        const material = try self.leaf(host);
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TLSFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_use_certificate(ctx, material.certificate) != 1 or c.SSL_CTX_use_PrivateKey(ctx, material.key) != 1 or c.SSL_CTX_check_private_key(ctx) != 1 or c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return error.TLSFailed;
        return ctx;
    }
    /// Cached TLS contexts are independent references. Callers should replace
    /// their context when this reports renewal or a changed active issuer.
    /// serverContext already verified the signature and key pair, so this per-handshake
    /// check only compares issuer identity, exact name and validity without signature work.
    pub fn contextNeedsRenewal(self: *Authority, ctx: *c.SSL_CTX, host: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const cert = c.SSL_CTX_get0_certificate(ctx) orelse return true;
        if (c.X509_check_issued(self.certificate, cert) != c.X509_V_OK or !exactDNSName(cert, host)) return true;
        return !usableLeaf(cert, now(self.io), self.options.renew_before_seconds);
    }
    fn leaf(self: *Authority, host: []const u8) !Material {
        const path = try leafPath(self.allocator, host);
        defer self.allocator.free(path);
        if (self.leaves.get(host)) |cached| {
            if (try openOwned(self.leaves_dir, path, 0o600)) |owned| {
                defer owned.close(self.io);
                const stat = try owned.stat(self.io);
                if (stat.inode == cached.stat.inode and stat.size == cached.stat.size and stat.mtime.nanoseconds == cached.stat.mtime.nanoseconds and stat.ctime.nanoseconds == cached.stat.ctime.nanoseconds and usableLeaf(cached.material.certificate, now(self.io), self.options.renew_before_seconds)) return cached.material;
            }
        }
        var material: ?Material = null;
        if (try readOwned(self.allocator, self.io, self.leaves_dir, path, 0o600)) |bundle| {
            defer self.allocator.free(bundle);
            const loaded = try parseBundle(bundle, false);
            validateLeaf(loaded, host, self.certificate) catch |err| {
                loaded.deinit();
                return err;
            };
            if (usableLeaf(loaded.certificate, now(self.io), self.options.renew_before_seconds)) material = loaded else loaded.deinit();
        }
        const issued = material == null;
        const value = material orelse blk: {
            const key = try generateKey();
            errdefer c.EVP_PKEY_free(key);
            const cert = try makeCertificate(self.allocator, self.io, key, self.certificate, self.key, host, false, self.options);
            errdefer c.X509_free(cert);
            const bundle = try bundlePEM(self.allocator, .{ .certificate = cert, .key = key });
            defer self.allocator.free(bundle);
            try atomicOwnedWrite(self.allocator, self.io, self.leaves_dir, path, bundle, 0o600);
            break :blk Material{ .certificate = cert, .key = key };
        };
        errdefer value.deinit();
        const copy = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(copy);
        if (issued) self.enforceLeafBound(host, false) catch |err| {
            self.leaves_dir.deleteFile(self.io, path) catch {};
            return err;
        } else try self.enforceLeafBound(host, false);
        const stored = (try openOwned(self.leaves_dir, path, 0o600)) orelse return error.AuthorityChanged;
        defer stored.close(self.io);
        const stat = try stored.stat(self.io);
        // Bind the cached crypto material to the metadata of the descriptor
        // actually read, even if another owner replaces a file during issuance.
        const stored_bundle = try readFile(self.allocator, self.io, stored);
        defer self.allocator.free(stored_bundle);
        const checked = try parseBundle(stored_bundle, false);
        defer checked.deinit();
        const after = try stored.stat(self.io);
        if (stat.inode != after.inode or stat.size != after.size or stat.mtime.nanoseconds != after.mtime.nanoseconds or stat.ctime.nanoseconds != after.ctime.nanoseconds or c.X509_cmp(value.certificate, checked.certificate) != 0 or c.EVP_PKEY_eq(value.key, checked.key) != 1) return error.AuthorityChanged;
        const entry = try self.leaves.getOrPut(self.allocator, copy);
        if (entry.found_existing) {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.material.deinit();
        }
        entry.key_ptr.* = copy;
        entry.value_ptr.* = .{ .material = value, .stat = stat };
        return value;
    }
    /// Startup validates every retained leaf. Issuance only needs safe names, ownership
    /// and age for eviction; any leaf actually served is fully validated when loaded.
    fn enforceLeafBound(self: *Authority, keep: []const u8, validate: bool) !void {
        var entries: std.ArrayList(CacheEntry) = .empty;
        defer {
            for (entries.items) |entry| self.allocator.free(entry.host);
            entries.deinit(self.allocator);
        }
        var iterator = self.leaves_dir.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (entries.items.len >= 65537) return error.LeafCacheTooLarge;
            if (entry.kind != .file) return error.UnsafeLeafCache;
            const name = try leafName(entry.name);
            const host = try normalizeCacheHost(self.allocator, name);
            errdefer self.allocator.free(host);
            if (!std.mem.eql(u8, name, host)) return error.UnsafeLeafCache;
            const file = (try openOwned(self.leaves_dir, entry.name, 0o600)) orelse return error.UnsafeLeafCache;
            defer file.close(self.io);
            const stat = try file.stat(self.io);
            if (validate) {
                const bundle = try readFile(self.allocator, self.io, file);
                defer self.allocator.free(bundle);
                const material = try parseBundle(bundle, false);
                defer material.deinit();
                try validateLeaf(material, host, self.certificate);
            }
            try entries.append(self.allocator, .{ .host = host, .mtime = stat.mtime.toNanoseconds() });
        }
        var stale: std.ArrayList([]const u8) = .empty;
        defer stale.deinit(self.allocator);
        var cached = self.leaves.keyIterator();
        while (cached.next()) |host| {
            var exists = false;
            for (entries.items) |entry| if (std.mem.eql(u8, entry.host, host.*)) {
                exists = true;
                break;
            };
            if (!exists) try stale.append(self.allocator, host.*);
        }
        for (stale.items) |host| if (self.leaves.fetchRemove(host)) |removed| {
            self.allocator.free(removed.key);
            removed.value.material.deinit();
        };
        if (entries.items.len <= self.options.max_leaf_certificates) return;
        std.mem.sort(CacheEntry, entries.items, keep, struct {
            fn less(keep_host: []const u8, left: CacheEntry, right: CacheEntry) bool {
                if (std.mem.eql(u8, left.host, keep_host)) return false;
                if (std.mem.eql(u8, right.host, keep_host)) return true;
                if (left.mtime != right.mtime) return left.mtime < right.mtime;
                return std.mem.lessThan(u8, left.host, right.host);
            }
        }.less);
        for (entries.items[0 .. entries.items.len - self.options.max_leaf_certificates]) |entry| {
            const path = try leafPath(self.allocator, entry.host);
            defer self.allocator.free(path);
            try self.leaves_dir.deleteFile(self.io, path);
            if (self.leaves.fetchRemove(entry.host)) |removed| {
                self.allocator.free(removed.key);
                removed.value.material.deinit();
            }
        }
        try syncDir(self.io, self.leaves_dir);
    }
    pub fn prepareRootRotation(self: *Authority) !Rotation {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) |previous| {
            self.allocator.free(previous);
            return error.RotationNotFinalized;
        }
        const material = if (try readOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600)) |bundle| blk: {
            defer self.allocator.free(bundle);
            break :blk try parseBundle(bundle, true);
        } else blk: {
            const generated = try newRoot(self.allocator, self.io, self.options);
            errdefer generated.deinit();
            const bundle = try bundlePEM(self.allocator, generated);
            defer self.allocator.free(bundle);
            try atomicOwnedWrite(self.allocator, self.io, self.dir, "pending-root.pem", bundle, 0o600);
            break :blk generated;
        };
        defer material.deinit();
        if (!validNow(material.certificate, now(self.io))) return error.InvalidAuthority;
        const public = try certificatePEM(self.allocator, material.certificate);
        defer self.allocator.free(public);
        try atomicOwnedWrite(self.allocator, self.io, self.dir, "pending-ca.pem", public, 0o644);
        return .{ .fingerprint = try fingerprint(material.certificate), .certificate_path = try std.fs.path.join(self.allocator, &.{ self.directory, "pending-ca.pem" }), .not_after = expiry(material.certificate) };
    }
    pub fn activateRoot(self: *Authority, expected: []const u8) ![]u8 {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        const bundle = (try readOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600)) orelse {
            const active = try fingerprint(self.certificate);
            if (expected.len != 64 or !std.ascii.eqlIgnoreCase(expected, &active)) return error.NoPreparedRoot;
            const previous = (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) orelse return error.NoPreparedRoot;
            defer self.allocator.free(previous);
            const certificate = try parsePublicRoot(previous);
            defer c.X509_free(certificate);
            try self.recoverRotation();
            return std.fs.path.join(self.allocator, &.{ self.directory, "previous-ca.pem" });
        };
        defer self.allocator.free(bundle);
        const material = try parseBundle(bundle, true);
        var transferred = false;
        defer if (!transferred) material.deinit();
        const digest = try fingerprint(material.certificate);
        if (expected.len != 64 or !std.ascii.eqlIgnoreCase(expected, &digest)) return error.RootFingerprintMismatch;
        if (!validNow(material.certificate, now(self.io))) return error.InvalidAuthority;
        const public = try certificatePEM(self.allocator, material.certificate);
        defer self.allocator.free(public);
        const staged_public = (try readOwned(self.allocator, self.io, self.dir, "pending-ca.pem", 0o644)) orelse return error.IncompleteRotation;
        defer self.allocator.free(staged_public);
        if (!std.mem.eql(u8, public, staged_public)) return error.RootFingerprintMismatch;
        const current_id = try fingerprint(self.certificate);
        const previous_path = try std.fs.path.join(self.allocator, &.{ self.directory, "previous-ca.pem" });
        errdefer self.allocator.free(previous_path);
        if (!std.mem.eql(u8, &current_id, &digest)) {
            const old = try certificatePEM(self.allocator, self.certificate);
            defer self.allocator.free(old);
            if (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) |previous| {
                defer self.allocator.free(previous);
                if (!std.mem.eql(u8, previous, old)) return error.RotationNotFinalized;
            }
            try atomicOwnedWrite(self.allocator, self.io, self.dir, "previous-ca.pem", old, 0o644);
            try atomicOwnedWrite(self.allocator, self.io, self.dir, "root.pem", bundle, 0o600);
        } else {
            const prior = (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) orelse return error.IncompleteRotation;
            defer self.allocator.free(prior);
            const previous = try parsePublicRoot(prior);
            defer c.X509_free(previous);
            const prior_id = try fingerprint(previous);
            if (std.mem.eql(u8, &prior_id, &digest)) return error.IncompleteRotation;
        }
        c.X509_free(self.certificate);
        c.EVP_PKEY_free(self.key);
        self.certificate = material.certificate;
        self.key = material.key;
        transferred = true;
        self.clearMemory();
        try atomicOwnedWrite(self.allocator, self.io, self.dir, "ca.pem", public, 0o644);
        try self.clearDiskLeaves();
        try deleteOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600);
        try deleteOwned(self.allocator, self.io, self.dir, "pending-ca.pem", 0o644);
        return previous_path;
    }
    pub fn finalizeRootRotation(self: *Authority) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        if (try readOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600)) |pending| {
            self.allocator.free(pending);
            return error.IncompleteRotation;
        }
        if (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) |data| {
            defer self.allocator.free(data);
            const previous = try parsePublicRoot(data);
            defer c.X509_free(previous);
            const prior_id = try fingerprint(previous);
            const active_id = try fingerprint(self.certificate);
            if (std.mem.eql(u8, &prior_id, &active_id)) return error.IncompleteRotation;
        }
        try deleteOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644);
    }
    fn recoverRotation(self: *Authority) !void {
        const data = (try readOwned(self.allocator, self.io, self.dir, "previous-ca.pem", 0o644)) orelse return;
        defer self.allocator.free(data);
        const previous = try parsePublicRoot(data);
        defer c.X509_free(previous);
        const old_id = try fingerprint(previous);
        const active_id = try fingerprint(self.certificate);
        if (std.mem.eql(u8, &old_id, &active_id)) return; // Archived, promotion has not occurred.
        var iterator = self.leaves_dir.iterate();
        var remove: std.ArrayList([]u8) = .empty;
        defer {
            for (remove.items) |name| self.allocator.free(name);
            remove.deinit(self.allocator);
        }
        while (try iterator.next(self.io)) |entry| {
            if (remove.items.len >= 65537 or entry.kind != .file) return error.UnsafeLeafCache;
            const host = try normalizeCacheHost(self.allocator, try leafName(entry.name));
            defer self.allocator.free(host);
            if (!std.mem.eql(u8, host, try leafName(entry.name))) return error.UnsafeLeafCache;
            const bundle = (try readOwned(self.allocator, self.io, self.leaves_dir, entry.name, 0o600)) orelse return error.UnsafeLeafCache;
            defer self.allocator.free(bundle);
            const material = try parseBundle(bundle, false);
            defer material.deinit();
            validateLeaf(material, host, self.certificate) catch {
                try validateLeaf(material, host, previous);
                const name = try self.allocator.dupe(u8, entry.name);
                errdefer self.allocator.free(name);
                try remove.append(self.allocator, name);
            };
        }
        for (remove.items) |name| try self.leaves_dir.deleteFile(self.io, name);
        if (remove.items.len > 0) try syncDir(self.io, self.leaves_dir);
        if (try readOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600)) |bundle| {
            defer self.allocator.free(bundle);
            const candidate = try parseBundle(bundle, true);
            defer candidate.deinit();
            const pending_id = try fingerprint(candidate.certificate);
            if (!std.mem.eql(u8, &pending_id, &active_id)) return error.IncompleteRotation;
            try deleteOwned(self.allocator, self.io, self.dir, "pending-root.pem", 0o600);
        }
        if (try readOwned(self.allocator, self.io, self.dir, "pending-ca.pem", 0o644)) |public| {
            defer self.allocator.free(public);
            const active_public = try certificatePEM(self.allocator, self.certificate);
            defer self.allocator.free(active_public);
            if (!std.mem.eql(u8, active_public, public)) return error.RootFingerprintMismatch;
            try deleteOwned(self.allocator, self.io, self.dir, "pending-ca.pem", 0o644);
        }
    }
    fn clearDiskLeaves(self: *Authority) !void {
        var iterator = self.leaves_dir.iterate();
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| self.allocator.free(name);
            names.deinit(self.allocator);
        }
        while (try iterator.next(self.io)) |entry| {
            if (entry.kind != .file) return error.UnsafeLeafCache;
            const host = try normalizeCacheHost(self.allocator, try leafName(entry.name));
            defer self.allocator.free(host);
            if (!std.mem.eql(u8, host, try leafName(entry.name))) return error.UnsafeLeafCache;
            const file = (try openOwned(self.leaves_dir, entry.name, 0o600)) orelse return error.UnsafeLeafCache;
            file.close(self.io);
            if (names.items.len >= 65537) return error.LeafCacheTooLarge;
            const name = try self.allocator.dupe(u8, entry.name);
            errdefer self.allocator.free(name);
            try names.append(self.allocator, name);
        }
        for (names.items) |name| try self.leaves_dir.deleteFile(self.io, name);
        try syncDir(self.io, self.leaves_dir);
    }
};

fn openPrivateDirectory(io: Io, path: []const u8) !Io.Dir {
    var parent = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer parent.close(io);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    var part = components.next() orelse return error.InvalidStateDirectory;
    while (true) {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidStateDirectory;
        if (components.next()) |next| {
            const child = try parent.openDir(io, part, .{ .follow_symlinks = false });
            parent.close(io);
            parent = child;
            part = next;
        } else {
            parent.createDir(io, part, .fromMode(0o700)) catch |err| if (err != error.PathAlreadyExists) return err;
            return parent.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
        }
    }
}
fn parsePublicRoot(data: []const u8) !*c.X509 {
    if (data.len == 0 or data.len > max_bundle or !std.mem.startsWith(u8, data, "-----BEGIN CERTIFICATE-----")) return error.InvalidAuthority;
    const bio = c.BIO_new_mem_buf(data.ptr, @intCast(data.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    const cert = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidAuthority;
    errdefer c.X509_free(cert);
    if (std.mem.trim(u8, try remaining(bio), " \r\n\t").len != 0 or c.X509_get_ext_by_NID(cert, c.NID_basic_constraints, -1) < 0 or c.X509_get_ext_by_NID(cert, c.NID_key_usage, -1) < 0 or c.X509_check_ca(cert) == 0 or c.X509_get_key_usage(cert) & c.KU_KEY_CERT_SIGN == 0 or c.X509_NAME_cmp(c.X509_get_subject_name(cert), c.X509_get_issuer_name(cert)) != 0 or c.X509_verify(cert, c.X509_get0_pubkey(cert)) != 1) return error.InvalidAuthority;
    return cert;
}
fn now(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).toNanoseconds(), 1_000_000_000));
}
fn expiry(cert: *c.X509) i64 {
    var calendar: c.struct_tm = undefined;
    if (c.ASN1_TIME_to_tm(c.X509_get0_notAfter(cert), &calendar) != 1) return 0;
    return c.timegm(&calendar);
}
fn validNow(cert: *c.X509, seconds: i64) bool {
    const instant = c.ASN1_TIME_set(null, @intCast(seconds)) orelse return false;
    defer c.ASN1_TIME_free(instant);
    if (c.ASN1_TIME_check(c.X509_get0_notBefore(cert)) != 1 or c.ASN1_TIME_check(c.X509_get0_notAfter(cert)) != 1) return false;
    return c.ASN1_TIME_compare(c.X509_get0_notBefore(cert), instant) <= 0 and c.ASN1_TIME_compare(c.X509_get0_notAfter(cert), instant) > 0;
}
fn usableLeaf(cert: *c.X509, seconds: i64, renew_before: i64) bool {
    return validNow(cert, seconds) and expiry(cert) > seconds +| renew_before;
}
// DNS names can reach 253 bytes, while NAME_MAX is 255. Use a shorter cosmetic
// suffix for the longest hosts; exact SAN and ownership checks remain authoritative.
fn leafPath(a: A, host: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}{s}", .{ host, if (host.len > 251) ".p" else ".pem" });
}
fn leafName(path: []const u8) ![]const u8 {
    if (std.mem.endsWith(u8, path, ".pem") and path.len <= 255) return path[0 .. path.len - 4];
    if (path.len >= 254 and path.len <= 255 and std.mem.endsWith(u8, path, ".p")) return path[0 .. path.len - 2];
    return error.UnsafeLeafCache;
}
// A retained leaf may belong to a previous namespace. Validate its exact DNS
// identity and issuer here; configured namespaces still gate every issuance.
fn normalizeCacheHost(a: A, input: []const u8) ![]u8 {
    if (input.len == 0 or input.len > 253 or std.mem.indexOfScalar(u8, input, '.') == null) return error.InvalidCertificateHost;
    const lower = try std.ascii.allocLowerString(a, input);
    errdefer a.free(lower);
    var labels = std.mem.splitScalar(u8, lower, '.');
    while (labels.next()) |label| if (!@import("routes.zig").validLabel(label)) return error.InvalidCertificateHost;
    return lower;
}
fn normalizeHost(a: A, input: []const u8, options: Options) ![]u8 {
    if (input.len == 0 or std.mem.endsWith(u8, input, ".") or std.mem.findAny(u8, input, ":/\\\x00 \r\n\t") != null) return error.InvalidCertificateHost;
    return @import("routes.zig").normalizeAnyAuthority(a, input, options.allowed_suffix, options.allowed_suffixes);
}
fn fingerprint(cert: *c.X509) ![64]u8 {
    var bytes: [32]u8 = undefined;
    var length: c_uint = 0;
    if (c.X509_digest(cert, c.EVP_sha256(), &bytes, &length) != 1 or length != 32) return error.InvalidCertificate;
    return std.fmt.bytesToHex(bytes, .lower);
}
fn bioBytes(a: A, bio: *c.BIO) ![]u8 {
    var data: [*c]u8 = null;
    const count = c.BIO_ctrl(bio, c.BIO_CTRL_INFO, 0, @ptrCast(&data));
    if (count < 0 or count > max_bundle or (count > 0 and data == null)) return error.InvalidCertificate;
    return a.dupe(u8, data[0..@intCast(count)]);
}
fn certificatePEM(a: A, cert: *c.X509) ![]u8 {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_X509(bio, cert) != 1) return error.InvalidCertificate;
    return bioBytes(a, bio);
}
fn bundlePEM(a: A, material: Material) ![]u8 {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    if (c.PEM_write_bio_X509(bio, material.certificate) != 1 or c.PEM_write_bio_PrivateKey(bio, material.key, null, null, 0, null, null) != 1) return error.InvalidCertificate;
    return bioBytes(a, bio);
}
fn remaining(bio: *c.BIO) ![]const u8 {
    var data: [*c]u8 = null;
    const count = c.BIO_ctrl(bio, c.BIO_CTRL_INFO, 0, @ptrCast(&data));
    if (count < 0 or count > max_bundle or (count > 0 and data == null)) return error.InvalidCertificate;
    return if (count == 0) "" else data[0..@intCast(count)];
}
fn parseBundle(data: []const u8, is_root: bool) !Material {
    if (data.len == 0 or data.len > max_bundle or !std.mem.startsWith(u8, std.mem.trimStart(u8, data, " \r\n\t"), "-----BEGIN CERTIFICATE-----")) return error.InvalidCertificate;
    const bio = c.BIO_new_mem_buf(data.ptr, @intCast(data.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    const cert = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidCertificate;
    errdefer c.X509_free(cert);
    if (!std.mem.startsWith(u8, std.mem.trimStart(u8, try remaining(bio), " \r\n\t"), "-----BEGIN PRIVATE KEY-----")) return error.InvalidKey;
    const key = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.InvalidKey;
    errdefer c.EVP_PKEY_free(key);
    if (std.mem.trim(u8, try remaining(bio), " \r\n\t").len != 0 or c.X509_check_private_key(cert, key) != 1) return error.InvalidKey;
    var group: [80]u8 = undefined;
    var length: usize = 0;
    if (c.EVP_PKEY_is_a(key, "EC") != 1 or c.EVP_PKEY_get_group_name(key, &group, group.len, &length) != 1 or length > group.len or !std.mem.eql(u8, group[0..length], "prime256v1")) return error.InvalidKey;
    if (is_root) {
        if (c.X509_get_ext_by_NID(cert, c.NID_basic_constraints, -1) < 0 or c.X509_get_ext_by_NID(cert, c.NID_key_usage, -1) < 0 or c.X509_check_ca(cert) == 0 or c.X509_get_key_usage(cert) & c.KU_KEY_CERT_SIGN == 0 or c.X509_NAME_cmp(c.X509_get_subject_name(cert), c.X509_get_issuer_name(cert)) != 0 or c.X509_verify(cert, key) != 1) return error.InvalidAuthority;
    } else if (c.X509_check_ca(cert) != 0) return error.InvalidLeafCertificate;
    return .{ .certificate = cert, .key = key };
}
fn validateLeaf(material: Material, host: []const u8, root: *c.X509) !void {
    const cert = material.certificate;
    if (c.ASN1_TIME_check(c.X509_get0_notBefore(cert)) != 1 or c.ASN1_TIME_check(c.X509_get0_notAfter(cert)) != 1 or c.X509_get_ext_by_NID(cert, c.NID_basic_constraints, -1) < 0 or c.X509_get_ext_by_NID(cert, c.NID_ext_key_usage, -1) < 0 or c.X509_check_ca(cert) != 0 or c.X509_check_private_key(cert, material.key) != 1 or c.X509_check_issued(root, cert) != c.X509_V_OK or c.X509_verify(cert, c.X509_get0_pubkey(root)) != 1 or c.ASN1_TIME_compare(c.X509_get0_notAfter(cert), c.X509_get0_notAfter(root)) > 0 or c.X509_get_extended_key_usage(cert) & c.XKU_SSL_SERVER == 0) return error.InvalidLeafCertificate;
    if (!exactDNSName(cert, host)) return error.InvalidLeafCertificate;
}
/// True when the only subject alternative name is exactly this DNS host.
fn exactDNSName(cert: *c.X509, host: []const u8) bool {
    const raw = c.X509_get_ext_d2i(cert, c.NID_subject_alt_name, null, null) orelse return false;
    const names: *c.GENERAL_NAMES = @ptrCast(@alignCast(raw));
    defer c.GENERAL_NAMES_free(names);
    if (c.OPENSSL_sk_num(@ptrCast(names)) != 1) return false;
    const item: *c.GENERAL_NAME = @ptrCast(@alignCast(c.OPENSSL_sk_value(@ptrCast(names), 0) orelse return false));
    if (item.type != c.GEN_DNS) return false;
    const size = c.ASN1_STRING_length(item.d.dNSName);
    const bytes = c.ASN1_STRING_get0_data(item.d.dNSName);
    return size > 0 and bytes != null and std.mem.eql(u8, bytes[0..@intCast(size)], host);
}
fn newRoot(a: A, io: Io, options: Options) !Material {
    const key = try generateKey();
    errdefer c.EVP_PKEY_free(key);
    return .{ .key = key, .certificate = try makeCertificate(a, io, key, null, null, options.root_common_name, true, options) };
}
fn loadOrCreateRoot(a: A, io: Io, dir: Io.Dir, options: Options) !Material {
    const old_cert = try readOwned(a, io, dir, "ca.pem", 0o644);
    defer if (old_cert) |data| a.free(data);
    const old_key = try readOwned(a, io, dir, "ca-key.pem", 0o600);
    defer if (old_key) |data| a.free(data);
    if ((old_cert == null) != (old_key == null)) return error.IncompleteAuthority;
    const material = if (old_cert) |cert| blk: {
        const bundle = try std.mem.concat(a, u8, &.{ cert, old_key.? });
        defer a.free(bundle);
        break :blk try parseBundle(bundle, true);
    } else try newRoot(a, io, options);
    errdefer material.deinit();
    if (!validNow(material.certificate, now(io))) return error.InvalidAuthority;
    const bundle = try bundlePEM(a, material);
    defer a.free(bundle);
    try atomicOwnedWrite(a, io, dir, "root.pem", bundle, 0o600);
    if (old_key != null) try deleteOwned(a, io, dir, "ca-key.pem", 0o600);
    return material;
}
fn readFile(a: A, io: Io, file: Io.File) ![]u8 {
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(a, .limited(max_bundle));
}
fn readOwned(a: A, io: Io, dir: Io.Dir, name: []const u8, mode: u16) !?[]u8 {
    const file = (try openOwned(dir, name, mode)) orelse return null;
    defer file.close(io);
    return try readFile(a, io, file);
}
/// Opens an owned regular file without following a final symlink, or null when absent.
/// O_NONBLOCK keeps a planted FIFO or device from blocking open(); it is cleared only
/// after fstat proves a regular file with the exact owner and mode.
fn openOwned(dir: Io.Dir, name: []const u8, mode: u16) !?Io.File {
    var buffer: [256]u8 = undefined;
    if (name.len >= buffer.len or std.mem.findScalar(u8, name, 0) != null) return error.UnsafeStateFile;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    const fd = while (true) {
        const result = c.openat(dir.handle, &buffer, c.O_RDONLY | c.O_CLOEXEC | c.O_NOFOLLOW | c.O_NONBLOCK);
        if (result >= 0) break result;
        switch (std.c._errno().*) {
            c.EINTR => continue,
            c.ENOENT => return null,
            c.ELOOP => return error.UnsafeStateFile,
            else => return error.FileOpenFailed,
        }
    };
    errdefer _ = c.close(fd);
    try osprocess.validateOwned(fd, mode, false);
    const flags = c.fcntl(fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags & ~@as(c_int, c.O_NONBLOCK)) < 0) return error.FileOpenFailed;
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}
fn atomicOwnedWrite(a: A, io: Io, dir: Io.Dir, name: []const u8, data: []const u8, mode: u16) !void {
    if (try readOwned(a, io, dir, name, mode)) |existing| {
        defer a.free(existing);
        if (std.mem.eql(u8, existing, data)) return;
    }
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true, .permissions = .fromMode(mode) });
    defer atomic.deinit(io);
    // Explicit modes also survive the service's restrictive creation umask.
    try atomic.file.setPermissions(io, .fromMode(mode));
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncDir(io, dir);
}
fn deleteOwned(a: A, io: Io, dir: Io.Dir, name: []const u8, mode: u16) !void {
    const existing = (try readOwned(a, io, dir, name, mode)) orelse return;
    defer a.free(existing);
    try dir.deleteFile(io, name);
    try syncDir(io, dir);
}
fn syncDir(io: Io, dir: Io.Dir) !void {
    const file: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}
pub fn secureFile(path: [:0]const u8, private: bool) !void {
    var st: c.struct_stat = undefined;
    if (c.lstat(path, &st) != 0 or st.st_mode & c.S_IFMT != c.S_IFREG or st.st_mode & 0o022 != 0 or (private and st.st_mode & 0o077 != 0) or (st.st_uid != 0 and st.st_uid != c.geteuid())) return error.UnsafeCertificatePath;
}
/// Custom PEM loading keeps the existing API while using a narrow native
/// descriptor boundary. OpenSSL receives only objects parsed from owned bytes.
pub fn fileContext(a: A, certpath: []const u8, keypath: []const u8) !*c.SSL_CTX {
    if (!std.fs.path.isAbsolute(certpath) or !std.fs.path.isAbsolute(keypath) or std.mem.eql(u8, certpath, keypath) or std.mem.findScalar(u8, certpath, 0) != null or std.mem.findScalar(u8, keypath, 0) != null) return error.InvalidCertificatePath;
    const certificates = try readCustomPEM(a, certpath, false);
    defer a.free(certificates);
    const private_key = try readCustomPEM(a, keypath, true);
    defer a.free(private_key);
    const bio = c.BIO_new_mem_buf(certificates.ptr, @intCast(certificates.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    if (!std.mem.startsWith(u8, std.mem.trimStart(u8, certificates, " \r\n\t"), "-----BEGIN CERTIFICATE-----")) return error.InvalidCertificate;
    const leaf = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidCertificate;
    defer c.X509_free(leaf);
    // ASN.1 comparisons reject malformed dates, including the -2 error result.
    const instant = c.time(null);
    if (c.X509_check_ca(leaf) != 0 or !validNow(leaf, instant) or c.X509_check_purpose(leaf, c.X509_PURPOSE_SSL_SERVER, 0) != 1) return error.InvalidCertificate;
    const key_bio = c.BIO_new_mem_buf(private_key.ptr, @intCast(private_key.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(key_bio);
    const key_data = std.mem.trimStart(u8, private_key, " \r\n\t");
    if (!std.mem.startsWith(u8, key_data, "-----BEGIN PRIVATE KEY-----") and !std.mem.startsWith(u8, key_data, "-----BEGIN RSA PRIVATE KEY-----") and !std.mem.startsWith(u8, key_data, "-----BEGIN EC PRIVATE KEY-----")) return error.InvalidKey; // gitleaks:allow PEM format markers only; no key material.
    // Encrypted PEMs fail without ever prompting on the application's stdin.
    const key = c.PEM_read_bio_PrivateKey(key_bio, null, rejectPassword, null) orelse return error.InvalidKey;
    defer c.EVP_PKEY_free(key);
    if (std.mem.trim(u8, try remaining(key_bio), " \r\n\t").len != 0 or c.X509_check_private_key(leaf, key) != 1) return error.InvalidKey;
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TLSFailed;
    errdefer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate(ctx, leaf) != 1 or c.SSL_CTX_use_PrivateKey(ctx, key) != 1 or c.SSL_CTX_check_private_key(ctx) != 1 or c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION) != 1) return error.InvalidCertificate;
    var previous = leaf;
    var count: usize = 1;
    while (std.mem.trim(u8, try remaining(bio), " \r\n\t").len != 0) {
        if (count >= 32 or !std.mem.startsWith(u8, std.mem.trimStart(u8, try remaining(bio), " \r\n\t"), "-----BEGIN CERTIFICATE-----")) return error.InvalidCertificate;
        const issuer = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidCertificate;
        if (c.X509_check_ca(issuer) == 0 or !validNow(issuer, instant) or c.X509_check_issued(issuer, previous) != c.X509_V_OK or c.X509_verify(previous, c.X509_get0_pubkey(issuer)) != 1 or c.SSL_CTX_add_extra_chain_cert(ctx, issuer) != 1) {
            c.X509_free(issuer);
            return error.InvalidCertificate;
        }
        // SSL_CTX owns the chain certificate after successful addition.
        previous = issuer;
        count += 1;
    }
    return ctx;
}
fn rejectPassword(_: [*c]u8, _: c_int, _: c_int, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}
fn customFileStat(fd: c_int, private: bool) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(fd, &stat) != 0 or stat.st_mode & c.S_IFMT != c.S_IFREG or stat.st_mode & 0o022 != 0 or (private and stat.st_mode & 0o077 != 0) or (stat.st_uid != 0 and stat.st_uid != c.geteuid()) or stat.st_nlink != 1) return error.UnsafeCertificatePath;
    if (stat.st_size <= 0 or stat.st_size > max_bundle) return error.InvalidCertificate;
    return stat;
}
fn readCustomPEM(a: A, path: []const u8, private: bool) ![]u8 {
    var parent = c.open("/", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC | c.O_NOFOLLOW);
    if (parent < 0) return error.UnsafeCertificatePath;
    defer _ = c.close(parent);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    var component = components.next() orelse return error.InvalidCertificatePath;
    while (true) {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidCertificatePath;
        const name = try a.dupeSentinel(u8, component, 0);
        defer a.free(name);
        if (components.next()) |next| {
            const child = c.openat(parent, name, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC | c.O_NOFOLLOW);
            if (child < 0) return error.UnsafeCertificatePath;
            _ = c.close(parent);
            parent = child;
            component = next;
            continue;
        }
        // Nonblocking prevents a substituted FIFO from blocking before fstat.
        const fd = c.openat(parent, name, c.O_RDONLY | c.O_CLOEXEC | c.O_NOFOLLOW | c.O_NONBLOCK);
        if (fd < 0) return error.UnsafeCertificatePath;
        defer _ = c.close(fd);
        const before = try customFileStat(fd, private);
        const bytes = try a.alloc(u8, @intCast(before.st_size));
        errdefer a.free(bytes);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const n = c.read(fd, bytes.ptr + offset, bytes.len - offset);
            if (n < 0) {
                if (std.c._errno().* == c.EINTR) continue;
                return error.CertificateReadFailed;
            }
            if (n == 0) return error.AuthorityChanged;
            offset += @intCast(n);
        }
        var extra: [1]u8 = undefined;
        while (true) {
            const n = c.read(fd, &extra, extra.len);
            if (n < 0 and std.c._errno().* == c.EINTR) continue;
            if (n != 0) return error.AuthorityChanged;
            break;
        }
        const after = try customFileStat(fd, private);
        const mtime_before = if (@import("builtin").os.tag == .macos) before.st_mtimespec else before.st_mtim;
        const mtime_after = if (@import("builtin").os.tag == .macos) after.st_mtimespec else after.st_mtim;
        const ctime_before = if (@import("builtin").os.tag == .macos) before.st_ctimespec else before.st_ctim;
        const ctime_after = if (@import("builtin").os.tag == .macos) after.st_ctimespec else after.st_ctim;
        if (before.st_dev != after.st_dev or before.st_ino != after.st_ino or before.st_size != after.st_size or mtime_before.tv_sec != mtime_after.tv_sec or mtime_before.tv_nsec != mtime_after.tv_nsec or ctime_before.tv_sec != ctime_after.tv_sec or ctime_before.tv_nsec != ctime_after.tv_nsec) return error.AuthorityChanged;
        return bytes;
    }
}

fn generateKey() !*c.EVP_PKEY {
    const context = c.EVP_PKEY_CTX_new_from_name(null, "EC", null) orelse return error.KeyGenerationFailed;
    defer c.EVP_PKEY_CTX_free(context);
    if (c.EVP_PKEY_keygen_init(context) <= 0 or c.EVP_PKEY_CTX_set_group_name(context, "prime256v1") <= 0) return error.KeyGenerationFailed;
    var key: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_generate(context, &key) <= 0) return error.KeyGenerationFailed;
    return key.?;
}
fn extension(cert: *c.X509, issuer: *c.X509, nid: c_int, value: [:0]const u8) !void {
    var context: c.X509V3_CTX = std.mem.zeroes(c.X509V3_CTX);
    c.X509V3_set_ctx(&context, issuer, cert, null, null, 0);
    const ext = c.X509V3_EXT_conf_nid(null, &context, nid, @constCast(value.ptr)) orelse return error.CertificateGenerationFailed;
    defer c.X509_EXTENSION_free(ext);
    if (c.X509_add_ext(cert, ext, -1) != 1) return error.CertificateGenerationFailed;
}
fn makeCertificate(a: A, io: Io, key: *c.EVP_PKEY, issuer: ?*c.X509, issuer_key: ?*c.EVP_PKEY, name: []const u8, is_ca: bool, options: Options) !*c.X509 {
    const cert = c.X509_new() orelse return error.CertificateGenerationFailed;
    errdefer c.X509_free(cert);
    var serial: [16]u8 = undefined;
    io.random(&serial);
    serial[0] &= 0x7f;
    serial[15] |= 1;
    const bn = c.BN_bin2bn(&serial, serial.len, null) orelse return error.CertificateGenerationFailed;
    defer c.BN_free(bn);
    const number = c.BN_to_ASN1_INTEGER(bn, null) orelse return error.CertificateGenerationFailed;
    defer c.ASN1_INTEGER_free(number);
    if (c.X509_set_version(cert, 2) != 1 or c.X509_set_serialNumber(cert, number) != 1 or c.X509_set_pubkey(cert, key) != 1) return error.CertificateGenerationFailed;
    const instant = now(io);
    if (c.ASN1_TIME_set(c.X509_getm_notBefore(cert), @intCast(instant - (if (is_ca) @as(i64, 300) else 60))) == null or c.ASN1_TIME_set(c.X509_getm_notAfter(cert), @intCast(instant + (if (is_ca) options.root_validity_seconds else options.leaf_validity_seconds))) == null) return error.CertificateGenerationFailed;
    if (issuer) |root| if (c.ASN1_TIME_compare(c.X509_get0_notAfter(cert), c.X509_get0_notAfter(root)) > 0) {
        if (c.X509_set1_notAfter(cert, c.X509_get0_notAfter(root)) != 1) return error.CertificateGenerationFailed;
    };
    const subject = @constCast(c.X509_get_subject_name(cert));
    const common_name = name[0..@min(name.len, 64)];
    if (c.X509_NAME_add_entry_by_txt(subject, "CN", c.MBSTRING_ASC, common_name.ptr, @intCast(common_name.len), -1, 0) != 1 or c.X509_set_issuer_name(cert, if (issuer) |root| c.X509_get_subject_name(root) else subject) != 1) return error.CertificateGenerationFailed;
    try extension(cert, issuer orelse cert, c.NID_basic_constraints, if (is_ca) "critical,CA:TRUE,pathlen:0" else "critical,CA:FALSE");
    try extension(cert, issuer orelse cert, c.NID_subject_key_identifier, "hash");
    try extension(cert, issuer orelse cert, c.NID_authority_key_identifier, "keyid:always");
    try extension(cert, issuer orelse cert, c.NID_key_usage, if (is_ca) "critical,digitalSignature,keyCertSign,cRLSign" else "critical,digitalSignature");
    if (!is_ca) {
        try extension(cert, issuer.?, c.NID_ext_key_usage, "serverAuth");
        const san = try std.fmt.allocPrintSentinel(a, "DNS:{s}", .{name}, 0);
        defer a.free(san);
        try extension(cert, issuer.?, c.NID_subject_alt_name, san);
    }
    if (c.X509_sign(cert, issuer_key orelse key, c.EVP_sha256()) <= 0) return error.CertificateGenerationFailed;
    return cert;
}
