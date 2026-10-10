//! A foreground-capable runtime. Caller controls cancellation and lifetime.
const std = @import("std");
const net = @import("net.zig");
const c = net.c;
const protocol = @import("protocol.zig");
const registry = @import("registry.zig");
const profile = @import("profile.zig");
const routes = @import("routes.zig");
const process = @import("process.zig");
const pki = @import("pki.zig");
const proxy = @import("proxy.zig");
const apple = @import("applecredential.zig");
pub const Config = struct {
    state_dir: []const u8,
    socket_path: []const u8 = "/var/run/dotlocal-zig/management.sock",
    management_gid: ?u32 = null,
    profile: profile.Config = .{},
    profile_explicit: bool = false,
    legacy_listeners: bool = true,
    redirect_listen: ?[]const u8 = null,
    container_cli: ?[]const u8 = null,
    dual_loopback: ?bool = null,
    reconcile_profile: bool = false,
};
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    loaded_profile: ?std.json.Parsed(profile.Config) = null,
    profile_tld: []u8,
    profile_tlds: [][]const u8,
    registry: registry.Registry,
    authority: ?pki.Authority = null,
    base_ctx: ?*c.SSL_CTX = null,
    cert_mutex: std.Io.Mutex = .init,
    certificates: std.StringHashMapUnmanaged(*c.SSL_CTX) = .empty,
    management: c_int = -1,
    public: c_int = -1,
    redirect: c_int = -1,
    public_v6: c_int = -1,
    redirect_v6: c_int = -1,
    connection_mutex: std.Io.Mutex = .init,
    connections: [160]c_int = @splat(-1),
    cancels: [160]proxy.Cancel = @splat(.{}),
    tasks: std.Io.Group = .init,
    stopping: std.atomic.Value(bool) = .init(false),
    pub fn init(a: std.mem.Allocator, io: std.Io, requested: Config) !*Runtime {
        if (@import("builtin").os.tag != .macos and @import("builtin").os.tag != .linux) return error.UnsupportedPlatform;
        var config = requested;
        var loaded: ?std.json.Parsed(profile.Config) = null;
        if (!config.profile_explicit and config.profile.isDefault()) {
            loaded = try profile.load(a, io, config.state_dir);
            if (loaded) |saved| config.profile = saved.value;
        }
        errdefer if (loaded) |saved| saved.deinit();
        const tld = try routes.normalizeTld(a, config.profile.tld);
        errdefer a.free(tld);
        config.profile.tld = tld;
        if (config.legacy_listeners and !config.profile_explicit and config.profile.isDefault()) {
            if (config.dual_loopback == null) config.dual_loopback = true;
            if (config.redirect_listen == null) config.redirect_listen = "127.0.0.1:80";
        }
        const tlds = try routes.cloneTlds(a, tld, config.profile.tlds);
        errdefer {
            for (tlds) |suffix| a.free(suffix);
            a.free(tlds);
        }
        config.profile.tlds = tlds;
        try config.profile.validate(a);
        const self = try a.create(Runtime);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .io = io, .config = config, .loaded_profile = loaded, .profile_tld = tld, .profile_tlds = tlds, .registry = try registry.Registry.init(a, io, config.state_dir, config.profile) };
        errdefer self.registry.deinit();
        try self.refresh();
        self.management = try net.listenUnix(a, config.socket_path);
        errdefer {
            net.close(self.management);
            const z = a.dupeSentinel(u8, config.socket_path, 0) catch null;
            if (z) |path| {
                defer a.free(path);
                _ = c.unlink(path);
            }
        }
        if (config.management_gid) |management_gid| {
            const socket_z = try a.dupeSentinel(u8, config.socket_path, 0);
            defer a.free(socket_z);
            if (c.chown(socket_z, c.geteuid(), management_gid) != 0) return error.SocketOwnershipFailed;
        }
        const address = try std.Io.net.IpAddress.parseLiteral(config.profile.listen);
        const host = try ipHost(a, address);
        defer a.free(host);
        self.public = try net.tcp(a, host, address.getPort(), true);
        errdefer net.close(self.public);
        if (config.redirect_listen) |value| {
            const addr = try std.Io.net.IpAddress.parseLiteral(value);
            const h = try ipHost(a, addr);
            defer a.free(h);
            const cls = try routes.classifyAddress(h);
            if (!cls.loopback) return error.InvalidListener;
            self.redirect = try net.tcp(a, h, addr.getPort(), true);
        }
        errdefer if (self.redirect >= 0) net.close(self.redirect);
        errdefer {
            if (self.public_v6 >= 0) net.close(self.public_v6);
            if (self.redirect_v6 >= 0) net.close(self.redirect_v6);
        }
        if (config.dual_loopback orelse false) {
            if (!std.mem.eql(u8, host, "127.0.0.1")) return error.InvalidDualLoopback;
            self.public_v6 = try net.tcp(a, "::1", address.getPort(), true);
            if (config.redirect_listen) |listener| {
                const redirect_address = try std.Io.net.IpAddress.parseLiteral(listener);
                self.redirect_v6 = try net.tcp(a, "::1", redirect_address.getPort(), true);
            }
        }
        if (std.mem.eql(u8, config.profile.scheme, "https")) {
            if (config.profile.cert) |cert| {
                self.base_ctx = try pki.fileContext(a, cert, config.profile.key.?);
            } else {
                const directory = try std.fmt.allocPrint(a, "{s}/pki", .{config.state_dir});
                defer a.free(directory);
                self.authority = try pki.Authority.initWithOptions(a, io, directory, .{ .allowed_suffix = config.profile.tld, .allowed_suffixes = config.profile.tlds, .max_leaf_certificates = 1024, .allow_host = allowCertificateHost, .allow_context = self });
                // SNI chooses a currently registered exact-host certificate.
                self.base_ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse {
                    self.authority.?.deinit();
                    return error.TLSFailed;
                };
                if (c.SSL_CTX_set_min_proto_version(self.base_ctx.?, c.TLS1_2_VERSION) != 1) {
                    c.SSL_CTX_free(self.base_ctx.?);
                    self.authority.?.deinit();
                    return error.TLSFailed;
                }
            }
            _ = c.SSL_CTX_callback_ctrl(self.base_ctx.?, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&sni));
            _ = c.SSL_CTX_set_tlsext_servername_arg(self.base_ctx.?, self);
            c.SSL_CTX_set_alpn_select_cb(self.base_ctx.?, alpn, null);
        }
        errdefer {
            if (self.base_ctx) |ctx| c.SSL_CTX_free(ctx);
            if (self.authority) |*authority| authority.deinit();
        }
        try self.persistProfile();
        return self;
    }
    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        net.close(self.management);
        net.close(self.public);
        if (self.public_v6 >= 0) net.close(self.public_v6);
        if (self.redirect_v6 >= 0) net.close(self.redirect_v6);
        if (self.redirect >= 0) net.close(self.redirect);
        self.connection_mutex.lockUncancelable(self.io);
        for (self.connections, 0..) |fd, index| if (fd >= 0) {
            self.cancels[index].stop();
            _ = c.shutdown(fd, c.SHUT_RDWR);
        };
        self.connection_mutex.unlock(self.io);
        self.tasks.await(self.io) catch {};
        const z = self.allocator.dupeSentinel(u8, self.config.socket_path, 0) catch null;
        if (z) |path| {
            defer self.allocator.free(path);
            _ = c.unlink(path);
        }
        var it = self.certificates.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            c.SSL_CTX_free(entry.value_ptr.*);
        }
        self.certificates.deinit(self.allocator);
        if (self.base_ctx) |ctx| c.SSL_CTX_free(ctx);
        if (self.authority) |*authority| authority.deinit();
        self.registry.deinit();
        if (self.loaded_profile) |saved| saved.deinit();
        self.allocator.free(self.profile_tld);
        for (self.profile_tlds) |suffix| self.allocator.free(suffix);
        self.allocator.free(self.profile_tlds);
        self.allocator.destroy(self);
    }
    /// Runs until stop is set. Runtime operations are bounded; no install or trust side effects.
    pub fn run(self: *Runtime, stop: *const std.atomic.Value(bool)) !void {
        var polls = [_]c.struct_pollfd{ .{ .fd = self.management, .events = c.POLLIN, .revents = 0 }, .{ .fd = self.public, .events = c.POLLIN, .revents = 0 }, .{ .fd = self.redirect, .events = c.POLLIN, .revents = 0 }, .{ .fd = self.public_v6, .events = c.POLLIN, .revents = 0 }, .{ .fd = self.redirect_v6, .events = c.POLLIN, .revents = 0 } };
        defer self.stopping.store(true, .release);
        try self.tasks.concurrent(self.io, refreshLoop, .{ self, stop });
        while (!stop.load(.acquire)) {
            const n = c.poll(&polls, polls.len, 200);
            if (n < 0) continue;
            for (&polls, 0..) |*p, index| {
                if (p.revents & c.POLLIN == 0) continue;
                var peer: c.struct_sockaddr_storage = undefined;
                var len: c.socklen_t = @sizeOf(@TypeOf(peer));
                const fd = c.accept(p.fd, @ptrCast(&peer), &len);
                if (fd < 0) continue;
                net.configure(fd, if (index == 0) 5 else 30);
                self.connection_mutex.lockUncancelable(self.io);
                // Public clients cannot exhaust authenticated management capacity.
                const begin: usize = if (index == 0) 0 else 32;
                const end: usize = if (index == 0) 32 else self.connections.len;
                const available = std.mem.indexOfScalar(c_int, self.connections[begin..end], -1);
                const slot = if (available) |offset| begin + offset else null;
                if (slot) |position| {
                    self.cancels[position] = .{};
                    self.connections[position] = fd;
                }
                self.connection_mutex.unlock(self.io);
                if (slot == null) {
                    net.close(fd);
                    continue;
                }
                // One connection that cannot get a task is dropped; the listeners keep serving.
                self.tasks.concurrent(self.io, connection, .{ self, fd, index, slot.?, peer }) catch |err| {
                    self.connection_mutex.lockUncancelable(self.io);
                    self.connections[slot.?] = -1;
                    self.connection_mutex.unlock(self.io);
                    net.close(fd);
                    std.log.warn("connection task: {s}", .{@errorName(err)});
                };
            }
        }
    }
    fn connection(self: *Runtime, fd: c_int, index: usize, slot: usize, peer: c.struct_sockaddr_storage) void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var stream: net.Stream = .{ .fd = fd };
        defer {
            self.connection_mutex.lockUncancelable(self.io);
            self.connections[slot] = -1;
            stream.deinit();
            self.connection_mutex.unlock(self.io);
        }
        if (index == 0) {
            self.managementCall(a, stream) catch {};
            return;
        }
        if ((index == 1 or index == 3) and self.base_ctx != null) {
            const ssl = c.SSL_new(self.base_ctx.?) orelse return;
            stream.ssl = ssl;
            if (c.SSL_set_fd(ssl, fd) != 1 or c.SSL_accept(ssl) != 1) return;
            var selected: [*c]const u8 = null;
            var selected_len: c_uint = 0;
            c.SSL_get0_alpn_selected(ssl, &selected, &selected_len);
            if (selected_len == 2 and std.mem.eql(u8, selected[0..selected_len], "h2")) {
                @import("http2.zig").serve(self.allocator, self.io, stream, &self.registry, self.config.profile, self.caPath(a) catch null, remoteIP(a, peer) catch "127.0.0.1") catch {};
                return;
            }
        }
        proxy.serveWatched(a, stream, &self.registry, self.config.profile, self.caPath(a) catch null, remoteIP(a, peer) catch "127.0.0.1", (index == 2 or index == 4), &self.cancels[slot]) catch {};
    }
    fn caPath(self: *Runtime, a: std.mem.Allocator) !?[]const u8 {
        if (self.authority) |authority| return try std.fmt.allocPrint(a, "{s}/ca.pem", .{authority.directory});
        return null;
    }
    fn managementCall(self: *Runtime, a: std.mem.Allocator, stream: net.Stream) !void {
        var allowed = false;
        var uid: c.uid_t = 0;
        if (@import("builtin").os.tag == .linux) {
            // Linux SO_PEERCRED returns this stable kernel ABI. Defining it here
            // avoids GNU transparent sockaddr unions in the translated headers.
            var creds: extern struct { pid: c.pid_t, uid: c.uid_t, gid: c.gid_t } = undefined;
            var creds_len: c.socklen_t = @sizeOf(@TypeOf(creds));
            if (c.getsockopt(stream.fd, c.SOL_SOCKET, c.SO_PEERCRED, &creds, &creds_len) != 0 or creds_len != @sizeOf(@TypeOf(creds))) return error.InvalidPeer;
            uid = creds.uid;
            allowed = creds.uid == 0 or creds.uid == c.geteuid() or (self.config.management_gid != null and creds.gid == self.config.management_gid.?);
            if (!allowed) if (self.config.management_gid) |group| {
                // SO_PEERGROUPS authenticates the groups captured by the kernel
                // at connect time, without trusting /proc or account databases.
                const groups = try a.alloc(c.gid_t, 65536);
                var length: c.socklen_t = @intCast(groups.len * @sizeOf(c.gid_t));
                if (c.getsockopt(stream.fd, c.SOL_SOCKET, c.SO_PEERGROUPS, groups.ptr, &length) != 0 or length > groups.len * @sizeOf(c.gid_t) or length % @sizeOf(c.gid_t) != 0) return error.InvalidPeer;
                allowed = std.mem.indexOfScalar(c.gid_t, groups[0 .. length / @sizeOf(c.gid_t)], group) != null;
            };
        } else {
            var creds: c.struct_xucred = undefined;
            var creds_len: c.socklen_t = @sizeOf(@TypeOf(creds));
            if (c.getsockopt(stream.fd, 0, c.LOCAL_PEERCRED, &creds, &creds_len) != 0 or creds.cr_version != 0 or creds.cr_ngroups < 0 or creds.cr_ngroups > 16) return error.InvalidPeer;
            uid = creds.cr_uid;
            allowed = creds.cr_uid == 0 or creds.cr_uid == c.geteuid();
            if (self.config.management_gid) |management_gid| for (creds.cr_groups[0..@intCast(creds.cr_ngroups)]) |group| if (group == management_gid) {
                allowed = true;
                break;
            };
        }
        if (!allowed) return error.Unauthorized;
        const data = try net.readFrame(a, stream, 65536);
        const parsed = protocol.parseRequest(a, data) catch {
            try writeResponse(a, stream, .{ .version = 2, .id = "invalid", .ok = false, .@"error" = .{ .code = "invalid_request", .message = "invalid management request" } });
            return;
        };
        // parseRequest has already validated the decoded request.
        var request = parsed.value;
        const response = self.execute(a, uid, &request) catch |err| {
            try writeResponse(a, stream, .{ .version = 2, .id = request.id, .ok = false, .@"error" = .{ .code = if (err == error.RouteConflict) "route_conflict" else "operation_failed", .message = @errorName(err) } });
            return;
        };
        try writeResponse(a, stream, response);
    }
    fn execute(self: *Runtime, a: std.mem.Allocator, uid: u32, request: *protocol.Request) !protocol.Response {
        var response: protocol.Response = .{ .version = 2, .id = request.id, .ok = true };
        const op = request.operation;
        if (std.mem.eql(u8, op, "add")) {
            var route = request.route.?;
            if (std.mem.eql(u8, route.owner.kind, "process")) {
                if (route.owner.process_start != 0) return error.InvalidOwner;
                const identity = try process.inspect(route.owner.pid);
                if (uid != 0 and uid != identity.uid) return error.UnauthorizedOwner;
                route.owner.process_start = identity.start;
            }
            if (std.mem.eql(u8, route.owner.kind, "container")) {
                if (uid == 0 or route.owner.inspector_uid != 0) return error.UnprivilegedLoginRequired;
                const endpoint = try apple.resolve(a, self.io, self.config.container_cli orelse return error.ContainerNotConfigured, route.owner.container, route.port, route.scheme, uid);
                if (!std.mem.eql(u8, endpoint.host, route.host) or !std.mem.eql(u8, endpoint.network, route.owner.network)) return error.StaleContainer;
                route.owner.inspector_uid = uid;
            }
            request.route = route;
            const result = try self.registry.mutate(request.*);
            if (result) |r| {
                defer r.deinit(self.allocator);
                response.route = try r.clone(a);
            }
        } else if (std.mem.eql(u8, op, "remove")) {
            if (try self.registry.mutate(request.*)) |r| r.deinit(self.allocator);
        } else if (std.mem.eql(u8, op, "list")) {
            response.routes = try self.registry.list(a);
        } else if (std.mem.eql(u8, op, "status")) {
            response.status = .{ .running = true, .version = @import("build_options").version, .socket_path = self.config.socket_path, .scheme = self.config.profile.scheme, .listen_address = self.config.profile.listen, .tld = self.config.profile.tld, .tlds = if (self.config.profile.tlds.len > 1) self.config.profile.tlds else null, .wildcard_fallback = self.config.profile.wildcard, .certificate_mode = if (self.config.profile.cert != null) "files" else if (self.authority != null) "local-ca" else "", .certificate_file = self.config.profile.cert orelse "", .key_file = self.config.profile.key orelse "" };
        } else if (std.mem.eql(u8, op, "doctor")) {
            var diagnostics: std.ArrayList(protocol.Diagnostic) = .empty;
            try diagnostics.appendSlice(a, &.{ .{ .name = "management", .level = "ok", .message = "authenticated Unix management listener" }, .{ .name = "proxy", .level = "ok", .message = "loopback listener active" } });
            if (try self.caPath(a)) |cert| {
                if (@import("service.zig").systemTrusted(a, self.io, cert)) |trusted| {
                    try diagnostics.append(a, .{ .name = "ca-trust", .level = if (trusted) "ok" else "warning", .message = if (trusted) "exact local CA is in the System keychain" else "exact local CA is absent from the System keychain" });
                } else |err| {
                    try diagnostics.append(a, .{ .name = "ca-trust", .level = "warning", .message = try std.fmt.allocPrint(a, "System keychain inspection failed: {s}", .{@errorName(err)}) });
                }
            }
            response.diagnostics = try diagnostics.toOwnedSlice(a);
        } else if (std.mem.eql(u8, op, "refresh")) {
            try self.refresh();
            response.diagnostics = &.{.{ .name = "routes", .level = "ok", .message = "live process owners checked" }};
        } else if (std.mem.eql(u8, op, "install") or std.mem.eql(u8, op, "uninstall")) return error.PrivilegeRequired else return error.UnsupportedOperation;
        return response;
    }
    pub fn refresh(self: *Runtime) !void {
        try self.refreshUntil(null);
    }
    fn refreshUntil(self: *Runtime, stop: ?*const std.atomic.Value(bool)) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const list = try self.registry.list(a);
        for (list) |route| {
            if (stop) |value| if (value.load(.acquire)) return;
            if (std.mem.eql(u8, route.owner.kind, "process")) self.registry.setActiveOwned(route.name, route.owner, process.matches(route.owner)) catch |err| {
                if (err != error.RouteConflict) return err;
            };
            if (std.mem.eql(u8, route.owner.kind, "container")) {
                const executable = self.config.container_cli orelse {
                    self.registry.setActiveOwned(route.name, route.owner, false) catch {};
                    continue;
                };
                const endpoint = apple.resolve(a, self.io, executable, route.owner.container, route.port, route.scheme, route.owner.inspector_uid) catch {
                    self.registry.setActiveOwned(route.name, route.owner, false) catch {};
                    continue;
                };
                var updated = route;
                updated.host = endpoint.host;
                updated.port = endpoint.port;
                updated.owner.network = endpoint.network;
                if (std.mem.eql(u8, updated.host, route.host) and updated.port == route.port and std.mem.eql(u8, updated.owner.network, route.owner.network)) {
                    self.registry.setActiveOwned(route.name, route.owner, true) catch {};
                    continue;
                }
                self.registry.replaceOwned(updated, route.owner) catch |err| {
                    if (err != error.RouteConflict) return err;
                };
            }
        }
    }
    fn refreshLoop(self: *Runtime, stop: *const std.atomic.Value(bool)) void {
        var iterations: u32 = 0;
        while (!stop.load(.acquire) and !self.stopping.load(.acquire)) {
            iterations += 1;
            if (iterations % 10 == 1) self.refreshUntil(stop) catch |err| std.log.warn("route refresh: {s}", .{@errorName(err)});
            std.Io.sleep(self.io, .fromMilliseconds(200), .awake) catch return;
        }
    }
    fn persistProfile(self: *Runtime) !void {
        const dir = self.registry.dir;
        const current = try std.json.Stringify.valueAlloc(self.allocator, self.config.profile, .{});
        defer self.allocator.free(current);
        if (try profile.load(self.allocator, self.io, self.config.state_dir)) |saved| {
            defer saved.deinit();
            var prior = saved.value;
            const normalized = try routes.normalizeTld(self.allocator, prior.tld);
            defer self.allocator.free(normalized);
            prior.tld = normalized;
            const prior_tlds = try routes.cloneTlds(self.allocator, normalized, prior.tlds);
            defer {
                for (prior_tlds) |suffix| self.allocator.free(suffix);
                self.allocator.free(prior_tlds);
            }
            prior.tlds = prior_tlds;
            const previous = try std.json.Stringify.valueAlloc(self.allocator, prior, .{});
            defer self.allocator.free(previous);
            if (std.mem.eql(u8, previous, current)) return;
            if (!self.config.reconcile_profile) return error.IncompatibleProfile;
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            if ((try self.registry.list(arena.allocator())).len != 0) return error.ProfileHasRoutes;
        }
        var atomic = try dir.createFileAtomic(self.io, "zig-profile.json", .{ .permissions = .fromMode(0o600), .replace = true });
        defer atomic.deinit(self.io);
        try atomic.file.writePositionalAll(self.io, current, 0);
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
        const directory_file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
        try directory_file.sync(self.io);
    }
    fn allowCertificateHost(context: ?*anyopaque, host: []const u8) bool {
        const self: *Runtime = @ptrCast(@alignCast(context.?));
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        return (self.registry.resolve(arena.allocator(), host) catch return false) != null;
    }
    fn sni(ssl: ?*c.SSL, alert: [*c]c_int, argument: ?*anyopaque) callconv(.c) c_int {
        const self: *Runtime = @ptrCast(@alignCast(argument.?));
        const name = c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name);
        if (name == null) {
            alert.* = c.SSL_AD_UNRECOGNIZED_NAME;
            return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const host = routes.normalizeAnyAuthority(a, std.mem.span(name), self.config.profile.tld, self.config.profile.tlds) catch return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        const registered = self.registry.resolve(a, host) catch return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        if (registered == null) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        if (self.authority == null) {
            const cert = c.SSL_CTX_get0_certificate(self.base_ctx.?);
            if (c.X509_check_host(cert, host.ptr, host.len, 0, null) != 1) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
            return c.SSL_TLSEXT_ERR_OK;
        }
        self.cert_mutex.lockUncancelable(self.io);
        defer self.cert_mutex.unlock(self.io);
        if (self.certificates.get(host)) |cached| {
            if (self.authority.?.contextNeedsRenewal(cached, host)) {
                if (self.certificates.fetchRemove(host)) |removed| {
                    self.allocator.free(removed.key);
                    c.SSL_CTX_free(removed.value);
                }
            }
        }
        const ctx = self.certificates.get(host) orelse blk: {
            if (self.certificates.count() >= 1024) {
                var it = self.certificates.iterator();
                const entry = it.next().?;
                const key = entry.key_ptr.*;
                const old = entry.value_ptr.*;
                _ = self.certificates.remove(key);
                self.allocator.free(key);
                c.SSL_CTX_free(old);
            }
            const context = self.authority.?.serverContext(host) catch return c.SSL_TLSEXT_ERR_ALERT_FATAL;
            c.SSL_CTX_set_alpn_select_cb(context, alpn, null);
            const key = self.allocator.dupe(u8, host) catch {
                c.SSL_CTX_free(context);
                return c.SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            self.certificates.put(self.allocator, key, context) catch {
                self.allocator.free(key);
                c.SSL_CTX_free(context);
                return c.SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            break :blk context;
        };
        if (c.SSL_set_SSL_CTX(ssl, ctx) == null) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        return c.SSL_TLSEXT_ERR_OK;
    }
    fn alpn(_: ?*c.SSL, out: [*c][*c]const u8, outlen: [*c]u8, input: [*c]const u8, inputlen: c_uint, _: ?*anyopaque) callconv(.c) c_int {
        const protocols = "\x02h2\x08http/1.1";
        if (c.SSL_select_next_proto(@ptrCast(out), outlen, protocols, protocols.len, input, inputlen) != c.OPENSSL_NPN_NEGOTIATED) return c.SSL_TLSEXT_ERR_NOACK;
        return c.SSL_TLSEXT_ERR_OK;
    }
};
fn writeResponse(a: std.mem.Allocator, stream: net.Stream, response: protocol.Response) !void {
    const data = try std.json.Stringify.valueAlloc(a, response, .{ .emit_null_optional_fields = false });
    try stream.writeAll(data);
    try stream.writeAll("\n");
}
fn ipHost(a: std.mem.Allocator, address: std.Io.net.IpAddress) ![]u8 {
    return switch (address) {
        .ip4 => |ip| std.fmt.allocPrint(a, "{d}.{d}.{d}.{d}", .{ ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3] }),
        .ip6 => |ip| blk: {
            const value = try std.fmt.allocPrint(a, "{f}", .{ip});
            defer a.free(value);
            const end = std.mem.indexOfScalar(u8, value, ']').?;
            break :blk a.dupe(u8, value[1..end]);
        },
    };
}
fn remoteIP(a: std.mem.Allocator, peer: c.struct_sockaddr_storage) ![]const u8 {
    var buffer: [c.INET6_ADDRSTRLEN]u8 = undefined;
    const ptr: *const anyopaque = if (peer.ss_family == c.AF_INET) &@as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(&peer))).sin_addr else &@as(*const c.struct_sockaddr_in6, @ptrCast(@alignCast(&peer))).sin6_addr;
    if (c.inet_ntop(peer.ss_family, ptr, &buffer, buffer.len) == null) return error.InvalidIP;
    return a.dupe(u8, std.mem.sliceTo(&buffer, 0));
}
