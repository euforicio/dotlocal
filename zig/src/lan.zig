const std = @import("std");
const apple = @import("applecontainer.zig");
const c = @import("native");
const net = @import("net.zig");
const routes = @import("routes.zig");
const pki = @import("pki.zig");
const proxy = @import("proxy.zig");
const http2 = @import("http2.zig");
const profile = @import("profile.zig");
const mdns = @import("mdns.zig");
const A = std.mem.Allocator;
const process_identity = @import("process.zig");
pub const Address = struct {
    host: []u8,
    interface: []u8,
    index: u32,
    pub fn deinit(self: Address, a: A) void {
        a.free(self.host);
        a.free(self.interface);
    }
};
/// Eligible interfaces are up, multicast capable, and neither loopback nor point-to-point.
pub fn eligible(a: A, io: std.Io) ![]Address {
    _ = io;
    var head: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&head) != 0) return error.InterfaceDiscoveryFailed;
    defer c.freeifaddrs(head);
    var result: std.ArrayList(Address) = .empty;
    errdefer {
        for (result.items) |v| v.deinit(a);
        result.deinit(a);
    }
    var cursor = head;
    while (cursor) |entry| : (cursor = entry.ifa_next) {
        if (entry.ifa_addr == null) continue;
        const flags = entry.ifa_flags;
        if ((flags & (c.IFF_UP | c.IFF_MULTICAST)) != (c.IFF_UP | c.IFF_MULTICAST) or (flags & (c.IFF_LOOPBACK | c.IFF_POINTOPOINT)) != 0) continue;
        var buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
        const family = entry.ifa_addr.*.sa_family;
        const ptr: *const anyopaque = switch (family) {
            c.AF_INET => &@as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(entry.ifa_addr))).sin_addr,
            c.AF_INET6 => blk: {
                const addr: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(entry.ifa_addr));
                if (addr.sin6_scope_id != 0) continue;
                break :blk &addr.sin6_addr;
            },
            else => continue,
        };
        if (c.inet_ntop(family, ptr, &buf, buf.len) == null) continue;
        const host = std.mem.sliceTo(&buf, 0);
        if (!apple.privateAddress(host)) continue;
        const index = c.if_nametoindex(entry.ifa_name);
        if (index == 0) continue;
        const ip = try a.dupe(u8, host);
        errdefer a.free(ip);
        const name = try a.dupe(u8, std.mem.span(entry.ifa_name));
        errdefer a.free(name);
        try result.append(a, .{ .host = ip, .interface = name, .index = index });
    }
    std.mem.sort(Address, result.items, {}, struct {
        fn less(_: void, x: Address, y: Address) bool {
            if (x.index != y.index) return x.index < y.index;
            const x6 = std.mem.findScalar(u8, x.host, ':') != null;
            const y6 = std.mem.findScalar(u8, y.host, ':') != null;
            if (x6 != y6) return !x6;
            return std.mem.order(u8, x.host, y.host) == .lt;
        }
    }.less);
    return result.toOwnedSlice(a);
}
pub fn select(a: A, io: std.Io, pinned: ?[]const u8) !Address {
    if (pinned) |p| if (!apple.privateAddress(p)) return error.InvalidLANAddress;
    const addresses = try eligible(a, io);
    defer {
        for (addresses) |v| v.deinit(a);
        a.free(addresses);
    }
    for (addresses) |v| {
        if (pinned) |p| if (!std.mem.eql(u8, p, v.host)) continue;
        const host = try a.dupe(u8, v.host);
        errdefer a.free(host);
        return .{ .host = host, .interface = try a.dupe(u8, v.interface), .index = v.index };
    }
    return error.NoEligibleLANAddress;
}
const Bound = struct { fd: c_int, port: u16 };
fn bind(a: A, host: []const u8, port: u16) !Bound {
    const fd = try net.tcp(a, host, port, true);
    errdefer net.close(fd);
    // A connection reset between poll and accept must not block run() past stop.
    const flags = c.fcntl(fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK) < 0) return error.NonblockingFailed;
    var sock: c.struct_sockaddr_storage = undefined;
    var len: c.socklen_t = @sizeOf(@TypeOf(sock));
    if (c.getsockname(fd, @ptrCast(&sock), &len) != 0) return error.ListenerInspectionFailed;
    const actual = std.mem.bigToNative(u16, if (sock.ss_family == c.AF_INET) @as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(&sock))).sin_port else @as(*const c.struct_sockaddr_in6, @ptrCast(@alignCast(&sock))).sin6_port);
    return .{ .fd = fd, .port = actual };
}
pub const Session = struct {
    allocator: A,
    io: std.Io,
    address: Address,
    name: []u8,
    port: u16,
    url: []u8,
    pinned: ?[]u8 = null,
    /// Called after withdrawal and after replacement readiness. Failure closes the replacement.
    on_changed: ?*const fn (*Session, ?*anyopaque) anyerror!void = null,
    change_context: ?*anyopaque = null,
    ca_path: ?[]u8 = null,
    authority: ?pki.Authority = null,
    tls: ?*c.SSL_CTX = null,
    listener: c_int = -1,
    publisher: ?mdns.Publisher = null,
    table: routes.Table,
    config: profile.Config,
    tasks: std.Io.Group = .init,
    mutex: std.Io.Mutex = .init,
    connections: [128]c_int = @splat(-1),
    cancels: [128]proxy.Cancel = @splat(.{}),

    pub fn init(a: A, io: std.Io, state_dir: []const u8, app_host: []const u8, app_port: u16, name: []const u8, pinned: ?[]const u8, https: bool) !*Session {
        try routes.validateUpstream("http", app_host, app_port);
        const address = try select(a, io, pinned);
        errdefer address.deinit(a);
        const pin: ?[]u8 = if (pinned) |value| try a.dupe(u8, value) else null;
        errdefer if (pin) |value| a.free(value);
        const host = try routes.normalizeName(a, name, ".local");
        errdefer a.free(host);
        var table = try routes.Table.init(a, ".local", false);
        errdefer table.deinit();
        try table.set(.{ .name = host, .scheme = "http", .host = app_host, .port = app_port });
        const bound = try bind(a, address.host, 0);
        errdefer net.close(bound.fd);
        const listen = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{bound.port});
        errdefer a.free(listen);
        const config: profile.Config = .{ .scheme = if (https) "https" else "http", .listen = listen, .tld = ".local" };
        const url = try config.publicUrl(a, host);
        errdefer a.free(url);
        const self = try a.create(Session);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .io = io, .address = address, .pinned = pin, .name = host, .port = bound.port, .url = url, .listener = bound.fd, .table = table, .config = config };
        // Function-scoped so a later advertisement failure also releases TLS state.
        errdefer {
            if (self.tls) |ctx| c.SSL_CTX_free(ctx);
            if (self.ca_path) |path| a.free(path);
            if (self.authority) |*authority| authority.deinit();
        }
        if (https) {
            const directory = try std.fmt.allocPrint(a, "{s}/lan-pki", .{state_dir});
            defer a.free(directory);
            self.authority = try pki.Authority.initWithOptions(a, io, directory, .{ .allowed_suffix = ".local", .root_common_name = "dotlocal LAN Root CA", .max_leaf_certificates = 256, .allow_host = allowCertificateHost, .allow_context = self });
            self.ca_path = try std.fmt.allocPrint(a, "{s}/ca.pem", .{directory});
            self.tls = try self.authority.?.serverContext(host);
            _ = c.SSL_CTX_callback_ctrl(self.tls.?, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&sni));
            _ = c.SSL_CTX_ctrl(self.tls.?, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, self);
            c.SSL_CTX_set_alpn_select_cb(self.tls.?, alpn, null);
        }
        self.publisher = try mdns.start(a, io, .{ .host = host, .address = address.host, .port = bound.port, .scheme = config.scheme });
        return self;
    }
    pub fn run(self: *Session, stop: *const std.atomic.Value(bool)) !void {
        var next_refresh = std.Io.Clock.awake.now(self.io).nanoseconds + 5 * std.time.ns_per_s;
        while (!stop.load(.acquire)) {
            const now = std.Io.Clock.awake.now(self.io).nanoseconds;
            if (now >= next_refresh) {
                _ = try self.refresh();
                next_refresh = now + 5 * std.time.ns_per_s;
            }
            var poll: c.struct_pollfd = .{ .fd = self.listener, .events = c.POLLIN, .revents = 0 };
            if (c.poll(&poll, 1, 200) <= 0 or (poll.revents & c.POLLIN) == 0) continue;
            var peer: c.struct_sockaddr_storage = undefined;
            var len: c.socklen_t = @sizeOf(@TypeOf(peer));
            const fd = c.accept(self.listener, @ptrCast(&peer), &len);
            if (fd < 0) continue;
            // BSD accept inherits O_NONBLOCK; connection I/O relies on blocking timeouts.
            const flags = c.fcntl(fd, c.F_GETFL);
            if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags & ~@as(c_int, c.O_NONBLOCK)) < 0) {
                net.close(fd);
                continue;
            }
            net.configure(fd, 30);
            self.mutex.lockUncancelable(self.io);
            const slot = std.mem.findScalar(c_int, &self.connections, -1);
            if (slot) |index| {
                self.cancels[index] = .{};
                self.connections[index] = fd;
            }
            self.mutex.unlock(self.io);
            if (slot == null) {
                net.close(fd);
                continue;
            }
            self.tasks.concurrent(self.io, connection, .{ self, fd, slot.?, peer }) catch |err| {
                self.mutex.lockUncancelable(self.io);
                self.connections[slot.?] = -1;
                self.mutex.unlock(self.io);
                net.close(fd);
                return err;
            };
        }
    }
    /// Refresh is serialized with run; callers can invoke it while run is stopped.
    pub fn refresh(self: *Session) !bool {
        const next = self.nextAddress() catch |err| {
            const changed = self.listener >= 0 or self.publisher != null;
            if (changed) {
                self.withdraw();
                try self.notify();
            }
            if (self.pinned != null) return error.LANAddressWithdrawn;
            if (err == error.NoEligibleLANAddress) return changed;
            return err;
        };
        var committed = false;
        defer if (!committed) next.deinit(self.allocator);
        const publisher_live = if (self.publisher) |publisher| !publisher.closed and publisher.child.id != null and blk: {
            _ = process_identity.inspect(publisher.child.id.?) catch break :blk false;
            break :blk true;
        } else false;
        if (self.listener >= 0 and publisher_live and self.address.index == next.index and std.mem.eql(u8, self.address.host, next.host)) return false;
        self.withdraw();
        try self.notify(); // Persist withdrawal before creating the next advertising child.
        const bound = bind(self.allocator, next.host, self.port) catch |err| switch (err) {
            error.BindFailed => try bind(self.allocator, next.host, 0),
            else => return err,
        };
        errdefer if (!committed) net.close(bound.fd);
        const listen = try std.fmt.allocPrint(self.allocator, "127.0.0.1:{d}", .{bound.port});
        errdefer if (!committed) self.allocator.free(listen);
        var config = self.config;
        config.listen = listen;
        const url = try config.publicUrl(self.allocator, self.name);
        errdefer if (!committed) self.allocator.free(url);
        var publisher = try mdns.start(self.allocator, self.io, .{ .host = self.name, .address = next.host, .port = bound.port, .scheme = config.scheme });
        errdefer if (!committed) publisher.close(self.io);
        self.address.deinit(self.allocator);
        self.allocator.free(self.config.listen);
        self.allocator.free(self.url);
        self.address = next;
        self.port = bound.port;
        self.config = config;
        self.url = url;
        self.listener = bound.fd;
        self.publisher = publisher;
        committed = true;
        self.notify() catch |err| {
            self.withdraw();
            return err;
        };
        return true;
    }
    fn nextAddress(self: *Session) !Address {
        if (self.pinned) |pin| if (!apple.privateAddress(pin)) return error.InvalidLANAddress;
        const addresses = try eligible(self.allocator, self.io);
        defer {
            for (addresses) |value| value.deinit(self.allocator);
            self.allocator.free(addresses);
        }
        var chosen: ?Address = null;
        for (addresses) |value| {
            const wanted = if (self.pinned) |pin| std.mem.eql(u8, pin, value.host) else value.index == self.address.index and std.mem.eql(u8, value.host, self.address.host);
            if (wanted) {
                chosen = value;
                break;
            }
        }
        if (chosen == null) {
            if (self.pinned != null or addresses.len == 0) return error.NoEligibleLANAddress;
            chosen = addresses[0];
        }
        const value = chosen.?;
        const host = try self.allocator.dupe(u8, value.host);
        errdefer self.allocator.free(host);
        return .{ .host = host, .interface = try self.allocator.dupe(u8, value.interface), .index = value.index };
    }
    fn notify(self: *Session) !void {
        if (self.on_changed) |callback| try callback(self, self.change_context);
    }
    fn withdraw(self: *Session) void {
        if (self.publisher) |*publisher| publisher.close(self.io);
        self.publisher = null;
        if (self.listener >= 0) {
            _ = c.shutdown(self.listener, c.SHUT_RDWR);
            net.close(self.listener);
            self.listener = -1;
        }
        self.mutex.lockUncancelable(self.io);
        for (self.connections, 0..) |fd, index| if (fd >= 0) {
            self.cancels[index].stop();
            _ = c.shutdown(fd, c.SHUT_RDWR);
        };
        self.mutex.unlock(self.io);
        self.tasks.await(self.io) catch {};
    }
    fn connection(self: *Session, fd: c_int, slot: usize, peer: c.struct_sockaddr_storage) void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var stream: net.Stream = .{ .fd = fd };
        defer {
            self.mutex.lockUncancelable(self.io);
            self.connections[slot] = -1;
            stream.deinit();
            self.mutex.unlock(self.io);
        }
        self.mutex.lockUncancelable(self.io);
        if (self.tls) |ctx| {
            if (self.authority.?.contextNeedsRenewal(ctx, self.name)) {
                const renewed = self.authority.?.serverContext(self.name) catch {
                    self.mutex.unlock(self.io);
                    return;
                };
                _ = c.SSL_CTX_callback_ctrl(renewed, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&sni));
                _ = c.SSL_CTX_ctrl(renewed, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, self);
                c.SSL_CTX_set_alpn_select_cb(renewed, alpn, null);
                self.tls = renewed;
                c.SSL_CTX_free(ctx);
            }
            const ssl = c.SSL_new(self.tls.?) orelse {
                self.mutex.unlock(self.io);
                return;
            };
            stream.ssl = ssl;
            self.mutex.unlock(self.io);
            if (c.SSL_set_fd(ssl, fd) != 1 or c.SSL_accept(ssl) != 1) return;
        } else self.mutex.unlock(self.io);
        var buffer: [c.INET6_ADDRSTRLEN]u8 = undefined;
        const ptr: *const anyopaque = if (peer.ss_family == c.AF_INET) &@as(*const c.struct_sockaddr_in, @ptrCast(@alignCast(&peer))).sin_addr else &@as(*const c.struct_sockaddr_in6, @ptrCast(@alignCast(&peer))).sin6_addr;
        if (c.inet_ntop(peer.ss_family, ptr, &buffer, buffer.len) == null) return;
        if (stream.ssl) |ssl| {
            var selected: [*c]const u8 = null;
            var selected_len: c_uint = 0;
            c.SSL_get0_alpn_selected(ssl, &selected, &selected_len);
            if (selected_len == 2 and std.mem.eql(u8, selected[0..selected_len], "h2")) {
                http2.serve(self.allocator, self.io, stream, &self.table, self.config, null, std.mem.sliceTo(&buffer, 0)) catch {};
                return;
            }
        }
        proxy.serveWatched(a, stream, &self.table, self.config, null, std.mem.sliceTo(&buffer, 0), false, &self.cancels[slot]) catch {};
    }
    fn allowCertificateHost(context: ?*anyopaque, host: []const u8) bool {
        const self: *Session = @ptrCast(@alignCast(context.?));
        return std.mem.eql(u8, host, self.name) and self.table.records.contains(host);
    }
    fn sni(ssl: ?*c.SSL, alert: [*c]c_int, argument: ?*anyopaque) callconv(.c) c_int {
        const self: *Session = @ptrCast(@alignCast(argument.?));
        const name = c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name);
        if (name == null or !std.ascii.eqlIgnoreCase(std.mem.span(name), self.name)) {
            alert.* = c.SSL_AD_UNRECOGNIZED_NAME;
            return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        return c.SSL_TLSEXT_ERR_OK;
    }
    fn alpn(_: ?*c.SSL, out: [*c][*c]const u8, outlen: [*c]u8, input: [*c]const u8, inputlen: c_uint, _: ?*anyopaque) callconv(.c) c_int {
        const protocols = "\x02h2\x08http/1.1";
        if (c.SSL_select_next_proto(@ptrCast(out), outlen, protocols, protocols.len, input, inputlen) != c.OPENSSL_NPN_NEGOTIATED) return c.SSL_TLSEXT_ERR_NOACK;
        return c.SSL_TLSEXT_ERR_OK;
    }
    pub fn deinit(self: *Session) void {
        self.withdraw();
        if (self.tls) |ctx| c.SSL_CTX_free(ctx);
        if (self.authority) |*authority| authority.deinit();
        if (self.ca_path) |path| self.allocator.free(path);
        if (self.pinned) |pin| self.allocator.free(pin);
        self.address.deinit(self.allocator);
        self.table.deinit();
        self.allocator.free(self.config.listen);
        self.allocator.free(self.name);
        self.allocator.free(self.url);
        self.allocator.destroy(self);
    }
};
