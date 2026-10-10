//! The small native socket boundary shared by management, TLS and HTTP/2.
const file_stat = @import("file_stat.zig");
const std = @import("std");
pub const c = @import("native");
pub fn errno() c_int {
    return @backingInt(std.c.errno(@as(c_int, -1)));
}
pub fn close(fd: c_int) void {
    _ = c.close(fd);
}
pub fn configure(fd: c_int, seconds: c_long) void {
    const tv: c.struct_timeval = .{ .tv_sec = seconds, .tv_usec = 0 };
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(@TypeOf(tv)));
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(@TypeOf(tv)));
    _ = c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC);
    // Small HTTP/2 WINDOW_UPDATE frames must not wait for Nagle/delayed ACK.
    // This option is inapplicable to Unix sockets and can be ignored there.
    const no_delay: c_int = 1;
    _ = c.setsockopt(fd, c.IPPROTO_TCP, c.TCP_NODELAY, &no_delay, @sizeOf(c_int));
    if (@import("builtin").os.tag == .macos) {
        const yes: c_int = 1;
        _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_NOSIGPIPE, &yes, @sizeOf(c_int));
    }
}
pub fn unixAddress(path: []const u8) !c.struct_sockaddr_un {
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidSocketPath;
    var address: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    if (path.len >= address.sun_path.len) return error.SocketPathTooLong;
    address.sun_family = c.AF_UNIX;
    @memcpy(address.sun_path[0..path.len], path);
    return address;
}
pub fn listenUnix(a: std.mem.Allocator, path: []const u8) !c_int {
    var address = try unixAddress(path);
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    var st: c.struct_stat = undefined;
    if (file_stat.lstat(z, &st) == 0) return error.SocketAlreadyExists;
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer close(fd);
    configure(fd, 5);
    if (c.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address))) != 0) return error.BindFailed;
    errdefer {
        _ = c.unlink(z);
    }
    if (c.chmod(z, 0o660) != 0 or c.listen(fd, 64) != 0) return error.ListenFailed;
    return fd;
}
pub fn connectUnix(a: std.mem.Allocator, path: []const u8) !c_int {
    var address = try unixAddress(path);
    const z = try a.dupeSentinel(u8, path, 0);
    defer a.free(z);
    var st: c.struct_stat = undefined;
    if (file_stat.lstat(z, &st) != 0) return if (errno() == c.ENOENT) error.FileNotFound else error.UnsafeSocket;
    if (st.st_mode & c.S_IFMT != c.S_IFSOCK or st.st_mode & 0o002 != 0 or (st.st_uid != 0 and st.st_uid != c.geteuid())) return error.UnsafeSocket;
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer close(fd);
    configure(fd, 5);
    if (c.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address))) != 0) return error.ConnectFailed;
    return fd;
}
pub fn tcp(a: std.mem.Allocator, host: []const u8, port: u16, listening: bool) !c_int {
    const z = try a.dupeSentinel(u8, host, 0);
    defer a.free(z);
    const ipv6 = std.mem.indexOfScalar(u8, host, ':') != null;
    const family: c_int = if (ipv6) c.AF_INET6 else c.AF_INET;
    const fd = c.socket(family, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer close(fd);
    configure(fd, 30);
    var v4: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var v6: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
    const addr: *const c.struct_sockaddr = if (ipv6) blk: {
        v6.sin6_family = c.AF_INET6;
        v6.sin6_port = std.mem.nativeToBig(u16, port);
        if (c.inet_pton(family, z, &v6.sin6_addr) != 1) return error.InvalidIP;
        break :blk @ptrCast(&v6);
    } else blk: {
        v4.sin_family = c.AF_INET;
        v4.sin_port = std.mem.nativeToBig(u16, port);
        if (c.inet_pton(family, z, &v4.sin_addr) != 1) return error.InvalidIP;
        break :blk @ptrCast(&v4);
    };
    const len: c.socklen_t = if (ipv6) @sizeOf(@TypeOf(v6)) else @sizeOf(@TypeOf(v4));
    if (listening) {
        const yes: c_int = 1;
        _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &yes, @sizeOf(c_int));
        if (c.bind(fd, addr, len) != 0 or c.listen(fd, 128) != 0) return error.BindFailed;
    } else if (c.connect(fd, addr, len) != 0) return error.ConnectFailed;
    return fd;
}
pub const Stream = struct {
    fd: c_int,
    ssl: ?*c.SSL = null,
    pub fn read(self: Stream, bytes: []u8) !usize {
        const n = if (self.ssl) |ssl| c.SSL_read(ssl, bytes.ptr, @intCast(@min(bytes.len, std.math.maxInt(c_int)))) else c.recv(self.fd, bytes.ptr, bytes.len, 0);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
    /// Like `read`, but leaves the bytes queued for the next read.
    pub fn peek(self: Stream, bytes: []u8) !usize {
        const n = if (self.ssl) |ssl| c.SSL_peek(ssl, bytes.ptr, @intCast(@min(bytes.len, std.math.maxInt(c_int)))) else c.recv(self.fd, bytes.ptr, bytes.len, c.MSG_PEEK);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
    pub fn writeAll(self: Stream, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const part = bytes[offset..];
            const n = if (self.ssl) |ssl| c.SSL_write(ssl, part.ptr, @intCast(@min(part.len, std.math.maxInt(c_int)))) else c.send(self.fd, part.ptr, part.len, if (@import("builtin").os.tag == .linux) c.MSG_NOSIGNAL else 0);
            if (n <= 0) return error.WriteFailed;
            offset += @intCast(n);
        }
    }
    pub fn deinit(self: Stream) void {
        if (self.ssl) |ssl| {
            // Send close_notify once, without waiting for the peer's reply.
            // EOF-framed HTTP responses require a clean TLS end.
            const flags = c.fcntl(self.fd, c.F_GETFL);
            if (flags >= 0) _ = c.fcntl(self.fd, c.F_SETFL, flags | c.O_NONBLOCK);
            if (c.SSL_is_init_finished(ssl) == 1 and c.SSL_get_shutdown(ssl) & c.SSL_SENT_SHUTDOWN == 0) _ = c.SSL_shutdown(ssl);
            c.SSL_free(ssl);
        }
        close(self.fd);
    }
};
pub fn readFrame(a: std.mem.Allocator, stream: Stream, limit: usize) ![]u8 {
    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(a);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        if (data.items.len + n > limit) return error.FrameTooLarge;
        try data.appendSlice(a, buf[0..n]);
    }
    if (data.items.len == 0) return error.EmptyFrame;
    return data.toOwnedSlice(a);
}
