const std = @import("std");
const routes = registry.routes;
const protocol = registry.protocol;
const profile = registry.profile;
const registry = @import("../src/registry.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;
fn route(name: []const u8, port: u16) protocol.Route {
    return .{ .name = name, .host = "127.0.0.1", .port = port };
}
fn freeRoutes(entries: []protocol.Route) void {
    for (entries) |entry| entry.deinit(allocator);
    allocator.free(entries);
}

test "names authorities and private upstream boundary" {
    const name = try routes.normalizeName(allocator, " App ", ".local.");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("app.local", name);
    const authority = try routes.normalizeAuthority(allocator, "API.App.local.:443", ".local");
    defer allocator.free(authority);
    try std.testing.expectEqualStrings("api.app.local", authority);
    try std.testing.expectError(error.InvalidHost, routes.normalizeAuthority(allocator, "app.local.evil", ".local"));
    try std.testing.expectError(error.InvalidHost, routes.normalizeAuthority(allocator, "app.local:0", ".local"));
    try std.testing.expectError(error.InvalidHost, routes.normalizeName(allocator, "bad/name", ".local"));
    try std.testing.expectError(error.InvalidTld, routes.normalizeTld(allocator, ".123"));
    try std.testing.expectError(error.InvalidUpstream, routes.validateUpstream("http", "8.8.8.8", 80));
    try std.testing.expectError(error.InvalidUpstream, routes.validateUpstream("http", "0.0.0.0", 80));
    try std.testing.expectError(error.InvalidUpstream, routes.validateUpstream("http", "169.254.1.1", 80));
    try routes.validateUpstream("https", "10.1.2.3", 443);
    try routes.validateUpstream("http", "::1", 80);
    try route("ipv6.local", 3000).validate(allocator, ".local");
    var ipv6 = route("ipv6.local", 3000);
    ipv6.host = "::1";
    try ipv6.validate(allocator, ".local");
}

test "wildcard fallback picks longest registered parent and exact wins" {
    var table = try routes.Table.init(allocator, ".test", true);
    defer table.deinit();
    try table.set(route("app.test", 3000));
    try table.set(route("api.app.test", 3001));
    const child = (try table.resolve(allocator, "x.api.app.test:443")).?;
    defer child.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 3001), child.port);
    try std.testing.expect((try table.resolve(allocator, "unknown.test")) == null);
    try std.testing.expectError(error.InvalidHost, table.resolve(allocator, "x.other"));
}

test "protocol version ownership and mutation match validation" {
    const request: protocol.Request = .{ .id = "test-1", .operation = "add", .route = route("app.local", 3000), .match = "absent" };
    try request.validate(allocator);
    const encoded = try std.json.Stringify.valueAlloc(allocator, request, .{});
    defer allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(protocol.Request, allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u32, 2), parsed.value.version);
    var invalid = request;
    invalid.version = 1;
    try std.testing.expectError(error.UnsupportedVersion, invalid.validate(allocator));
    invalid = request;
    invalid.match = "owner";
    try std.testing.expectError(error.InvalidMatch, invalid.validate(allocator));
    invalid = request;
    invalid.route.?.owner = .{ .kind = "process", .pid = 4, .process_start = 20 };
    invalid.route.?.host = "10.0.0.1";
    try std.testing.expectError(error.InvalidOwnerAddress, invalid.validate(allocator));
    const owner: protocol.Owner = .{ .kind = "process", .pid = 4 };
    try std.testing.expectError(error.InvalidOwner, owner.validateExpected());
}

test "profile enforces loopback listener and public url" {
    const config: profile.Config = .{ .scheme = "http", .listen = "127.0.0.1:8080", .tld = ".test" };
    const url = try config.publicUrl(allocator, "App");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("http://app.test:8080", url);
    const authority_url = try config.publicUrl(allocator, "app.test:9999");
    defer allocator.free(authority_url);
    try std.testing.expectEqualStrings("http://app.test:8080", authority_url);
    try std.testing.expectError(error.InvalidListener, (profile.Config{ .listen = "0.0.0.0:443" }).validate(allocator));
    try (profile.Config{ .wildcard = true }).validate(allocator);
}

test "durable registry restart sorted records CAS and permissions" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var store = try registry.Registry.init(allocator, io, path, .{});
    const added = (try store.mutate(.{ .id = "add", .operation = "add", .route = route("app.local", 3000), .match = "absent" })).?;
    added.deinit(allocator);
    try std.testing.expectError(error.RouteConflict, store.mutate(.{ .id = "again", .operation = "add", .route = route("app.local", 3001), .match = "absent" }));
    const changed = (try store.mutate(.{ .id = "replace", .operation = "add", .route = route("app.local", 3001), .match = "owner", .expected_owner = .{} })).?;
    changed.deinit(allocator);
    store.deinit();
    store = try registry.Registry.init(allocator, io, path, .{});
    defer store.deinit();
    const resolved = (try store.resolve(allocator, "APP.local:443")).?;
    defer resolved.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 3001), resolved.port);
    const entries = try store.list(allocator);
    defer freeRoutes(entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    const removed = (try store.mutate(.{ .id = "remove", .operation = "remove", .name = "app.local", .match = "owner", .expected_owner = .{} })).?;
    removed.deinit(allocator);
    try std.testing.expect((try store.resolve(allocator, "app.local")) == null);
    const stat = try tmp.dir.statFile(io, "routes.json", .{ .follow_symlinks = false });
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);
}

test "registry rejects unsafe directory permissions and symlink state" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    try tmp.dir.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeStateDirectory, registry.Registry.init(allocator, io, path, .{}));
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    try tmp.dir.symLink(io, "/etc/passwd", "routes.json", .{});
    if (registry.Registry.init(allocator, io, path, .{})) |value| {
        var opened = value;
        opened.deinit();
        return error.AcceptedSymlink;
    } else |_| {}
}

test "persisted dynamic owner is inactive until live identity validation" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var store = try registry.Registry.init(allocator, io, path, .{});
    var dynamic = route("dynamic.local", 3000);
    dynamic.owner = .{ .kind = "process", .pid = 123, .process_start = 456 };
    const added = (try store.mutate(.{ .id = "add", .operation = "add", .route = dynamic, .match = "absent" })).?;
    added.deinit(allocator);
    store.deinit();
    store = try registry.Registry.init(allocator, io, path, .{});
    defer store.deinit();
    try std.testing.expect((try store.resolve(allocator, dynamic.name)) == null);
    const persisted = try store.list(allocator);
    defer freeRoutes(persisted);
    try std.testing.expectEqual(@as(usize, 1), persisted.len);
    try store.setActive(dynamic.name, true);
    const resolved = (try store.resolve(allocator, dynamic.name)).?;
    defer resolved.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 456), resolved.owner.process_start);
    var stale_owner = dynamic.owner;
    stale_owner.process_start = 455;
    try std.testing.expectError(error.RouteConflict, store.mutate(.{ .id = "remove", .operation = "remove", .name = dynamic.name, .match = "owner", .expected_owner = stale_owner }));
    try store.setActive(dynamic.name, false);
    try std.testing.expect((try store.resolve(allocator, dynamic.name)) == null);
}

test "unsafe persistence file blocks mutation without changing visible route" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var store = try registry.Registry.init(allocator, io, path, .{});
    defer store.deinit();
    const added = (try store.mutate(.{ .id = "add", .operation = "add", .route = route("app.local", 3000), .match = "absent" })).?;
    added.deinit(allocator);
    const file = try tmp.dir.openFile(io, "routes.json", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeStateFile, store.mutate(.{ .id = "replace", .operation = "add", .route = route("app.local", 3001), .match = "any" }));
    const resolved = (try store.resolve(allocator, "app.local")).?;
    defer resolved.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 3000), resolved.port);
}

test "registry rejects unknown fields trailing JSON and unsupported state version" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const values = [_][]const u8{ "{\"version\":1,\"routes\":[],\"unknown\":true}", "{\"version\":1,\"routes\":[]} {}", "{\"version\":2,\"routes\":[]}", "{\"routes\":[]}" };
    for (values) |json| {
        const file = try tmp.dir.createFile(io, "routes.json", .{ .permissions = .fromMode(0o600) });
        try file.writePositionalAll(io, json, 0);
        file.close(io);
        if (registry.Registry.init(allocator, io, path, .{})) |value| {
            var opened = value;
            opened.deinit();
            return error.AcceptedInvalidState;
        } else |_| {}
    }
}

test "wire requests require explicit version route scheme and owner metadata" {
    const complete = "{\"version\":2,\"id\":\"wire\",\"operation\":\"add\",\"match\":\"absent\",\"route\":{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000,\"owner\":{\"kind\":\"static\",\"refresh\":\"never\"}}}";
    const parsed = try protocol.parseRequest(allocator, complete);
    defer parsed.deinit();
    const omissions = [_][]const u8{ "\"version\":2,", "\"scheme\":\"http\",", "\"kind\":\"static\",", ",\"refresh\":\"never\"" };
    for (omissions) |omission| {
        const at = std.mem.indexOf(u8, complete, omission).?;
        const malformed = try std.fmt.allocPrint(allocator, "{s}{s}", .{ complete[0..at], complete[at + omission.len ..] });
        defer allocator.free(malformed);
        try std.testing.expectError(error.MissingField, protocol.parseRequest(allocator, malformed));
    }
    const missing_owner = "{\"version\":2,\"id\":\"wire\",\"operation\":\"add\",\"match\":\"absent\",\"route\":{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000}}";
    try std.testing.expectError(error.MissingField, protocol.parseRequest(allocator, missing_owner));
}

test "single-pass wire decoding keeps unknown, null, shape and numeric-string rules" {
    const head = "{\"version\":2,\"id\":\"wire\",\"operation\":\"add\",\"match\":\"absent\",\"route\":";
    const owner = "\"owner\":{\"kind\":\"static\",\"refresh\":\"never\"";
    const cases = [_]struct { body: []const u8, err: anyerror }{
        .{ .body = "{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000,\"extra\":1," ++ owner ++ "}}}", .err = error.UnknownField },
        .{ .body = "{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000," ++ owner ++ ",\"extra\":1}}}", .err = error.UnknownField },
        .{ .body = "{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000,\"port\":3001," ++ owner ++ "}}}", .err = error.DuplicateField },
        .{ .body = "[]}", .err = error.UnexpectedToken },
        .{ .body = "{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":3000,\"owner\":null}}", .err = error.UnexpectedToken },
    };
    for (cases) |case| {
        const bytes = try std.fmt.allocPrint(allocator, "{s}{s}", .{ head, case.body });
        defer allocator.free(bytes);
        try std.testing.expectError(case.err, protocol.parseRequest(allocator, bytes));
    }
    try std.testing.expectError(error.MissingField, protocol.parseRequest(allocator, "{\"version\":2,\"operation\":\"list\"}"));
    try std.testing.expectError(error.MissingField, protocol.parseRequest(allocator, "{\"version\":2,\"id\":\"x\",\"operation\":\"remove\",\"name\":\"app.local\",\"match\":\"owner\",\"expected_owner\":{\"kind\":\"static\"}}"));
    // std.json integer decoding accepts numeric strings; the previous two-pass decoder did too.
    const quoted = try std.fmt.allocPrint(allocator, "{s}{s}", .{ head, "{\"name\":\"app.local\",\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":\"3000\"," ++ owner ++ "}}}" });
    defer allocator.free(quoted);
    const parsed = try protocol.parseRequest(allocator, quoted);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 3000), parsed.value.route.?.port);
    try std.testing.expectError(error.UnexpectedToken, protocol.parseRequest(allocator, "{\"version\":2,\"id\":7,\"operation\":\"list\"}"));
    const client = @import("../src/client.zig");
    try std.testing.expectError(error.InvalidResponse, client.parseResponse(allocator, "{\"version\":2,\"id\":\"r\",\"ok\":true,\"routes\":[{\"name\":\"app.local\",\"host\":\"127.0.0.1\",\"port\":1," ++ owner ++ "}}]}", "r"));
}

test "route clones own one allocation released by deinit" {
    const source: protocol.Route = .{ .name = "app.local", .scheme = "https", .host = "10.0.0.2", .port = 443, .owner = .{ .kind = "container", .inspector_uid = 501, .container = "web", .network = "default", .refresh = "container-address" } };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const copy = try source.clone(failing.allocator());
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expectEqualStrings("app.local", copy.name);
    try std.testing.expectEqualStrings("10.0.0.2", copy.host);
    try std.testing.expectEqualStrings("default", copy.owner.network);
    try std.testing.expect(copy.owner.eql(source.owner));
    try std.testing.expect(copy.name.ptr != source.name.ptr);
    copy.deinit(failing.allocator());
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, source.clone(failing.allocator()));
}

test "owner-qualified activation cannot deactivate a replacement owner" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var store = try registry.Registry.init(allocator, io, path, .{});
    defer store.deinit();
    var dynamic = route("dynamic.local", 3000);
    dynamic.owner = .{ .kind = "process", .pid = 123, .process_start = 456 };
    const old_owner = dynamic.owner;
    const added = (try store.mutate(.{ .id = "add", .operation = "add", .route = dynamic, .match = "absent" })).?;
    added.deinit(allocator);
    dynamic.owner.process_start = 457;
    try store.replaceOwned(dynamic, old_owner);
    try std.testing.expectError(error.RouteConflict, store.setActiveOwned(dynamic.name, old_owner, false));
    const resolved = (try store.resolve(allocator, dynamic.name)).?;
    defer resolved.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 457), resolved.owner.process_start);
}

test "whole-table replacement is atomic and exact lookup does not fall back" {
    var table = try routes.Table.init(allocator, ".local", true);
    defer table.deinit();
    try table.set(route("app.local", 3000));
    try std.testing.expect((try table.lookup(allocator, "child.app.local")) == null);
    try std.testing.expectError(error.DuplicateRoute, table.replace(&.{ route("other.local", 3001), route("other.local", 3002) }));
    const original = (try table.lookup(allocator, "APP.local:443")).?;
    defer original.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 3000), original.port);
    try table.replace(&.{route("next.local", 3003)});
    try std.testing.expect((try table.lookup(allocator, "app.local")) == null);
    try std.testing.expect(table.remove("NEXT.local:443"));
}

test "registry has exclusive lifetime lock and releases it on close" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var first = try registry.Registry.init(allocator, io, path, .{});
    try std.testing.expectError(error.StateInUse, registry.Registry.init(allocator, io, path, .{}));
    first.deinit();
    var second = try registry.Registry.init(allocator, io, path, .{});
    second.deinit();
}

test "response decoder rejects omitted identity and malformed error envelopes" {
    const client = @import("../src/client.zig");
    const good = try client.parseResponse(allocator, "{\"version\":2,\"id\":\"r\",\"ok\":true}", "r");
    good.deinit();
    for ([_][]const u8{
        "{\"id\":\"r\",\"ok\":true}",
        "{\"version\":2,\"id\":\"x\",\"ok\":true}",
        "{\"version\":2,\"id\":\"r\",\"ok\":false}",
        "{\"version\":2,\"id\":\"r\",\"ok\":false,\"error\":{\"code\":\"\",\"message\":\"missing\"}}",
        "{\"version\":2,\"id\":\"r\",\"ok\":true,\"error\":{\"code\":\"bad\",\"message\":\"bad\"}}",
    }) |bytes| try std.testing.expectError(error.InvalidResponse, client.parseResponse(allocator, bytes, "r"));
}

test "profile load checks private real files before parsing" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    try std.testing.expect((try profile.load(allocator, io, path)) == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "zig-profile.json", .data = "{\"scheme\":\"http\",\"listen\":\"127.0.0.1:8080\",\"tld\":\".test\"}" });
    const private_profile = try tmp.dir.openFile(io, "zig-profile.json", .{});
    try private_profile.setPermissions(io, .fromMode(0o600));
    private_profile.close(io);
    const loaded = (try profile.load(allocator, io, path)).?;
    defer loaded.deinit();
    try std.testing.expectEqualStrings(".test", loaded.value.tld);
    const file = try tmp.dir.openFile(io, "zig-profile.json", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    if (profile.load(allocator, io, path)) |value| {
        if (value) |parsed| parsed.deinit();
        return error.AcceptedUnsafeProfile;
    } else |_| {}
    try tmp.dir.deleteFile(io, "zig-profile.json");
    try tmp.dir.symLink(io, "/etc/passwd", "zig-profile.json", .{});
    if (profile.load(allocator, io, path)) |value| {
        if (value) |parsed| parsed.deinit();
        return error.AcceptedSymlinkProfile;
    } else |_| {}
    try std.testing.expectError(error.InvalidCertificate, (profile.Config{ .cert = "/private/tmp/../key", .key = "/private/tmp/key" }).validate(allocator));
}

test "standard URLs multi-label names multiple namespaces and registered wildcard" {
    const https = try (profile.Config{}).publicUrl(allocator, "api.myapp");
    defer allocator.free(https);
    try std.testing.expectEqualStrings("https://api.myapp.local", https);
    const http = try (profile.Config{ .scheme = "http", .listen = "127.0.0.1:80" }).publicUrl(allocator, "demo");
    defer allocator.free(http);
    try std.testing.expectEqualStrings("http://demo.local", http);
    const config: profile.Config = .{ .tld = ".local", .tlds = &.{ ".local", ".test", ".dev.example.com" }, .wildcard = true };
    try config.validate(allocator);
    var table = try routes.Table.initWithTlds(allocator, config.tld, config.tlds, true);
    defer table.deinit();
    try table.set(route("api.myapp.local", 3000));
    for ([_][]const u8{ "api.myapp.test", "api.myapp.dev.example.com:443", "tenant.api.myapp.test" }) |host| {
        const found = (try table.resolve(allocator, host)).?;
        defer found.deinit(allocator);
        try std.testing.expectEqualStrings("api.myapp.local", found.name);
    }
    const url = try config.publicUrl(allocator, "api.myapp.dev.example.com");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("https://api.myapp.dev.example.com", url);
    try std.testing.expectError(error.InvalidHost, table.resolve(allocator, "api.myapp.other"));
    try std.testing.expectError(error.InvalidTld, routes.normalizeTld(allocator, "dev..example.com"));
}

test "overlapping namespaces preserve exact registered names and reject alias collisions" {
    var table = try routes.Table.initWithTlds(allocator, ".example.com", &.{ ".example.com", ".dev.example.com" }, true);
    defer table.deinit();
    try table.set(route("app.dev.example.com", 3000));
    for ([_][]const u8{ "app.dev.example.com", "tenant.app.dev.example.com", "app.dev.dev.example.com" }) |host| {
        const found = (try table.resolve(allocator, host)).?;
        defer found.deinit(allocator);
        try std.testing.expectEqualStrings("app.dev.example.com", found.name);
    }
    try std.testing.expectError(error.RouteAliasConflict, table.set(route("app.example.com", 4000)));
}

test "multi-namespace registry copies keep alias rejection and durable wildcard resolution" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const config: profile.Config = .{ .tld = ".example.com", .tlds = &.{ ".example.com", ".dev.example.com" }, .wildcard = true };
    var store = try registry.Registry.init(allocator, io, path, config);
    for ([_][]const u8{ "app.dev.example.com", "other.example.com" }, 0..) |name, index| {
        const added = (try store.mutate(.{ .id = "add", .operation = "add", .route = route(name, @intCast(3000 + index)), .match = "absent" })).?;
        added.deinit(allocator);
    }
    try std.testing.expectError(error.RouteAliasConflict, store.mutate(.{ .id = "alias", .operation = "add", .route = route("app.example.com", 4000), .match = "absent" }));
    store.deinit();
    store = try registry.Registry.init(allocator, io, path, config);
    defer store.deinit();
    const entries = try store.list(allocator);
    defer freeRoutes(entries);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    const found = (try store.resolve(allocator, "tenant.app.dev.dev.example.com:443")).?;
    defer found.deinit(allocator);
    try std.testing.expectEqualStrings("app.dev.example.com", found.name);
    var long: [260]u8 = @splat('a');
    @memcpy(long[250..], ".localhost");
    try std.testing.expectError(error.InvalidHost, routes.normalizeAuthority(allocator, &long, ".localhost"));
    const tld = try routes.normalizeTld(allocator, ".Dev.Example.COM.");
    defer allocator.free(tld);
    try std.testing.expectEqualStrings(".dev.example.com", tld);
}

test "version is a valid semantic version from build options" {
    const v = try std.SemanticVersion.parse(@import("../root.zig").version);
    _ = v;
    try std.testing.expect(@import("../root.zig").is_dev_build == std.mem.eql(u8, @import("build_options").version, "0.0.0-dev"));
}
