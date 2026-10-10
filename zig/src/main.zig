const std = @import("std");
const p = @import("dotlocal");
const background = @import("background.zig");
const cli_update = @import("cli_update.zig");
const A = std.mem.Allocator;
var stopping: std.atomic.Value(bool) = .init(false);
const installed_socket = "/var/run/dotlocal-zig/management.sock";
const installed_ca = "/usr/local/share/dotlocal-zig/ca.pem";
var background_launch: ?*background.Launch = null;
const Flags = struct {
    values: std.StringHashMapUnmanaged([]const u8) = .empty,
    positional: std.ArrayList([]const u8) = .empty,
    argv: []const []const u8 = &.{},
    tlds: std.ArrayList([]const u8) = .empty,
    fn parse(a: A, args: []const []const u8, valued: []const []const u8, boolean: []const []const u8) !Flags {
        var result: Flags = .{};
        var index: usize = 0;
        while (index < args.len) : (index += 1) {
            const arg = if (eq(args[index], "-p")) "--port" else args[index];
            if (eq(arg, "--")) {
                result.argv = args[index + 1 ..];
                break;
            }
            if (std.mem.startsWith(u8, arg, "--")) {
                const assignment = std.mem.indexOfScalar(u8, arg, '=');
                const key = arg[2 .. assignment orelse arg.len];
                if (result.values.contains(key) and !eq(key, "tld")) return error.DuplicateFlag;
                if (contains(valued, key)) {
                    const value = if (assignment) |offset| arg[offset + 1 ..] else blk: {
                        index += 1;
                        if (index >= args.len) return error.MissingFlagValue;
                        break :blk args[index];
                    };
                    if (eq(key, "tld")) try result.tlds.append(a, value);
                    if (!result.values.contains(key)) try result.values.put(a, key, value);
                } else if (contains(boolean, key)) {
                    const value = if (assignment) |offset| arg[offset + 1 ..] else "true";
                    if (!eq(value, "true") and !eq(value, "false")) return error.InvalidBooleanFlag;
                    try result.values.put(a, key, value);
                } else return error.UnknownFlag;
            } else try result.positional.append(a, arg);
        }
        return result;
    }
    fn get(self: Flags, key: []const u8, default: []const u8) []const u8 {
        return self.values.get(key) orelse default;
    }
    fn has(self: Flags, key: []const u8) bool {
        return self.values.contains(key) and !eq(self.values.get(key).?, "false");
    }
};
fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn contains(list: []const []const u8, key: []const u8) bool {
    for (list) |v| if (eq(v, key)) return true;
    return false;
}
fn output(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
    try writer.interface.print(fmt, args);
    try writer.interface.flush();
}
fn json(io: std.Io, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}
fn port(value: []const u8) !u16 {
    const n = try std.fmt.parseInt(u16, value, 10);
    if (n == 0) return error.InvalidPort;
    return n;
}
fn enabled(value: ?[]const u8) bool {
    const text = value orelse return false;
    return eq(text, "1") or eq(text, "true");
}
fn bypass(init: std.process.Init) bool {
    const value = init.environ_map.get("DOTLOCAL") orelse return false;
    return eq(value, "0") or eq(value, "false") or eq(value, "skip");
}
fn selectedProfile(init: std.process.Init, flags: Flags) !p.profile.Config {
    const a = init.arena.allocator();
    if (flags.has("https") and flags.has("no-tls")) return error.IncompatibleFlags;
    const env_https = init.environ_map.get("DOTLOCAL_HTTPS");
    var scheme = flags.get("scheme", if (env_https != null and (eq(env_https.?, "0") or eq(env_https.?, "false"))) "http" else "https");
    if (flags.values.contains("https")) scheme = if (flags.has("https")) "https" else "http";
    if (flags.has("cert") or flags.has("key")) scheme = "https";
    if (flags.has("no-tls")) scheme = "http";
    const proxy_port = if (flags.values.get("port") orelse init.environ_map.get("DOTLOCAL_PORT")) |value| try port(value) else if (eq(scheme, "http")) @as(u16, 80) else 443;
    if (flags.has("listen") and flags.has("port")) return error.IncompatibleFlags;
    var suffixes: std.ArrayList([]const u8) = .empty;
    const inputs: []const []const u8 = if (flags.tlds.items.len != 0) flags.tlds.items else if (init.environ_map.get("DOTLOCAL_TLD")) |value| &.{value} else &.{p.routes.default_tld};
    for (inputs) |value| {
        var parts = std.mem.splitScalar(u8, value, ',');
        while (parts.next()) |part| {
            const normalized = try p.routes.normalizeTld(a, std.mem.trim(u8, part, " \t"));
            if (!contains(suffixes.items, normalized)) try suffixes.append(a, normalized);
        }
    }
    if (suffixes.items.len == 0) return error.InvalidTld;
    const config: p.profile.Config = .{ .scheme = scheme, .listen = flags.values.get("listen") orelse try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{proxy_port}), .tld = suffixes.items[0], .tlds = suffixes.items, .wildcard = if (flags.values.contains("wildcard")) flags.has("wildcard") else enabled(init.environ_map.get("DOTLOCAL_WILDCARD")), .cert = flags.values.get("cert"), .key = flags.values.get("key") };
    try config.validate(a);
    return config;
}
fn userState(init: std.process.Init, a: A) ![]const u8 {
    if (init.environ_map.get("DOTLOCAL_RUNNER_STATE")) |state| return state;
    if (init.environ_map.get("DOTLOCAL_STATE_DIR")) |state| return std.fs.path.join(a, &.{ state, "runners" });
    return std.fmt.allocPrint(a, "{s}/.dotlocal/zig-runners", .{init.environ_map.get("HOME") orelse return error.HomeMissing});
}
fn proxyState(init: std.process.Init, a: A) ![]const u8 {
    if (init.environ_map.get("DOTLOCAL_STATE_DIR")) |state| return state;
    return std.fmt.allocPrint(a, "{s}/.dotlocal/zig-proxy", .{init.environ_map.get("HOME") orelse return error.HomeMissing});
}
fn management(init: std.process.Init) p.client.Client {
    const a = init.arena.allocator();
    const socket = init.environ_map.get("DOTLOCAL_SOCKET") orelse blk: {
        const state = proxyState(init, a) catch break :blk installed_socket;
        const candidate = std.fs.path.join(a, &.{ state, "management.sock" }) catch break :blk installed_socket;
        if (init.environ_map.get("DOTLOCAL_STATE_DIR") != null) break :blk candidate;
        if (std.Io.Dir.cwd().statFile(init.io, candidate, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .unix_domain_socket) break :blk candidate;
        } else |_| {}
        break :blk installed_socket;
    };
    return .{ .allocator = init.gpa, .io = init.io, .socket_path = socket };
}

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch {
        std.process.exit(1);
    };
    const command: ?[]const u8 = if (args.len > 1) args[1] else null;
    cli_update.applyUserConfig(init, command) catch std.process.exit(1);
    cli_update.reportBackground(init, command);
    const code = execute(init, args[1..]) catch |err| blk: {
        std.log.err("dotlocal: {s}", .{@errorName(err)});
        break :blk 1;
    };
    cli_update.spawnBackground(init, command);
    std.process.exit(code);
}
fn execute(init: std.process.Init, args: []const []const u8) anyerror!u8 {
    const a = init.arena.allocator();
    const io = init.io;
    const client = management(init);
    if (args.len == 0) return runCommand(init, client, &.{}, false);
    if (std.mem.startsWith(u8, args[0], "--") and !contains(&.{"--help"}, args[0])) return runCommand(init, client, args, true);
    const command = args[0];
    const rest = args[1..];
    if (eq(command, "__background")) {
        if (rest.len < 2 or !contains(&.{ "named", "run" }, rest[1])) return error.InvalidBackgroundArguments;
        if (std.c.setsid() < 0) return error.DetachFailed;
        var launch = try background.Launch.open(a, io, try userState(init, a), rest[0]);
        defer launch.deinit();
        background_launch = &launch;
        defer background_launch = null;
        return runCommand(init, client, rest[2..], eq(rest[1], "named"));
    }
    if (eq(command, "__auto-update")) return cli_update.autoUpdate(init);
    if (eq(command, "config")) return cli_update.configCommand(init, rest);
    if (eq(command, "update")) {
        const f = try Flags.parse(a, rest, &.{ "channel", "version" }, &.{"check"});
        if (f.positional.items.len != 0 or f.argv.len != 0) return error.UnexpectedArgument;
        return cli_update.updateCommand(init, .{ .check = f.has("check"), .channel = f.values.get("channel"), .version = f.values.get("version") });
    }
    if (contains(&.{ "help", "--help", "-h" }, command)) {
        try output(io, "dotlocal {s} (Zig 0.17)\n" ++
            "  init | install | upgrade | uninstall\n" ++
            "  daemon --state-dir DIR --management-socket SOCKET [--scheme http|https]\n" ++
            "         [--listen LOOPBACK:PORT --tld TLD --cert FILE --key FILE --wildcard]\n" ++
            "  alias NAME PORT | alias --remove NAME\n" ++
            "  add NAME --host IP --port PORT [--protocol http|https --force]\n" ++
            "  add NAME --container ID --container-cli PATH --port PORT\n" ++
            "  run [--name NAME --app-port PORT --force] COMMAND ARGS...\n" ++
            "  start [NAME COMMAND ARGS...] | run --background [--name NAME] COMMAND ARGS...\n" ++
            "  stop NAME (stop an owned app; the shared proxy remains running)\n" ++
            "      [--lan [--https --ip IP] | --tailscale | --funnel | --ngrok]\n" ++
            "  NAME COMMAND ARGS... | bare project script/workspace\n" ++
            "  get NAME | list | remove NAME [--force] | status | doctor | refresh | prune\n" ++
            "  clean [--routes --yes] | hosts sync|clean [--apply]\n" ++
            "  proxy start|status|stop | service install|status|uninstall\n" ++
            "      (install applies your update config; sudo install keeps the service's)\n" ++
            "  trust install|status|remove | version\n" ++
            "  update [--check] [--channel stable|nightly] [--version X]\n" ++
            "  config [get KEY | set KEY VALUE | unset KEY]\n", .{p.version});
        return 0;
    }
    if (eq(command, "version")) {
        if (rest.len != 0) return error.UnexpectedArgument;
        try output(io, "{s}\n", .{p.version});
        return 0;
    }
    if (eq(command, "daemon")) {
        const f = try Flags.parse(a, rest, &.{ "state-dir", "management-socket", "management-group", "scheme", "listen", "port", "tld", "cert", "key", "redirect-listen", "container-cli", "update-channel", "update-pin" }, &.{ "wildcard", "dual-loopback", "reconcile-profile", "https", "no-tls", "no-auto-update" });
        if (f.positional.items.len != 0 or f.argv.len != 0) return error.UnexpectedArgument;
        const state = f.get("state-dir", init.environ_map.get("DOTLOCAL_STATE_DIR") orelse if (@import("builtin").os.tag == .linux) "/var/lib/dotlocal" else "/Library/Application Support/dotlocal-zig");
        const config = try selectedProfile(init, f);
        const runtime = try p.daemon.Runtime.init(init.gpa, io, .{ .state_dir = state, .socket_path = f.get("management-socket", client.socket_path), .profile = config, .profile_explicit = containsProfileFlags(f), .redirect_listen = f.values.get("redirect-listen"), .container_cli = f.values.get("container-cli"), .dual_loopback = if (f.values.contains("dual-loopback")) f.has("dual-loopback") else null, .reconcile_profile = f.has("reconcile-profile"), .management_gid = if (f.values.get("management-group")) |group| try p.service.groupID(a, group) else null });
        defer runtime.deinit();
        const action: std.posix.Sigaction = .{ .handler = .{ .handler = signalHandler }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
        std.posix.sigaction(.INT, &action, null);
        std.posix.sigaction(.TERM, &action, null);
        // Only the installed service passes --update-channel; user proxies
        // follow the CLI binary instead of updating it themselves.
        if (f.values.get("update-channel")) |text| if (!f.has("no-auto-update") and f.values.get("update-pin") == null and !p.is_dev_build) {
            const channel = std.meta.stringToEnum(p.manifest.Channel, text) orelse return error.InvalidChannel;
            var updated: std.atomic.Value(bool) = .init(false);
            if (io.concurrent(cli_update.daemonUpdater, .{ init.gpa, io, try p.update.sourceFromEnv(a, init.environ_map), channel, state, &stopping, &updated })) |task| {
                var updater = task;
                defer updater.cancel(io);
                try runtime.run(&stopping);
            } else |err| {
                std.log.warn("self-update disabled: {s}", .{@errorName(err)});
                try runtime.run(&stopping);
            }
            // launchd KeepAlive.SuccessfulExit=false restarts the new binary.
            return if (updated.load(.acquire)) 75 else 0;
        };
        try runtime.run(&stopping);
        return 0;
    }
    if (eq(command, "run")) return runCommand(init, client, rest, false);
    if (eq(command, "start")) {
        var start_args: std.ArrayList([]const u8) = .empty;
        try start_args.append(a, "--background");
        try start_args.appendSlice(a, rest);
        return runCommand(init, client, start_args.items, true);
    }
    if (eq(command, "stop")) return stopCommand(init, client, rest);
    if (eq(command, "alias") or eq(command, "add")) {
        const f = try Flags.parse(a, rest, &.{ "host", "port", "protocol", "container", "container-cli" }, &.{ "force", "remove" });
        if (f.has("remove")) {
            if (f.positional.items.len != 1) return error.ExpectedName;
            return execute(init, if (f.has("force")) &.{ "remove", f.positional.items[0], "--force" } else &.{ "remove", f.positional.items[0] });
        }
        if ((f.positional.items.len != 1 and f.positional.items.len != 2) or f.argv.len != 0) return error.ExpectedName;
        const status = try client.call(.{ .id = "", .operation = "status" });
        defer status.deinit();
        const tld = if (status.value.status) |s| s.tld else p.routes.default_tld;
        const name = try p.routes.normalizeName(a, f.positional.items[0], tld);
        const scheme = f.get("protocol", "http");
        const number: u16 = if (f.has("port")) try port(f.get("port", "0")) else if (f.positional.items.len == 2) try port(f.positional.items[1]) else if (f.has("container")) 0 else return error.MissingPort;
        var route: p.protocol.Route = .{ .name = name, .scheme = scheme, .host = f.get("host", "127.0.0.1"), .port = number };
        if (f.values.get("container")) |container| {
            if (f.has("host")) return error.IncompatibleFlags;
            const endpoint = try p.applecontainer.resolve(a, io, f.get("container-cli", "/opt/homebrew/bin/container"), container, number, scheme);
            route.host = endpoint.host;
            route.port = endpoint.port;
            route.owner = .{ .kind = "container", .container = endpoint.container, .network = endpoint.network, .refresh = "container-address" };
        }
        const response = try client.call(.{ .id = "", .operation = "add", .route = route, .match = if (f.has("force")) "any" else "absent" });
        defer response.deinit();
        try json(io, response.value.route);
        return 0;
    }
    if (eq(command, "remove")) {
        const f = try Flags.parse(a, rest, &.{}, &.{"force"});
        if (f.positional.items.len != 1 or f.argv.len != 0) return error.ExpectedName;
        const list = try client.call(.{ .id = "", .operation = "list" });
        defer list.deinit();
        const status = try client.call(.{ .id = "", .operation = "status" });
        defer status.deinit();
        const active = status.value.status orelse return error.MissingDaemonProfile;
        const name = try p.routes.normalizeName(a, f.positional.items[0], active.tld);
        var owner: ?p.protocol.Owner = null;
        for (list.value.routes orelse &.{}) |route| if (eq(route.name, name)) {
            owner = route.owner;
            break;
        };
        if (owner == null) return error.RouteNotFound;
        const response = try client.call(.{ .id = "", .operation = "remove", .name = name, .match = if (f.has("force")) "any" else "owner", .expected_owner = if (f.has("force")) null else owner });
        defer response.deinit();
        return 0;
    }
    if (contains(&.{ "list", "status", "doctor", "refresh" }, command)) {
        if (rest.len != 0) return error.UnexpectedArgument;
        const response = client.call(.{ .id = "", .operation = command }) catch |err| {
            if (eq(command, "status") and (err == error.FileNotFound or err == error.ConnectFailed)) {
                try json(io, p.protocol.Response{ .version = 2, .id = "", .ok = true, .status = .{ .running = false } });
                return 0;
            }
            return err;
        };
        defer response.deinit();
        try json(io, response.value);
        return 0;
    }
    if (eq(command, "prune") or eq(command, "clean")) {
        const f = try Flags.parse(a, rest, &.{}, &.{ "routes", "yes" });
        const all_routes = eq(command, "clean") and f.has("routes");
        if (f.positional.items.len != 0 or f.argv.len != 0) return error.UnexpectedArgument;
        if (eq(command, "prune") and f.values.count() != 0) return error.UnknownFlag;
        if (all_routes and !f.has("yes")) return error.ConfirmationRequired;
        const response = try client.call(.{ .id = "", .operation = "list" });
        defer response.deinit();
        const state = try userState(init, a);
        _ = try std.Io.Dir.cwd().createDirPathStatus(io, state, .fromMode(0o700));
        try p.sharing.prune(init.gpa, io, state, all_routes);
        for (response.value.routes orelse &.{}) |route| {
            if (!all_routes and (!eq(route.owner.kind, "process") or p.process.matches(route.owner))) continue;
            const result = try client.call(.{ .id = "", .operation = "remove", .name = route.name, .match = "owner", .expected_owner = route.owner });
            result.deinit();
        }
        var manager = try p.runner.Manager.open(init.gpa, io, state);
        defer manager.deinit();
        _ = try manager.prune();
        return 0;
    }
    if (eq(command, "hosts")) {
        if (rest.len == 0 or !contains(&.{ "sync", "clean" }, rest[0])) return error.ExpectedHostsOperation;
        const f = try Flags.parse(a, rest[1..], &.{}, &.{"apply"});
        if (f.positional.items.len != 0 or f.argv.len != 0) return error.UnexpectedArgument;
        var names: std.ArrayList([]const u8) = .empty;
        var hosts_config: p.hosts.Config = .{};
        if (eq(rest[0], "sync")) {
            const status_response = try client.call(.{ .id = "", .operation = "status" });
            defer status_response.deinit();
            const status = status_response.value.status orelse return error.MissingDaemonProfile;
            hosts_config.suffixes = try p.routes.cloneTlds(a, status.tld, status.tlds orelse &.{});
            const response = try client.call(.{ .id = "", .operation = "list" });
            defer response.deinit();
            for (response.value.routes orelse &.{}) |route| try names.append(a, try a.dupe(u8, route.name));
        }
        const plan = try p.hosts.plan(a, io, hosts_config, names.items);
        try json(io, plan);
        if (f.has("apply")) _ = try p.hosts.apply(a, io, hosts_config, plan);
        return 0;
    }
    if (eq(command, "proxy")) return proxyCommand(init, client, rest);
    if (eq(command, "get")) {
        if (rest.len != 1) return error.ExpectedName;
        const status = try client.call(.{ .id = "", .operation = "status" });
        defer status.deinit();
        const active = status.value.status orelse return error.MissingDaemonProfile;
        const route_list = try client.call(.{ .id = "", .operation = "list" });
        defer route_list.deinit();
        const config: p.profile.Config = .{ .scheme = active.scheme, .listen = active.listen_address, .tld = active.tld, .tlds = active.tlds orelse &.{} };
        const name = try p.routes.normalizeName(a, rest[0], active.tld);
        for (route_list.value.routes orelse &.{}) |route| if (eq(name, route.name)) {
            try output(io, "{s}\n", .{try config.publicUrl(a, name)});
            return 0;
        };
        return error.RouteNotFound;
    }
    if (eq(command, "service")) {
        if (rest.len != 1) return error.ExpectedServiceOperation;
        if (eq(rest[0], "status")) {
            try output(io, "loaded: {}\n", .{try p.service.loaded(a, io, .{})});
            return 0;
        }
        if (eq(rest[0], "install")) return execute(init, &.{"install"});
        if (eq(rest[0], "uninstall")) return execute(init, &.{"uninstall"});
        return error.UnknownOperation;
    }
    if (contains(&.{ "install", "upgrade", "init", "uninstall" }, command)) {
        const f = try Flags.parse(a, rest, &.{ "management-group", "scheme", "listen", "port", "tld", "cert", "key", "container-cli", "redirect-listen", "update-channel", "update-pin" }, &.{ "wildcard", "https", "no-tls", "no-auto-update", "keep-binary", "force" });
        // Unprivileged install/upgrade go through init, which forwards the
        // invoking user's update settings to the sudo'd install.
        const via_init = eq(command, "init") or (!eq(command, "uninstall") and p.process.uid() != 0);
        if (f.positional.items.len != 0 or f.argv.len != 0) return error.UnexpectedArgument;
        var config: p.service.Config = .{};
        config.management_group = f.get("management-group", "admin");
        config.profile = try selectedProfile(init, f);
        config.container_cli = f.values.get("container-cli");
        config.redirect_listen = f.values.get("redirect-listen");
        if (eq(command, "uninstall")) {
            try p.service.uninstall(a, io, config);
            return 0;
        }
        // init runs unprivileged with the user's config and forwards it to
        // the sudo install as flags; root never reads the user's config file.
        // Root without update flags (sudo install, sudo init) keeps the
        // installed service's settings instead of resetting them.
        const update_settings = try p.update.settings(init.environ_map);
        config.update = .{
            .channel = f.get("update-channel", @tagName(update_settings.channel)),
            .auto_update = if (f.values.contains("no-auto-update")) !f.has("no-auto-update") else update_settings.enabled,
            .pin = f.values.get("update-pin") orelse update_settings.pin,
        };
        const update_flags = f.values.contains("update-channel") or f.values.contains("update-pin") or f.values.contains("no-auto-update");
        if (p.process.uid() == 0 and !update_flags) try p.service.keepInstalledUpdate(a, &config);
        if (via_init) {
            var retained_profile: std.ArrayList([]const u8) = .empty;
            var keep_binary = false;
            var status_known = false;
            if (client.call(.{ .id = "", .operation = "status" })) |response| {
                defer response.deinit();
                if (response.value.status) |status| {
                    status_known = true;
                    const installed_update = p.service.installedUpdate(a, config) catch null;
                    const update_matches = if (installed_update) |installed| installed.eql(config.update) else false;
                    // Never replace a newer service binary with this one
                    // unless forced or pinned (rollback); settings changes
                    // still reinstall.
                    keep_binary = p.update.keepServiceBinary(status.version, p.version, config.update.pin, f.has("force"));
                    if (update_matches and (eq(status.version, p.version) or keep_binary) and (!containsProfileFlags(f) or statusMatches(a, status, config.profile))) {
                        const doctor = try client.call(.{ .id = "", .operation = "doctor" });
                        defer doctor.deinit();
                        if (healthy(doctor.value)) {
                            try json(io, doctor.value);
                            return 0;
                        }
                    }
                    if (!containsProfileFlags(f)) {
                        try retained_profile.appendSlice(a, &.{ "--scheme", try a.dupe(u8, status.scheme), "--listen", try a.dupe(u8, status.listen_address), "--tld", try a.dupe(u8, status.tld) });
                        if (status.tlds) |suffixes| for (suffixes) |suffix| if (!eq(suffix, status.tld)) try retained_profile.appendSlice(a, &.{ "--tld", try a.dupe(u8, suffix) });
                        if (status.wildcard_fallback) try retained_profile.append(a, "--wildcard");
                        if (status.certificate_file.len != 0) try retained_profile.appendSlice(a, &.{ "--cert", try a.dupe(u8, status.certificate_file), "--key", try a.dupe(u8, status.key_file) });
                    }
                }
            } else |_| {}
            // A stopped service cannot report its version; ask its binary.
            if (!status_known and !f.has("force")) {
                if (p.service.installedVersion(a, io, config) catch null) |installed| keep_binary = p.update.keepServiceBinary(installed, p.version, config.update.pin, false);
            }
            if (!eq(client.socket_path, installed_socket)) {
                try output(io, "Custom proxy socket {s} is not the installed service. Use proxy start with an unprivileged port, or unset DOTLOCAL_SOCKET before dotlocal init.\n", .{client.socket_path});
                return error.CustomSocketInstallUnsupported;
            }
            if (p.process.uid() != 0 and std.c.isatty(0) != 1) {
                try output(io, "One-time setup requires authentication. Run dotlocal init in a terminal, then retry this command. For an unprivileged proxy, run dotlocal proxy start --port 1355.\n", .{});
                return error.InteractiveSetupRequired;
            }
            const executable = try std.process.executablePathAlloc(io, a);
            var install_args: std.ArrayList([]const u8) = .empty;
            if (p.process.uid() != 0) try install_args.append(a, "/usr/bin/sudo");
            try install_args.appendSlice(a, &.{ executable, "install" });
            try install_args.appendSlice(a, rest);
            if (keep_binary) try install_args.append(a, "--keep-binary");
            if (!f.values.contains("update-channel")) try install_args.appendSlice(a, &.{ "--update-channel", config.update.channel });
            if (!f.values.contains("no-auto-update") and !config.update.auto_update) try install_args.append(a, "--no-auto-update");
            if (!f.values.contains("update-pin")) if (config.update.pin) |pin| try install_args.appendSlice(a, &.{ "--update-pin", pin });
            try install_args.appendSlice(a, retained_profile.items);
            var installer = try std.process.spawn(io, .{ .argv = install_args.items, .stdin = .inherit, .stdout = .inherit, .stderr = .inherit });
            defer installer.kill(io);
            if (!(try installer.wait(io)).success()) return error.InstallFailed;
            try waitForDaemon(client, null);
            const doctor = try client.call(.{ .id = "", .operation = "doctor" });
            defer doctor.deinit();
            try json(io, doctor.value);
            if (!healthy(doctor.value)) return error.UnhealthyInstallation;
            return 0;
        }
        // --keep-binary reinstalls the plist over the existing executable.
        try p.service.install(a, io, config, if (f.has("keep-binary")) config.executable else try std.process.executablePathAlloc(io, a));
        return 0;
    }
    if (eq(command, "trust")) {
        if (rest.len != 1) return error.ExpectedTrustOperation;
        if (eq(rest[0], "install")) {
            try p.service.trust(a, io, installed_ca);
            return 0;
        }
        if (eq(rest[0], "status")) {
            const trusted = try p.service.systemTrusted(a, io, installed_ca);
            try output(io, "{s}\n", .{if (trusted) "trusted" else "not trusted"});
            return if (trusted) 0 else 1;
        }
        if (eq(rest[0], "remove")) {
            try p.service.untrust(a, io, installed_ca);
            return 0;
        }
        return error.UnknownOperation;
    }
    return runCommand(init, client, args, true);
}
fn healthy(response: p.protocol.Response) bool {
    const diagnostics = response.diagnostics orelse return false;
    if (diagnostics.len == 0) return false;
    for (diagnostics) |diagnostic| if (!eq(diagnostic.level, "ok")) return false;
    return true;
}
fn signalHandler(_: std.posix.SIG) callconv(.c) void {
    stopping.store(true, .release);
}
fn leadingFlags(a: A, args: []const []const u8) !Flags {
    const valued = &.{ "name", "script", "app-port", "ip", "tailscale-cli", "ngrok-cli" };
    const boolean = &.{ "force", "lan", "https", "tailscale", "funnel", "ngrok", "help", "background" };
    var end: usize = 0;
    while (end < args.len) {
        const arg = args[end];
        if (eq(arg, "--")) {
            end += 1;
            break;
        }
        if (!std.mem.startsWith(u8, arg, "--")) break;
        const assignment = std.mem.indexOfScalar(u8, arg, '=');
        const key = arg[2 .. assignment orelse arg.len];
        if (!contains(valued, key) and !contains(boolean, key)) return error.UnknownFlag;
        end += 1;
        if (contains(valued, key) and assignment == null) {
            if (end >= args.len or std.mem.startsWith(u8, args[end], "--")) return error.MissingFlagValue;
            end += 1;
        }
    }
    var flags = try Flags.parse(a, args[0..end], valued, boolean);
    flags.argv = args[end..];
    return flags;
}
fn mergeFlags(a: A, first: *Flags, second: Flags) !void {
    var entries = second.values.iterator();
    while (entries.next()) |entry| {
        if (first.values.contains(entry.key_ptr.*)) return error.DuplicateFlag;
        try first.values.put(a, entry.key_ptr.*, entry.value_ptr.*);
    }
}
fn shortName(name: []const u8) []const u8 {
    const suffix = p.routes.default_tld;
    return if (std.mem.endsWith(u8, name, suffix)) name[0 .. name.len - suffix.len] else name;
}
fn flagOrEnvironment(flags: Flags, key: []const u8, value: ?[]const u8) bool {
    return if (flags.values.contains(key)) flags.has(key) else enabled(value);
}
fn configureSharing(init: std.process.Init, flags: Flags, session: *p.sharing.Session) !void {
    session.use_lan = flagOrEnvironment(flags, "lan", init.environ_map.get("DOTLOCAL_LAN"));
    session.ip = flags.values.get("ip") orelse init.environ_map.get("DOTLOCAL_LAN_IP");
    if (session.ip != null) session.use_lan = true;
    session.https = flagOrEnvironment(flags, "https", init.environ_map.get("DOTLOCAL_HTTPS"));
    const funnel = flagOrEnvironment(flags, "funnel", init.environ_map.get("DOTLOCAL_FUNNEL"));
    const tailscale = flagOrEnvironment(flags, "tailscale", init.environ_map.get("DOTLOCAL_TAILSCALE"));
    session.tail_mode = if (funnel) .funnel else if (tailscale) .serve else null;
    session.tail_cli = flags.get("tailscale-cli", "/opt/homebrew/bin/tailscale");
    session.use_ngrok = flagOrEnvironment(flags, "ngrok", init.environ_map.get("DOTLOCAL_NGROK"));
    session.ngrok_cli = flags.get("ngrok-cli", "/opt/homebrew/bin/ngrok");
}
fn configureRunner(init: std.process.Init, client: p.client.Client, options: *p.runner.Options, sharing: *p.sharing.Session) !void {
    const a = init.arena.allocator();
    const prefix = try p.auto.worktreePrefix(a, init.io, options.working_directory orelse try std.process.currentPathAlloc(init.io, a));
    options.name = try p.auto.applyWorktreePrefix(a, shortName(options.name), prefix);
    if (options.proxy) {
        const response = try client.call(.{ .id = "", .operation = "status" });
        defer response.deinit();
        const active = response.value.status orelse return error.MissingDaemonProfile;
        options.tld = try a.dupe(u8, active.tld);
        const config: p.profile.Config = .{ .scheme = active.scheme, .listen = active.listen_address, .tld = options.tld, .tlds = active.tlds orelse &.{} };
        options.name = try p.routes.normalizeName(a, options.name, options.tld);
        options.public_url = try config.publicUrl(a, options.name);
        options.vite_allowed_hosts = try std.mem.join(a, ",", if (active.tlds) |suffixes| suffixes else &.{options.tld});
        if (eq(active.certificate_mode, "local-ca")) {
            const user_ca = try std.fs.path.join(a, &.{ try proxyState(init, a), "pki", "ca.pem" });
            const ca = if (eq(client.socket_path, installed_socket)) installed_ca else user_ca;
            if (std.Io.Dir.openFileAbsolute(init.io, ca, .{ .follow_symlinks = false })) |file| {
                file.close(init.io);
                options.node_extra_ca_certs = ca;
            } else |_| {}
        }
    } else options.app_port = null;
    sharing.tld = options.tld;
    options.lan = sharing.use_lan;
    options.inject_framework_flags = true;
    options.before_start = p.sharing.Session.prepare;
    options.on_prepare_failure = p.sharing.Session.cancel;
    options.after_start = runnerStarted;
    options.after_exit = p.sharing.Session.exited;
    options.hook_context = sharing;
}
fn runnerStarted(child: *p.runner.Process, context: ?*anyopaque) !void {
    try p.sharing.Session.started(child, context);
    if (background_launch) |launch| try launch.ready(child.record);
}
fn launchBackground(init: std.process.Init, state: []const u8, args: []const []const u8, shorthand: bool) !u8 {
    const started = background.start(init.gpa, init.io, state, args, shorthand, init.environ_map) catch |err| {
        try output(init.io, "Background startup failed ({s}). Logs are under {s}/background/.\n", .{ @errorName(err), state });
        return err;
    };
    defer started.ready.deinit();
    defer init.gpa.free(started.log_path);
    for (started.ready.value.records) |record| try output(init.io, "Started {s} (PID {d}){s}{s}\n", .{ record.endpoint.name, record.identity.pid, if (record.endpoint.url.len > 0) ": " else "", record.endpoint.url });
    try output(init.io, "Log: {s}\n", .{started.log_path});
    return 0;
}
fn stopCommand(init: std.process.Init, client: p.client.Client, args: []const []const u8) !u8 {
    if (args.len != 1) return error.ExpectedAppName;
    const a = init.arena.allocator();
    const io = init.io;
    var manager = try p.runner.Manager.open(init.gpa, io, try userState(init, a));
    defer manager.deinit();
    const records = try manager.records();
    defer records.deinit();
    var name = args[0];
    var exact = false;
    for (records.value.records) |record| if (eq(record.endpoint.name, name)) {
        exact = true;
        break;
    };
    if (!exact) {
        var suffix: []const u8 = p.routes.default_tld;
        if (client.call(.{ .id = "", .operation = "status" })) |status| {
            defer status.deinit();
            if (status.value.status) |active| suffix = try a.dupe(u8, active.tld);
        } else |err| if (!absentProxy(err)) return err;
        const prefix = try p.auto.worktreePrefix(a, io, try std.process.currentPathAlloc(io, a));
        name = try p.routes.normalizeName(a, try p.auto.applyWorktreePrefix(a, shortName(name), prefix), suffix);
    }
    for (records.value.records) |record| if (eq(record.endpoint.name, name)) {
        // Its supervisor may finish cleanup between the listing and this stop.
        manager.stopRecord(record, 5000) catch |err| if (err != error.NotTracked) return err;
        // Wait for the existing supervisor's owner-checked route and sharing cleanup.
        if (record.endpoint.proxy) {
            const deadline = std.Io.Clock.awake.now(io).toNanoseconds() + 5 * std.time.ns_per_s;
            while (true) {
                const listed = client.call(.{ .id = "", .operation = "list" }) catch |err| {
                    if (absentProxy(err)) break;
                    return err;
                };
                defer listed.deinit();
                var owned = false;
                for (listed.value.routes orelse &.{}) |route| if (eq(route.name, name) and route.owner.eql(record.owner())) {
                    owned = true;
                };
                if (!owned) break;
                if (std.Io.Clock.awake.now(io).toNanoseconds() >= deadline) {
                    const removed = try client.call(.{ .id = "", .operation = "remove", .name = name, .match = "owner", .expected_owner = record.owner() });
                    removed.deinit();
                    break;
                }
                try std.Io.sleep(io, .fromMilliseconds(20), .awake);
            }
        }
        try output(io, "Stopped {s}\n", .{name});
        return 0;
    };
    try output(io, "{s} is not running under this user's dotlocal runner.\n", .{name});
    return 0;
}
fn configEnvironment(a: A, config: ?p.projectconfig.Config) !?*std.process.Environ.Map {
    const conf = config orelse return null;
    if (conf.env.map.count() == 0) return null;
    const map = try a.create(std.process.Environ.Map);
    map.* = .init(a);
    var entries = conf.env.map.iterator();
    while (entries.next()) |entry| try map.put(entry.key_ptr.*, entry.value_ptr.*);
    return map;
}
fn runCommand(init: std.process.Init, selected: p.client.Client, args: []const []const u8, shorthand: bool) !u8 {
    const a = init.arena.allocator();
    const io = init.io;
    var flags = try leadingFlags(a, args);
    var argv = flags.argv;
    var explicit_name = flags.values.get("name") orelse "";
    var named = shorthand;
    if (shorthand and explicit_name.len == 0 and argv.len != 0) {
        if (eq(argv[0], "run")) {
            named = false;
            argv = argv[1..];
        } else {
            explicit_name = argv[0];
            argv = argv[1..];
        }
        const following = try leadingFlags(a, argv);
        try mergeFlags(a, &flags, following);
        argv = following.argv;
        explicit_name = flags.values.get("name") orelse explicit_name;
    }
    if (shorthand and argv.len == 0 and explicit_name.len == 0) named = false;
    if (flags.has("help")) {
        try output(io, "dotlocal run [--background --name NAME --app-port PORT --force --lan --tailscale --funnel --ngrok --script NAME] COMMAND ARGS...\nCommands and their flags are passed directly after the first command token. -- is optional.\n", .{});
        return 0;
    }
    const cwd = try std.process.currentPathAlloc(io, a);
    var parsed_config: ?std.json.Parsed(p.projectconfig.Config) = null;
    var config_dir: []const u8 = cwd;
    if (try p.projectconfig.find(a, io, cwd)) |path| {
        config_dir = std.fs.path.dirname(path).?;
        parsed_config = try p.projectconfig.load(a, io, path);
    }
    defer if (parsed_config) |parsed| parsed.deinit();
    const config: ?p.projectconfig.Config = if (parsed_config) |parsed| parsed.value else null;
    const script = flags.values.get("script") orelse if (config != null and config.?.script.len != 0) config.?.script else "dev";
    const state = try userState(init, a);
    if (argv.len == 0 and !named and !bypass(init)) if (try p.workspace.discover(a, io, cwd)) |workspace| if (eq(workspace.root, cwd)) {
        if (flags.has("background") and background_launch == null) {
            _ = try ensureProxy(init, selected);
            return launchBackground(init, state, args, shorthand);
        }
        return runWorkspace(init, selected, flags, workspace, config, config_dir, script, state);
    };
    if (argv.len == 0 and config != null and config.?.command.len != 0) argv = config.?.command;
    if (argv.len == 0 and !named) argv = (try p.projectconfig.resolveCommand(a, io, cwd, script)) orelse return error.ExpectedCommand;
    if (argv.len == 0) return error.ExpectedCommand;
    if (bypass(init)) {
        if (flags.has("background")) return error.BackgroundRequiresRunner;
        return p.runner.direct(io, argv, init.environ_map, cwd);
    }
    var sharing: p.sharing.Session = .{ .allocator = init.gpa, .io = io, .state_dir = state };
    try configureSharing(init, flags, &sharing);
    var options: p.runner.Options = .{ .name = if (explicit_name.len != 0) explicit_name else if (config != null and config.?.name.len != 0) config.?.name else try p.auto.inferName(a, io, cwd), .argv = argv, .state_directory = state, .working_directory = cwd, .base_environment = init.environ_map, .force = flags.has("force"), .proxy = if (config) |conf| conf.proxy else true, .app_port = if (flags.values.get("app-port") orelse init.environ_map.get("DOTLOCAL_APP_PORT")) |value| try port(value) else if (config != null and config.?.appPort != 0) config.?.appPort else null, .environment = try configEnvironment(a, config) };
    const client = if (options.proxy) try ensureProxy(init, selected) else selected;
    try configureRunner(init, client, &options, &sharing);
    if (flags.has("background") and background_launch == null) return launchBackground(init, state, args, shorthand);
    return (try p.runner.run(init.gpa, io, client, options)).exitCode();
}
fn runWorkspace(init: std.process.Init, selected: p.client.Client, flags: Flags, workspace: p.workspace.Workspace, config: ?p.projectconfig.Config, config_dir: []const u8, script: []const u8, state: []const u8) !u8 {
    const a = init.arena.allocator();
    const io = init.io;
    var options: std.ArrayList(p.runner.Options) = .empty;
    var root_name = if (flags.values.get("name")) |name| name else if (config != null and config.?.name.len != 0) shortName(config.?.name) else try p.auto.inferName(a, io, workspace.root);
    if (!flags.values.contains("name") and (config == null or config.?.name.len == 0)) {
        var max: usize = 0;
        for (workspace.packages) |package| if (package.scope) |scope| {
            var count: usize = 0;
            for (workspace.packages) |other| if (other.scope != null and eq(scope, other.scope.?)) {
                count += 1;
            };
            if (count > max) {
                max = count;
                root_name = try p.auto.sanitize(a, scope);
            }
        };
    }
    var proxied = false;
    for (workspace.packages) |package| {
        const own = try p.projectconfig.loadCurrent(a, io, package.cwd);
        defer if (own) |parsed| parsed.deinit();
        const override = p.projectconfig.resolveEffectiveAppConfig(config orelse .{}, config_dir, package.cwd, if (own) |parsed| parsed.value else null);
        const package_script = if (flags.values.contains("script")) script else if (override.script.len != 0) override.script else script;
        const command = (try p.projectconfig.resolveCommand(a, io, package.cwd, package_script)) orelse continue;
        const raw = try p.projectconfig.resolveScriptRaw(a, io, package.cwd, package_script);
        const server = if (raw) |value| p.projectconfig.isServerCommand(try p.projectconfig.splitCommand(a, value)) else true;
        const use_proxy = if (override.proxy_set) override.proxy else server;
        const label = try p.auto.sanitize(a, package.name orelse try std.fs.path.relative(a, workspace.root, init.environ_map, workspace.root, package.cwd));
        const name = if (override.name.len != 0) try a.dupe(u8, shortName(override.name)) else if (eq(label, root_name)) root_name else try std.fmt.allocPrint(a, "{s}.{s}", .{ label, root_name });
        try options.append(a, .{ .name = name, .argv = command, .working_directory = package.cwd, .state_directory = state, .base_environment = init.environ_map, .force = flags.has("force"), .proxy = use_proxy, .app_port = if (override.appPort != 0) override.appPort else null, .environment = try configEnvironment(a, if (own) |parsed| parsed.value else config) });
        proxied = proxied or use_proxy;
    }
    if (options.items.len == 0) return error.NoWorkspaceScripts;
    if (background_launch) |launch| launch.expected = options.items.len;
    const client = if (proxied) try ensureProxy(init, selected) else selected;
    const sessions = try a.alloc(p.sharing.Session, options.items.len);
    for (options.items, sessions) |*option, *session| {
        session.* = .{ .allocator = init.gpa, .io = io, .state_dir = state };
        if (option.proxy) try configureSharing(init, flags, session);
        try configureRunner(init, client, option, session);
    }
    return p.runner.runMany(init.gpa, io, client, options.items);
}

/// Polls readiness; a spawned daemon that exits first fails fast instead of
/// waiting out the full deadline.
fn waitForDaemon(client: p.client.Client, daemon: ?*std.process.Child) !void {
    const deadline = std.Io.Clock.awake.now(client.io).toNanoseconds() + 10 * std.time.ns_per_s;
    while (std.Io.Clock.awake.now(client.io).toNanoseconds() < deadline) {
        if (client.call(.{ .id = "", .operation = "status" })) |response| {
            response.deinit();
            return;
        } else |_| {}
        if (daemon) |child| if (try p.runner.reap(client.io, child, false) != null) return error.ProxyExited;
        try std.Io.sleep(client.io, .fromMilliseconds(100), .awake);
    }
    return error.DaemonReadinessTimeout;
}
fn containsProfileFlags(flags: Flags) bool {
    for ([_][]const u8{ "scheme", "listen", "tld", "cert", "key", "wildcard", "port", "https", "no-tls" }) |key| if (flags.values.contains(key)) return true;
    return false;
}
fn defaultProfile(init: std.process.Init, flags: Flags) bool {
    if (containsProfileFlags(flags)) return false;
    for ([_][]const u8{ "DOTLOCAL_PORT", "DOTLOCAL_TLD", "DOTLOCAL_HTTPS", "DOTLOCAL_WILDCARD" }) |key| if (init.environ_map.get(key) != null) return false;
    return true;
}
fn statusMatches(a: A, status: p.protocol.Status, profile: p.profile.Config) bool {
    return eq(status.scheme, profile.scheme) and eq(status.listen_address, profile.listen) and (p.profile.sameTlds(a, status.tld, status.tlds orelse &.{}, profile.tld, profile.tlds)) and status.wildcard_fallback == profile.wildcard and eq(status.certificate_file, profile.cert orelse "") and eq(status.key_file, profile.key orelse "");
}

const ProxyRecord = struct { version: u32 = 1, identity: p.process.Identity, socket_path: []const u8, profile: p.profile.Config };
fn proxyRecord(a: A, io: std.Io, dir: std.Io.Dir) !?std.json.Parsed(ProxyRecord) {
    const file = dir.openFile(io, "proxy-process.json", .{ .follow_symlinks = false, .allow_directory = false }) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close(io);
    try p.process.validateOwned(file.handle, 0o600, false);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const data = try reader.interface.allocRemaining(a, .limited(65536));
    defer a.free(data);
    const record = try std.json.parseFromSlice(ProxyRecord, a, data, .{ .allocate = .alloc_always });
    errdefer record.deinit();
    if (record.value.version != 1 or record.value.identity.uid != p.process.uid() or record.value.identity.pid <= 0 or record.value.identity.start <= 0 or record.value.identity.pgid != record.value.identity.pid or !std.fs.path.isAbsolute(record.value.socket_path)) return error.InvalidProxyRecord;
    try record.value.profile.validate(a);
    return record;
}
fn recordAlive(record: ProxyRecord) bool {
    const live = p.process.inspect(record.identity.pid) catch return false;
    return live.uid == record.identity.uid and live.start == record.identity.start and live.pgid == record.identity.pgid;
}
fn daemonArguments(a: A, io: std.Io, config: p.profile.Config, state: []const u8, socket: []const u8, reconcile: bool) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ try std.process.executablePathAlloc(io, a), "daemon", "--state-dir", state, "--management-socket", socket, "--scheme", config.scheme, "--listen", config.listen, "--tld", config.tld });
    for (config.tlds) |suffix| if (!eq(suffix, config.tld)) try argv.appendSlice(a, &.{ "--tld", suffix });
    if (config.wildcard) try argv.append(a, "--wildcard");
    if (reconcile) try argv.append(a, "--reconcile-profile");
    if (config.cert) |certificate| try argv.appendSlice(a, &.{ "--cert", certificate, "--key", config.key.? });
    return argv.items;
}
/// Creates or opens, without following symlinks, a 0600 file this user owns.
fn openPrivateFile(io: std.Io, directory: std.Io.Dir, name: []const u8) !std.Io.File {
    const file = directory.createFile(io, name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) }) catch |err| blk: {
        if (err != error.PathAlreadyExists) return err;
        break :blk try directory.openFile(io, name, .{ .mode = .read_write, .follow_symlinks = false });
    };
    errdefer file.close(io);
    try p.process.validateOwned(file.handle, 0o600, false);
    return file;
}
fn lockProxy(io: std.Io, directory: std.Io.Dir) !std.Io.File {
    const file = try openPrivateFile(io, directory, "proxy.lock");
    errdefer file.close(io);
    try file.lock(io, .exclusive);
    return file;
}
fn startUserProxy(init: std.process.Init, flags: Flags, reconcile: bool) !p.client.Client {
    const a = init.arena.allocator();
    const io = init.io;
    const config = try selectedProfile(init, flags);
    const address = try std.Io.net.IpAddress.parseLiteral(config.listen);
    if (address.getPort() < 1024 and p.process.uid() != 0) {
        try output(io, "Ports 80/443 require one-time setup. Run dotlocal init in a terminal, or use dotlocal proxy start --port 1355.\n", .{});
        return error.InteractiveSetupRequired;
    }
    const state = flags.values.get("state-dir") orelse try proxyState(init, a);
    var manager = try p.runner.Manager.open(a, io, state);
    defer manager.deinit();
    const lock = try lockProxy(io, manager.directory);
    defer lock.close(io);
    const socket = flags.values.get("management-socket") orelse init.environ_map.get("DOTLOCAL_SOCKET") orelse try std.fs.path.join(a, &.{ state, "management.sock" });
    const client: p.client.Client = .{ .allocator = init.gpa, .io = io, .socket_path = socket };
    if (client.call(.{ .id = "", .operation = "status" })) |response| {
        defer response.deinit();
        if (response.value.status) |status| if (!statusMatches(a, status, config)) return error.ProxyProfileMismatch;
        return client;
    } else |err| if (!absentProxy(err)) return err;
    if (try proxyRecord(a, io, manager.directory)) |record| {
        defer record.deinit();
        if (recordAlive(record.value)) return error.ProxyNotReady;
        if (!eq(record.value.socket_path, socket)) return error.ProxySocketMismatch;
        try p.runner.removeOwnedSocket(a, io, socket);
    } else if (std.Io.Dir.cwd().statFile(io, socket, .{ .follow_symlinks = false })) |_| return error.UnmanagedProxySocket else |err| if (err != error.FileNotFound) return err;
    const log = try openPrivateFile(io, manager.directory, "proxy.log");
    defer log.close(io);
    const argv = try daemonArguments(a, io, config, state, socket, reconcile);
    var child = try std.process.spawn(io, .{ .argv = argv, .pgid = 0, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log }, .environ_map = init.environ_map });
    errdefer child.kill(io);
    const identity = try p.process.inspect(child.id.?);
    if (identity.uid != p.process.uid() or identity.pid != identity.pgid) return error.IdentityMismatch;
    const data = try std.json.Stringify.valueAlloc(a, ProxyRecord{ .identity = identity, .socket_path = socket, .profile = config }, .{});
    var atomic = try manager.directory.createFileAtomic(io, "proxy-process.json", .{ .replace = true, .permissions = .fromMode(0o600) });
    defer atomic.deinit(io);
    try atomic.file.setPermissions(io, .fromMode(0o600));
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
    const dir_file: std.Io.File = .{ .handle = manager.directory.handle, .flags = .{ .nonblocking = false } };
    try dir_file.sync(io);
    waitForDaemon(client, &child) catch |err| {
        try output(io, "Proxy startup failed. Read {s}/proxy.log for details.\n", .{state});
        return err;
    };
    return client;
}
/// The recorded daemon may exit between the liveness check and the signal.
fn stopSignal(identity: p.process.Identity, sig: std.posix.SIG) !void {
    p.process.signal(identity, sig) catch |err| if (err != error.ProcessGone) return err;
}
fn absentProxy(err: anyerror) bool {
    return err == error.FileNotFound or err == error.ConnectFailed;
}
fn ensureProxy(init: std.process.Init, selected: p.client.Client) !p.client.Client {
    if (selected.call(.{ .id = "", .operation = "status" })) |response| {
        response.deinit();
        return selected;
    } else |err| if (!absentProxy(err)) return err;
    const desired = try selectedProfile(init, .{});
    if ((try std.Io.net.IpAddress.parseLiteral(desired.listen)).getPort() >= 1024) return startUserProxy(init, .{}, false);
    if (@import("builtin").os.tag == .linux) {
        try output(init.io, "No proxy is running. Start a foreground daemon with permission to bind 80/443 and select its DOTLOCAL_SOCKET, or use DOTLOCAL_PORT=1355 dotlocal proxy start for an unprivileged proxy.\n", .{});
        return error.ProxyUnavailable;
    }
    if (!eq(selected.socket_path, installed_socket) or init.environ_map.get("DOTLOCAL_STATE_DIR") != null) {
        try output(init.io, "No proxy is running at {s}. Start this user proxy with DOTLOCAL_PORT=1355 dotlocal proxy start, then retry.\n", .{selected.socket_path});
        return error.ProxyUnavailable;
    }
    if (p.process.uid() != 0 and std.c.isatty(0) != 1) {
        try output(init.io, "No proxy is running. Run dotlocal init in a terminal for one-time authenticated setup, then retry. An unprivileged alternative is DOTLOCAL_PORT=1355 dotlocal proxy start.\n", .{});
        return error.InteractiveSetupRequired;
    }
    try output(init.io, "Preparing the local proxy with one-time service setup.\n", .{});
    _ = try execute(init, &.{"init"});
    try waitForDaemon(selected, null);
    return selected;
}
fn proxyCommand(init: std.process.Init, client: p.client.Client, args: []const []const u8) !u8 {
    if (args.len == 0) return error.ExpectedProxyOperation;
    if (eq(args[0], "status")) {
        if (args.len != 1) return error.UnexpectedArgument;
        return execute(init, &.{"status"});
    }
    const a = init.arena.allocator();
    const io = init.io;
    if (eq(args[0], "start")) {
        const flags = try Flags.parse(a, args[1..], &.{ "port", "listen", "scheme", "tld", "cert", "key", "state-dir", "management-socket" }, &.{ "foreground", "https", "no-tls", "wildcard" });
        if (flags.positional.items.len != 0 or flags.argv.len != 0) return error.UnexpectedArgument;
        if (!flags.has("foreground") and !flags.has("state-dir") and !flags.has("management-socket") and defaultProfile(init, flags)) {
            if (client.call(.{ .id = "", .operation = "status" })) |response| {
                defer response.deinit();
                const active = response.value.status orelse return error.MissingDaemonProfile;
                try output(io, "Proxy running at {s} ({s}); socket {s}\n", .{ active.listen_address, active.scheme, client.socket_path });
                return 0;
            } else |err| if (!absentProxy(err)) return err;
        }
        const config = try selectedProfile(init, flags);
        if (flags.has("foreground")) {
            const state = flags.values.get("state-dir") orelse try proxyState(init, a);
            var directory = try p.runner.Manager.open(a, io, state);
            directory.deinit();
            const socket = flags.values.get("management-socket") orelse init.environ_map.get("DOTLOCAL_SOCKET") orelse try std.fs.path.join(a, &.{ state, "management.sock" });
            const argv = try daemonArguments(a, io, config, state, socket, true);
            return execute(init, argv[1..]);
        }
        if ((try std.Io.net.IpAddress.parseLiteral(config.listen)).getPort() < 1024 and eq(client.socket_path, installed_socket) and !flags.has("state-dir") and !flags.has("management-socket") and init.environ_map.get("DOTLOCAL_STATE_DIR") == null) {
            if (defaultProfile(init, flags)) {
                _ = try ensureProxy(init, client);
                return 0;
            }
            var setup: std.ArrayList([]const u8) = .empty;
            try setup.append(a, "init");
            // Explicit proxy profile options survive the one-time setup handoff.
            const arguments = try daemonArguments(a, io, config, "/var/lib/dotlocal-zig", installed_socket, false);
            try setup.appendSlice(a, arguments[6..]);
            return execute(init, setup.items);
        }
        const started = try startUserProxy(init, flags, true);
        const status = try started.call(.{ .id = "", .operation = "status" });
        defer status.deinit();
        try output(io, "Proxy running at {s} ({s}); socket {s}\n", .{ config.listen, config.scheme, started.socket_path });
        return 0;
    }
    if (eq(args[0], "stop")) {
        if (args.len != 1) return error.UnexpectedArgument;
        const state = try proxyState(init, a);
        var manager = try p.runner.Manager.open(a, io, state);
        defer manager.deinit();
        const lock = try lockProxy(io, manager.directory);
        defer lock.close(io);
        if (try proxyRecord(a, io, manager.directory)) |record| {
            defer record.deinit();
            if (eq(record.value.socket_path, client.socket_path)) {
                if (recordAlive(record.value)) try stopSignal(record.value.identity, .TERM);
                const deadline = std.Io.Clock.awake.now(io).toNanoseconds() + 5 * std.time.ns_per_s;
                while (recordAlive(record.value) and std.Io.Clock.awake.now(io).toNanoseconds() < deadline) try std.Io.sleep(io, .fromMilliseconds(20), .awake);
                if (recordAlive(record.value)) try stopSignal(record.value.identity, .KILL);
                try p.runner.removeOwnedSocket(a, io, record.value.socket_path);
                try manager.directory.deleteFile(io, "proxy-process.json");
                return 0;
            }
        }
        if (!eq(client.socket_path, installed_socket)) return error.UnmanagedProxySocket;
        const result = try std.process.run(a, io, .{ .argv = &.{ "/bin/launchctl", "kill", "SIGTERM", "system/com.euforicio.dotlocal-zig" }, .stdout_limit = .limited(65536), .stderr_limit = .limited(65536) });
        if (!result.term.success()) return error.ServiceCommandFailed;
        return 0;
    }
    return error.UnknownOperation;
}
