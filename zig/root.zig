//! dotlocal as a reusable Zig library. Network listeners remain opt-in.
const std = @import("std");

pub const routes = @import("src/routes.zig");
pub const profile = @import("src/profile.zig");
pub const protocol = @import("src/protocol.zig");
pub const registry = @import("src/registry.zig");
pub const client = @import("src/client.zig");
pub const daemon = @import("src/daemon.zig");
pub const pki = @import("src/pki.zig");
pub const http2 = @import("src/http2.zig");
pub const proxy = @import("src/proxy.zig");
pub const net = @import("src/net.zig");
pub const sharing = @import("src/sharing.zig");
pub const runner = @import("src/runner.zig");
pub const auto = @import("src/auto.zig");
pub const framework = @import("src/framework.zig");
pub const workspace = @import("src/workspace.zig");
pub const ngrok = @import("src/ngrok.zig");
pub const process = @import("src/process.zig");
pub const projectconfig = @import("src/projectconfig.zig");
pub const applecredential = @import("src/applecredential.zig");
pub const applecontainer = @import("src/applecontainer.zig");
pub const tailscale = @import("src/tailscale.zig");
pub const lan = @import("src/lan.zig");
pub const mdns = @import("src/mdns.zig");
pub const hosts = @import("src/hosts.zig");
pub const service = @import("src/service.zig");
pub const manifest = @import("src/manifest.zig");
pub const release_keys = @import("src/release_keys.zig");
pub const userconfig = @import("src/userconfig.zig");
pub const update = @import("src/update.zig");
pub const version = @import("build_options").version;
/// Development builds never self-update.
pub const is_dev_build = std.mem.eql(u8, version, "0.0.0-dev");
test {
    std.testing.refAllDecls(@This());
    _ = @import("tests/core.zig");
    _ = @import("tests/runner.zig");
    _ = @import("tests/adapters.zig");
    _ = @import("tests/service.zig");
    _ = @import("tests/pki.zig");
    _ = @import("tests/update.zig");
}
