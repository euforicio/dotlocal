const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const deps = b.option([]const u8, "deps", "OpenSSL 4.0.3 and nghttp2 1.70.0 installation prefix") orelse ".zig-deps";
    const test_filters = b.option([]const []const u8, "test-filter", "Run only tests whose names contain this text") orelse &.{};
    const version = b.option([]const u8, "version", "Release version (semver); omitted for development builds") orelse "0.0.0-dev";
    _ = std.SemanticVersion.parse(version) catch @panic("-Dversion must be a semantic version");
    const update_test = b.option(bool, "update-test", "Trust the test update key and URL prefix from the environment") orelse false;
    const include = depPath(b, b.fmt("{s}/include", .{deps}));
    const libs = depPath(b, b.fmt("{s}/lib", .{deps}));

    const translated = b.addTranslateC(.{ .root_source_file = b.path("zig/src/native.h"), .target = target, .optimize = optimize });
    translated.addIncludePath(include);
    const native = translated.createModule();
    const library: Library = .{ .b = b, .target = target, .optimize = optimize, .native = native, .include = include, .libs = libs };
    const module = library.module("dotlocal", version, update_test);

    const consumer: Consumer = .{ .b = b, .target = target, .optimize = optimize, .dotlocal = module, .native = native };
    const exe = consumer.executable("dotlocal", "zig/src/main.zig", false);
    const fixture = consumer.executable("dotlocal-fixture", "zig/fixture.zig", true);
    const demo = consumer.executable("dotlocal-demo", "zig/demo.zig", true);
    for ([_]*std.Build.Step.Compile{ exe, fixture, demo }) |artifact| b.installArtifact(artifact);

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run the CLI").dependOn(&run.step);

    const test_run = b.addRunArtifact(b.addTest(.{ .root_module = module, .filters = test_filters }));
    test_run.step.dependOn(b.getInstallStep());
    b.step("test", "Run library and real CLI child tests").dependOn(&test_run.step);

    const integration = b.addRunArtifact(consumer.executable("dotlocal-integration", "zig/integration.zig", false));
    for ([_]*std.Build.Step.Compile{ exe, fixture, demo }) |artifact| integration.addArtifactArg(artifact);
    b.step("integration", "Verify real daemon, HTTP/TLS/H2/WebSockets").dependOn(&integration.step);

    const network_bench = b.addRunArtifact(consumer.executable("dotlocal-bench-network", "zig/bench_network.zig", false));
    network_bench.addArtifactArg(exe);
    network_bench.addArtifactArg(fixture);
    network_bench.step.dependOn(&b.addRunArtifact(consumer.executable("dotlocal-bench", "zig/benchmarks.zig", false)).step);
    b.step("bench", "Measure real routing, protocol, durable registry, PKI and network paths").dependOn(&network_bench.step);

    const example = consumer.executable("embedded-dotlocal", "zig/examples/embedded.zig", false);
    b.step("example", "Build a library consumer").dependOn(&b.addInstallArtifact(example, .{}).step);

    // Self-update end to end: two signed test releases of the real CLI.
    const update_run = b.addRunArtifact(consumer.executable("dotlocal-update-test", "zig/update_test.zig", false));
    for ([_][]const u8{ "0.1.0", "0.2.0" }) |v| {
        var variant = consumer;
        variant.dotlocal = library.module(null, v, true);
        update_run.addArtifactArg(variant.executable(b.fmt("dotlocal-{s}", .{v}), "zig/src/main.zig", false));
    }
    update_run.addArtifactArg(fixture);
    update_run.addFileArg(b.path("release/install.sh"));
    integration.step.dependOn(&update_run.step);

    const release_tool = consumer.executable("dotlocal-release", "zig/tools/release.zig", false);
    b.step("release-tool", "Build the release manifest/signing tool").dependOn(&b.addInstallArtifact(release_tool, .{}).step);
}

/// The dotlocal library module for one version/update-test configuration.
const Library = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    native: *std.Build.Module,
    include: std.Build.LazyPath,
    libs: std.Build.LazyPath,

    /// `public` names the module for package consumers; test variants are private.
    fn module(l: Library, public: ?[]const u8, version: []const u8, update_test: bool) *std.Build.Module {
        const options = l.b.addOptions();
        options.addOption([]const u8, "version", version);
        options.addOption(bool, "update_test", update_test);
        const create: std.Build.Module.CreateOptions = .{ .root_source_file = l.b.path("zig/root.zig"), .target = l.target, .optimize = l.optimize, .link_libc = true };
        const m = if (public) |name| l.b.addModule(name, create) else l.b.createModule(create);
        m.addImport("native", l.native);
        m.addOptions("build_options", options);
        m.addAnonymousImport("release-public-key", .{ .root_source_file = l.b.path("release/public-key") });
        m.addIncludePath(l.include);
        m.addLibraryPath(l.libs);
        for ([_][]const u8{ "ssl", "crypto", "nghttp2" }) |lib| {
            m.linkSystemLibrary(lib, .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        }
        return m;
    }
};

/// Executables that import the dotlocal module, and optionally the C bindings.
const Consumer = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    dotlocal: *std.Build.Module,
    native: *std.Build.Module,

    fn executable(c: Consumer, name: []const u8, root: []const u8, with_native: bool) *std.Build.Step.Compile {
        const imports: []const std.Build.Module.Import = if (with_native)
            &.{ .{ .name = "dotlocal", .module = c.dotlocal }, .{ .name = "native", .module = c.native } }
        else
            &.{.{ .name = "dotlocal", .module = c.dotlocal }};
        return c.b.addExecutable(.{ .name = name, .root_module = c.b.createModule(.{
            .root_source_file = c.b.path(root),
            .target = c.target,
            .optimize = c.optimize,
            .imports = imports,
            .link_libc = true,
        }) });
    }
};

fn depPath(b: *std.Build, path: []const u8) std.Build.LazyPath {
    return if (std.fs.path.isAbsolute(path)) .{ .cwd_relative = path } else b.path(path);
}
