# dotlocal in Zig

Native macOS and Linux implementation for Zig **0.17.0**, usable as the `dotlocal` module or the `dotlocal` CLI. Application logic, demo servers, integration fixtures and benchmark drivers are Zig.

## Build and validate

```sh
./zig/scripts/bootstrap-deps
zig build -Doptimize=ReleaseSafe
zig build test
zig build integration
zig build example
zig build bench -Doptimize=ReleaseSafe
zig fmt --check build.zig zig
zig build run -- help
```

Bootstrap builds checksum-pinned OpenSSL **4.0.3** and nghttp2 **1.70.0** into the ignored `.zig-deps` directory. Requirements are a C development toolchain, make, Perl, curl, shasum and tar on macOS or Linux. TLS certificate creation and TLS server support require OpenSSL; HTTP/2 framing, HPACK and flow control require nghttp2. OpenSSL is Apache-2.0; nghttp2 is MIT. The libraries are linked statically. No native libraries are installed globally.

For an existing installation, use `zig build -Ddeps=/absolute/prefix`. Consumers can pass the same `deps` option to `b.dependency`. The prefix must contain the matching architecture's `include` and `lib` directories. Windows is not implemented.

`zig build integration` builds native Zig servers and protocol clients. It also uses curl with HTTP/2 support, the OpenSSL CLI and npm for optional package-helper contract checks. It creates real private directories, sockets, certificates and child processes. It does not install a service, change system trust or edit `/etc/hosts`. Generic server execution needs no package manager.

## CLI

### Linux

The library, foreground daemon, user proxy, process supervision and transport
suite run on Linux. `init`, launchd installation and System-keychain trust are
macOS-specific. Linux authenticates management clients with kernel peer
credentials and group membership, and process owners with `/proc` start times.

For normal URLs without ports, run the daemon under your Linux service manager
with permission to bind 80/443. For example, in an administrator terminal:

```sh
sudo ./zig-out/bin/dotlocal daemon \
  --state-dir /var/lib/dotlocal \
  --management-socket /run/dotlocal.sock --management-group users \
  --dual-loopback --redirect-listen 127.0.0.1:80
```

Select a real group containing the permitted local users. Keep state private;
export only its public CA for clients and configure system/browser trust using
your distribution's trust tools. In another terminal:

```sh
sudo install -m 644 /var/lib/dotlocal/pki/ca.pem /usr/local/share/dotlocal-ca.pem
export DOTLOCAL_SOCKET=/run/dotlocal.sock
./zig-out/bin/dotlocal demo ./zig-out/bin/dotlocal-demo
```

Apply registered names with the explicit hosts operation or configure local DNS.
Clients can verify `https://demo.local` with the exported CA. Ordinary applications
and route operations run as the permitted user. For isolated unprivileged tests,
`dotlocal proxy start --port 1355 --no-tls` explicitly selects a user proxy with
URLs such as `http://demo.local:1355`.

### macOS

Initialize once, then run an ordinary server command:

```sh
./zig-out/bin/dotlocal init
./zig-out/bin/dotlocal myapp ./my-server
# -> https://myapp.local
./zig-out/bin/dotlocal run --name api -- ./api-server
./zig-out/bin/dotlocal alias dashboard 3000
./zig-out/bin/dotlocal get dashboard
./zig-out/bin/dotlocal list
```

The default suffix is `.local`. Configure local DNS or run `hosts sync` to inspect the current names and explicitly apply them with `sudo dotlocal hosts sync --apply`. The operation preserves unrelated hosts entries; repeat it when registered names change.

The normal proxy uses HTTPS 443 and HTTP 80 redirects, so public URLs contain no
port. `init` installs the shared local service and trusts its CA when necessary.
Application commands run as the ordinary user. A missing default proxy triggers
first-run setup in an interactive terminal; without a terminal, the CLI prints
the setup command. It does not silently switch to a URL containing a port.

The routing core accepts any validated HTTP/HTTPS upstream. Direct argv execution
and the `PORT`, `HOST`, and `DOTLOCAL_URL` environment contract work independently
of JavaScript, package managers, frameworks, or containers. Servers that ignore
`PORT` can use explicit arguments or an alias to their existing listening port.

For a reusable project command, create `dotlocal.json`:

```json
{"name":"demo","command":["./my-server"]}
```

Running bare `dotlocal` executes this command. Optional JavaScript conveniences
can resolve a package's `dev` or `--script` entry, infer its package name, discover
workspaces, and supply missing flags for frameworks that ignore `PORT`. They do
not add a runtime dependency to generic server execution. Linked git worktrees
receive a branch prefix to avoid collisions.

### Background apps

```sh
dotlocal start api ./api-server
dotlocal start                    # Current project's configured command/workspace
dotlocal run --background --name web python3 server.py
dotlocal stop api                 # Also accepts the full registered hostname
```

The detached supervisor and app run as the invoking user with no controlling terminal. Standard input is disconnected; output goes to a private log whose path is printed at startup. Proxied apps must begin listening on their assigned TCP port within 30 seconds. Startup errors and interruption clean up the new app; duplicate names preserve the existing app unless `--force` is explicit. This checks TCP listening readiness, not application health.

`stop NAME` checks the stored PID, kernel start time, UID and process group before signaling. It allows five seconds for graceful exit before escalating to SIGKILL, then waits for owned-route cleanup. It can stop foreground or background tracked apps without stopping the shared proxy or independently started apps. Aliases and untracked processes are not stopped. Workspace packages share a supervisor and failure/shutdown scope; stopping one package stops that workspace. Apps survive terminal closure, with no automatic reboot startup or crash restart. Keep the printed log path for `tail -f` and remove old launch logs when no longer needed.

`DOTLOCAL_RUNNER_STATE` selects an absolute private runner-state directory. The
default is `$HOME/.dotlocal/zig-runners`. Parent symlinks are rejected for private
state: use canonical `/private/tmp` paths on macOS. CLI flags override project
configuration. `DOTLOCAL=0` executes the command directly without proxy routing.

Alternate listener ports are explicit development/testing options:

```sh
./zig-out/bin/dotlocal proxy start --port 1355 --no-tls
# This profile deliberately produces URLs containing :1355.
```

Foreground HTTPS profiles export their public CA at `STATE/pki/ca.pem`; clients
can explicitly trust that file for a request. Foreground startup never installs
system trust. `--cert /absolute/cert.pem --key /absolute/key.pem` selects existing
certificate material. Keys must be private regular files. Unregistered SNI names
are rejected before HTTP routing.

`init` installs through the fixed `/usr/bin/sudo` boundary when reconciliation is necessary. `uninstall`, trust changes and `hosts --apply` require an already-privileged process. Ordinary routes, child execution and runtime adapters never invoke sudo. `init`, `install`, `upgrade` and `service install` run as your user go through the same path: they forward your update settings (`auto_update`, `channel`, `pin`) and reinstall when the service's differ. Run as root without `--update-channel`, `--update-pin` or `--no-auto-update`, they keep the installed service's update settings. A newer installed service binary is never replaced by an older CLI unless `--force` is given or your settings pin exactly the CLI's version (after `dotlocal update --version X`, `dotlocal init` rolls the service back). The installed service layout is:

- Label: `com.euforicio.dotlocal-zig`
- Binary: `/usr/local/libexec/dotlocal-zig`
- Socket: `/var/run/dotlocal-zig/management.sock`
- State: `/Library/Application Support/dotlocal-zig`
- Public CA: `/usr/local/share/dotlocal-zig/ca.pem`

The launchd job restarts after failures. A clean SIGTERM exit stays stopped until an explicit start; `proxy stop` therefore does not immediately restart it.

Default installed listeners are IPv4/IPv6 loopback HTTPS 443 and HTTP 80 redirects. Custom profiles use one loopback listener. `--dual-loopback` explicitly enables the matching IPv6 listener; `--redirect-listen` selects a method-preserving HTTPS redirect listener. Repeat `--tld` to serve several DNS suffixes; the first determines the primary URL. Generated certificates support registered wildcard routes. Profiles persist in `zig-profile.json`. Incompatible restarts fail closed. Explicit profile reconciliation requires private owned state and no remaining routes. Custom DNS suffixes also require local name resolution; `hosts sync` produces a plan for explicit application.

The default management group is `admin`; pass an existing dedicated group for non-admin operators. Installation compares artifact content and modes and checks the live authenticated daemon before returning unchanged. A loaded but unhealthy job is reconciled through `bootout`, `bootstrap`, `enable`, and `kickstart`. Trust inspection compares exact certificate DER in `/Library/Keychains/System.keychain`; login-keychain trust and matching common names do not satisfy it. Switching to HTTP or file certificates removes only the matching owned generated-CA export and exact System certificate, while retaining private CA state. Uninstall also removes that trust/export and the owned socket while retaining state, private certificates, and logs.

Read-only service tests use native `plutil`, `launchctl print`, fresh P-256 roots, and actual System-keychain certificate exports. The isolated privileged lifecycle gate is compiled but has not run: non-interactive sudo was unavailable. It requires an explicit confirmation and a rebuilt CLI, refuses pre-existing targets, uses a PID-qualified service label and separate state/runtime/log/binary/export paths with an ephemeral loopback port, and performs exact cleanup on success or failure. It verifies idempotent installation, mode repair, generated/HTTP/file-certificate profile switches, retained CA state, and uninstall. Run it only on a disposable macOS runner:

```sh
zig build -Doptimize=ReleaseSafe
gate_dir=$(mktemp -d /private/tmp/dotlocal-zig-service-gate.XXXXXX)
zig translate-c -I .zig-deps/include zig/src/native.h > "$gate_dir/native.zig"
zig test -OReleaseSafe -lc -lssl -lcrypto -lnghttp2 \
  -L .zig-deps/lib -I .zig-deps/include --dep native \
  -Mroot=zig/root.zig -Mnative="$gate_dir/native.zig" \
  --test-filter 'isolated privileged service' --test-no-exec \
  -femit-bin="$gate_dir/service-test"
sudo env DOTLOCAL_ZIG_SERVICE_TEST=RUN-PRIVILEGED-DOTLOCAL-ZIG \
  DOTLOCAL_ZIG_SERVICE_BINARY="$(pwd)/zig-out/bin/dotlocal" \
  "$gate_dir/service-test"
rm -rf "$gate_dir"
```

### Updates and user configuration

`~/.dotlocal/config.json` holds user defaults. Every key is optional; unknown
keys and invalid values are rejected, and the file must be a private regular
file owned by you. Precedence: command flag > `DOTLOCAL_*` environment > user
config > built-in default. Processes running as root never read it.

| Key | Environment | Value |
| :--- | :--- | :--- |
| `auto_update` | `DOTLOCAL_AUTO_UPDATE` | `true` (default) or `false` |
| `channel` | `DOTLOCAL_CHANNEL` | `stable` (default) or `nightly` |
| `pin` | `DOTLOCAL_PIN` | semantic version; disables automatic updates |
| `tld`, `port`, `https`, `wildcard` | `DOTLOCAL_TLD`, `DOTLOCAL_PORT`, ... | proxy profile defaults |
| `lan`, `lan_ip`, `tailscale`, `funnel`, `ngrok` | `DOTLOCAL_LAN`, ... | sharing defaults |
| `state_dir`, `runner_state`, `socket` | `DOTLOCAL_STATE_DIR`, ... | absolute paths |

```sh
dotlocal config                      # print the file
dotlocal config get channel
dotlocal config set auto_update false
dotlocal config unset pin
```

`dotlocal update [--check] [--channel stable|nightly] [--version X]` checks the
signed channel manifest and installs now. `--check` only reports. `--channel`
installs that channel's newest release and records the channel. `--version X`
installs a release still listed in the manifest (stable unless `--channel` is
given), which may be older, and pins it; a plain `dotlocal update` clears the pin.
Each update verifies the manifest's Ed25519 signature and the archive's SHA-256,
checks the new binary's reported version, then atomically replaces the running
executable.

Automatic updates run at most once a day: after an ordinary command finishes, a
detached check installs any newer release and the next command prints a
one-line notice; three consecutive failures print a warning. No automatic
check runs when `auto_update` is false, a version is pinned, the binary is a
development build (`0.0.0-dev`, built without `-Dversion`), the command runs as
root, or the executable's directory is not owned by you or is group/world-writable. `update`
and `config` refuse to run as root (`RunWithoutSudo`) and `update` refuses
development builds. Executables under `/opt/homebrew/`, a Homebrew `Cellar`,
`/usr/local/Homebrew/`, `/home/linuxbrew/` or `/nix/store/` are left to their
package manager.

The installed service carries its own update settings as daemon arguments:
`--update-channel stable|nightly`, `--update-pin X` and `--no-auto-update`.
`service install` captures them from your settings as described above; a pin or
`--no-auto-update` disables the daemon updater. The daemon checks 60 seconds
after start and then daily, installs over `/usr/local/libexec/dotlocal-zig`,
drains like a normal stop and exits with status 75 so launchd starts the new
binary. User proxies started with `proxy start` and foreground daemons without
`--update-channel` never update themselves.

Releases are published to this repository's GitHub Releases by
`.github/workflows/release.yml`, using the built-in `GITHUB_TOKEN` and a single
`DOTLOCAL_SIGNING_KEY` secret. Without that secret, scheduled nightly runs exit
cleanly with a notice while tag pushes and manual runs fail. Pushing a `v*` tag on `main` publishes a stable
release; a daily scheduled run publishes a nightly from `main` after CI passes.
Signed channel manifests (`stable.json`, `nightly.json` and their `.sig` files)
live at the root of the orphan `channels` branch. The stable channel
keeps the two newest releases for rollback (older releases are deleted but
their tags remain) and nightly keeps one; recover from
two bad stable releases by tagging known-good code as a new, higher version.
`release/public-key` lists trusted Ed25519 public keys, one base64 key per line.
To rotate the signing key: add the new public key as a second line and ship a
release signed with the old key; once that release is current, replace the
`DOTLOCAL_SIGNING_KEY` secret with the new seed (the release workflow checks
that it pairs with a listed key before creating a release); remove the old
line in a later release.

## Explicit sharing and adapters

```sh
dotlocal run --name api --lan -- ./api-server
dotlocal run --name api --lan --https --ip 192.168.1.20 -- ./api-server
dotlocal run --name api --tailscale -- ./api-server
dotlocal run --name api --funnel -- ./api-server
dotlocal run --name api --ngrok -- ./api-server
dotlocal add app --container sample-app --container-cli /opt/homebrew/bin/container --port 80
dotlocal prune
dotlocal clean --routes --yes
dotlocal hosts sync              # read-only plan
```

LAN binds one eligible literal interface address on an ephemeral port and advertises an exact `.local` name through the real `dns-sd` CLI. HTTP/1, streaming HTTP/2 and WebSockets are supported. LAN HTTPS creates a separate user-owned CA and prints its public path for client trust. Loss of the selected address withdraws the advertisement. An unpinned session selects another eligible address and republishes after readiness; a pinned session reports an error. The original CA remains stable across address changes, and the sharing journal tracks each owned advertisement child.

Tailscale Serve/Funnel require live capabilities and allocate one unused root-mounted registration. Cleanup checks the exact host, port, target and exposure mode. A private journal ties sharing to the runner and supervisor process identities; normal shutdown cleans it, and `prune` reconciles stale journals after a crash. `clean --routes --yes` rejects live sharing sessions; stop their owning runners first. LAN and Tailscale/Funnel are mutually exclusive per run. `--https`/`--ip` require `--lan`; configuration files cannot enable sharing.

Apple Container is optional and only called for explicitly registered container routes. The daemon refreshes its own validated metadata in the registration owner's login context. Local processes and published IP/port endpoints from other runtimes use the same core.

## Library

The public entry point is `zig/root.zig`; the build exports module `dotlocal`. The main types are:

- `routes.Table`: validated host/port registry, exact lookup, registered-parent resolution and atomic whole-table replacement.
- `profile.Config`: loopback listener, namespace, TLS and public origin policy.
- `registry.Registry`: serialized mutations, exclusive state-directory lifetime lock, durable atomic snapshots and owner compare-and-set.
- `client.Client`: authenticated protocol-v2 Unix socket calls.
- `daemon.Runtime`: HTTP/TLS/HTTP2/WebSocket listeners with explicit cancellation.
- `runner.Process`, `runner.Manager`, `runner.run`: direct children and durable ownership.
- `pki.Authority`, `lan.Session`, `sharing.Session`: explicit certificate/exposure lifetimes.
- `applecontainer`, `applecredential`, `tailscale`, `ngrok`, `mdns`, `hosts`, `service`: optional native adapters.

```zig
const std = @import("std");
const dotlocal = @import("dotlocal");

var table = try dotlocal.routes.Table.init(allocator, ".local", false);
defer table.deinit();
try table.set(.{ .name = "app.local", .host = "127.0.0.1", .port = 3000 });
const route = (try table.resolve(allocator, "app.local:443")).?;
defer route.deinit(allocator);
```

In a consuming build:

```zig
const dependency = b.dependency("dotlocal", .{
    .target = target,
    .optimize = optimize,
    .deps = "/absolute/native-library-prefix",
});
exe.root_module.addImport("dotlocal", dependency.module("dotlocal"));
```

Add this package as a local path or checksum-pinned dependency in the consumer's `build.zig.zon`. A separate local dependency consumer was also built and executed through `b.dependency`. `zig/examples/embedded.zig` is an independently compiled library consumer that runs a foreground HTTP daemon until stdin receives a newline:

```sh
./zig-out/bin/embedded-dotlocal /absolute/state /absolute/management.sock 127.0.0.1:8080
```

Generated authorities persist private `root.pem` and exact-host `leaf/*.pem` bundles. Private artifacts are owner-only regular files. Public `ca.pem` exports use mode 0644 even under launchd’s restrictive umask. `pki.Authority` accepts namespace, lifetime, renewal and cache bounds; `prepareRootRotation`, `activateRoot` and `finalizeRootRotation` stage a SHA-256-confirmed issuer change and retain the previous public root. The caller owns trust sequencing and must coordinate separate processes that share a library authority directory. The daemon already holds an exclusive registry lock for its state.

Functions take explicit allocators and `std.Io` where applicable. Returned routes/snapshots are owned copies; release routes with `Route.deinit(allocator)`, parsed client responses with `.deinit()`, and snapshots with their documented deinitializer. `routes.Table` requires external synchronization. `registry.Registry` and `daemon.Runtime` synchronize shared mutations. A running runtime needs a thread-safe allocator and valid borrowed configuration slices until `deinit`. Pass a cancellation atomic to `Runtime.run`, set it before teardown, and call `deinit` to drain listeners and release certificates. `runner.run` installs process-wide signal forwarding and explicitly rejects concurrent signal-forwarding supervisors in the same process; lower-level `runner.start` exposes caller-managed supervision.

## Verified behavior and remaining gates

Automated checks cover private route validation, exact/wildcard policy, owner compare-and-set, real durable files, strict wire fields, process identity/group checks, signal escalation, busy/dynamic ports, project configuration, live adapter capability checks, launchd parsing, strict TLS, HTTPS upstream verification, HTTP/1 streaming, redirects, real WebSocket frames, HTTP/2 large uploads/downloads and SSE, IPv6 loopback, custom profiles, secure restart.

Validation commands cover Debug and ReleaseSafe builds, real socket and certificate tests, full HTTP/TLS integration, and a separate `b.dependency` consumer. Optional integration gates report explicit skips when their native prerequisite or opt-in is absent.

Real LAN HTTPS over HTTP/1 and HTTP/2, exact Host/SNI validation, mDNS advertisement, listener polling and owned-child cleanup passed. Rebinding retained the port and CA and updated the exact advertising-child journal; journal failure withdrew the replacement. The running Apple Container adapter gate also passed.

Default privileged launchd installation and exact System CA trust have been verified with the browser demo at `https://demo.local`, HTTP 80 redirects and IPv4/IPv6 HTTPS 443. On Linux, a root foreground daemon on 80/443 serves an ordinary user's child over strict HTTPS/HTTP2 with HTTP redirects; Linux service installation and trust automation are not provided. The isolated full service lifecycle and root-to-login-user container credential transition are not covered by the automated suite. Tailscale capability/plan checks and idempotent cleanup run against the installed CLI; applying live Serve/Funnel exposure is a manual gate. Actual interface loss is not forced.

For explicit live gates:

```sh
DOTLOCAL_ZIG_CONTAINER_TEST=sample-app DOTLOCAL_ZIG_CONTAINER_PORT=80 zig build test
DOTLOCAL_ZIG_LAN_TEST=1 zig build test
```

The LAN tests use only the test's uniquely named advertisement and an ephemeral listener. On macOS, an enabled application firewall may require incoming-network approval for a newly built test executable; running a test executable that is already allowed avoids the prompt. They do not change the firewall or trust settings. HTTP/2 extended-CONNECT WebSockets bridge to real HTTP/1 upgrade backends, including verified HTTPS backends. Ordinary CONNECT requests receive 405. Private state is owned by dotlocal; internal files are not a migration contract.

Ngrok requires a configured installed CLI. Its public URL reaches the child before execution and its tunnel is removed on shutdown. Installed-CLI preflight is tested; opening a public tunnel requires the explicit `DOTLOCAL_ZIG_NGROK_TEST=RUN-PUBLIC-NGROK` gate and has not been executed. Native workspace supervision is implemented; Turbo-specific graph, cache and environment orchestration remains an optional JavaScript convenience gap.

## Benchmarks

`zig build bench -Doptimize=ReleaseSafe` runs five samples for route lookup, strict protocol parsing and serialization, HTTP header framing, durable CAS/fsync at 1/100/1024 routes, real certificate issuance/eviction and cached material loading. A native Zig server then serves a 77,824-byte payload for 100 requests each over HTTP/1, HTTPS/1 and HTTPS/2. Each sample batches 20 URLs in one curl process and verifies every negotiated protocol and payload size. Core and network measurements run sequentially. Results include server and client costs and are not production capacity guarantees.
