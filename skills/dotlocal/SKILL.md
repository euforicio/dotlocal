---
name: dotlocal
description: Run and verify local servers at stable .local HTTPS URLs using the native dotlocal CLI and shared local service. Use for app previews, named routes, or attaching an existing server.
---

# dotlocal

Use the same **`https://<name>.local`** URLs as developers: HTTPS on 443,
with HTTP on 80 redirecting to HTTPS. Internal app ports are implementation
details. Reuse the shared dotlocal service. Alternate suffixes, HTTP profiles,
and public ports require an explicit user request; do not select them as an
agent-specific default or silently fall back when setup is missing.

## Use the CLI as the operational entry point

Run the existing `dotlocal` executable for setup, route registration, app
supervision, status, diagnosis, and cleanup. The CLI uses the shared Zig library
and daemon; this skill adds instructions only. Keep profile selection, port
allocation, hostname/worktree handling, child environment, ownership checks,
certificates, and lifecycle behavior in those existing code paths.

Use the CLI's defaults and reported configuration and URLs. Do not implement
another proxy, launcher, management client, certificate generator, or direct
state-file writer in skill/plugin scripts. Use `curl` and the browser only to
verify the application's public endpoint; manage dotlocal through its CLI.

## Prepare the shared service

Find `dotlocal` with `command -v dotlocal`, or use an absolute path to the
checkout's `zig-out/bin/dotlocal`. Read `dotlocal help` and `dotlocal version`
when the available build is uncertain. This skill supplies instructions, not
an executable. If building from source, read its `AGENTS.md`, then run:

```sh
./zig/scripts/bootstrap-deps
zig build -Doptimize=ReleaseSafe
```

Use Zig 0.17.0. Bootstrap needs a C development toolchain, make, Perl, curl,
shasum, and tar. Generic app execution requires no JavaScript or Python runtime.
Run the CLI and app where the browser/client can reach the shared loopback
listener; a remote guest's loopback is not the user's desktop loopback.

Check `dotlocal status`. The normal profile reports a running HTTPS listener
on 443 and `.local` as its primary suffix. Check task-local environment overrides
such as `DOTLOCAL_PORT`, `DOTLOCAL_HTTPS`, `DOTLOCAL_TLD`, `DOTLOCAL_SOCKET`, and
`DOTLOCAL_STATE_DIR`; remove stale temporary-profile overrides from this task's
commands when returning to the normal service. Preserve intentional user
configuration and the user's global shell settings. `DOTLOCAL=0`, `false`, or
`skip` bypasses routing; detect it before starting an app.

If normal setup is missing, explain the prerequisite and use the authorized
one-time setup. On macOS, `dotlocal init` installs the shared service and trusts
its CA, requesting administrator authentication when needed. Routine app and
route operations run as the ordinary user. On Linux, follow the checkout's
`zig/README.md` Linux guide for the caller-managed daemon, CA trust, and DNS.
Do not reconfigure an existing proxy with live routes to fix a profile mismatch.

`.local` requires local name resolution. Use configured DNS, or inspect
`dotlocal hosts sync` after registering names. Apply its plan with
`sudo dotlocal hosts sync --apply` only when the task authorizes hosts-file
changes. Do not claim a browser-ready URL until name resolution also works.

## Start or attach a server

For a server that honors `PORT` and `HOST`, keep its supervisor running in a
persistent terminal/tool session:

```sh
dotlocal run --name api -- ./api-server
```

The child receives `PORT`, `HOST=127.0.0.1`, and `DOTLOCAL_URL`. Preserve its
actual command and argument vector. For a server that needs a fixed port,
pass its real listening flag as well as `--app-port`:

```sh
dotlocal run --name api --app-port 3000 -- ./api-server --port 3000
```

`--app-port` describes the upstream; the public URL remains `https://api.local`.
For an already-running server, keep its process under its existing owner:

```sh
dotlocal alias api 3000
dotlocal get api
```

Use `dotlocal add api --host 127.0.0.1 --port 3000 --protocol https` for a
verified HTTPS upstream. No container or framework adapter is needed for an
ordinary host/port endpoint. Never replace another app's route with `--force`.

## Verify the actual .local URL

Read the supervisor's printed URL and `dotlocal list` / `dotlocal get NAME`.
Linked Git worktrees receive a branch prefix, such as `branch.api.local`.
Use that actual registered hostname, without an explicit port for the normal
HTTPS profile. Substitute a real app readiness path below:

```sh
curl --fail --silent --show-error --noproxy '*' https://api.local/
```

Keep TLS certificate verification enabled. If curl's trust store does not use
the installed system CA, pass `--cacert` with the service's public CA. The
standard macOS export is `/usr/local/share/dotlocal-zig/ca.pem`; caller-managed
daemons export `STATE/pki/ca.pem`. Never use a private key or disable verification.

To distinguish a DNS issue from a routing or upstream issue, retain the actual
hostname and TLS verification while explicitly connecting to loopback:

```sh
curl --fail --silent --show-error --noproxy '*' \
  --cacert /usr/local/share/dotlocal-zig/ca.pem \
  --resolve api.local:443:127.0.0.1 https://api.local/
```

This diagnostic does not prove system DNS works. Use bounded readiness retries,
verify the app's actual response, and report DNS, trust, or upstream failures
accurately. Route registration alone does not prove the app is ready. For
browser tasks, open the actual `.local` HTTPS URL and verify the requested flow.
Report that URL, keeping internal ports out of the user-facing URL.

## Cleanup and boundaries

Stop an owned app through its supervisor session (Ctrl-C or an identity-checked
SIGTERM) so its route and children drain. Remove an alias you created using its
actual name, for example `dotlocal alias --remove api`. Keep a requested live
preview running and report how to stop it.

Leave the shared proxy running. Do not invoke `proxy stop`, uninstall the
service, remove trust, perform broad route cleanup, or kill unrelated processes
when ending an app task. Shared hosts-file cleanup also requires checking other
routes and authorization; do not remove resolution needed by other apps.

Use `dotlocal status` and `dotlocal doctor` for diagnosis. Summarize errors
without publishing environment contents, private paths, logs, tokens, or
certificate keys. Management uses an authenticated Unix socket through the
CLI; the public HTTPS listener is not a management REST API. LAN/public exposure
requires an explicitly requested workflow.
