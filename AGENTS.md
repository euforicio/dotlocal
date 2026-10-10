# Repository instructions

Build a small, production-friendly Zig library and CLI named `dotlocal`. The routing core accepts validated HTTP/HTTPS host/port endpoints from any server language or runtime. Optional runtime and framework adapters are conveniences. Default names use `.local`, with loopback HTTPS 443 and HTTP 80 redirects.

- Use Zig 0.17.0 and its current allocator, std.Io and process APIs.
- Keep APIs small, ownership explicit and implementations easy to debug.
- Agent skills/plugins must invoke the existing CLI for operations. Keep proxying, certificates, naming, supervision and route ownership in the shared Zig library/CLI; do not add parallel implementations or direct management/state-file clients.
- Default listeners are loopback-only. LAN/tailnet/public exposure must be explicit and separately tested.
- Privilege is limited to explicit service installation, privileged listeners, trust and hosts-file operations. Ordinary route/container operations must not invoke sudo.
- Validate names, ports, paths, file ownership, process identities and container metadata at every boundary.
- Never mock or stub. Use real files, listeners, sockets, processes, certificates and native tool paths.
- Read applicable AGENTS.md files before editing. Preserve unrelated work.
- Do not mention assistants or automation in commit messages.
- Keep personal identities, machine paths, local application names, logs, screenshots, credentials and generated private state out of commits. Use GitHub's private commit email and generic examples.
- Delegate only substantial independent slices, without shared-file conflicts; keep final integration and validation local.

Run at minimum:

```sh
zig fmt --check build.zig zig
zig build test
zig build test integration example -Doptimize=ReleaseSafe
git diff --check
```

Use benchmarks when changing routing, parsing, certificate or network hot paths. Optional live native/exposure gates must report explicit skips when prerequisites or authorization are absent.
