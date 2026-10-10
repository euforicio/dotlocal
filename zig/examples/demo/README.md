# Live demo

This compiled Zig server runs as a child of the Zig CLI. dotlocal
selects its internal listening port, injects `PORT`, `HOST`, and `DOTLOCAL_URL`,
and registers `demo.local`. Users open **https://demo.local** without
specifying a port. The proxy listens on loopback HTTPS 443 and redirects HTTP 80.

Build and initialize once on macOS from the repository root:

```sh
zig build -Doptimize=ReleaseSafe
./zig-out/bin/dotlocal init
```

Initialization requests administrator authentication only when installation or
reconciliation is necessary. It installs the local service and trusts its CA.
The app itself runs as your ordinary user:

```sh
cd zig/examples/demo
../../../zig-out/bin/dotlocal
```

After the route registers, configure local DNS or run this in a second terminal
from the repository root:

```sh
./zig-out/bin/dotlocal hosts sync
sudo ./zig-out/bin/dotlocal hosts sync --apply
```

Open <https://demo.local> and click **Send another request**. Stop the app
with Ctrl-C; the shared proxy remains available for other apps.

To keep it running after closing the terminal, use `../../../zig-out/bin/dotlocal start` instead. Stop it later with `../../../zig-out/bin/dotlocal stop demo`.

The demo response contains only its public URL and proxy routing headers. It
does not expose process IDs, internal ports, filesystem paths or environment
contents. Diagnostic echo endpoints belong to the separate test fixture.

The server could equally be Go, Zig, Rust, Java, or another HTTP implementation.
`dotlocal.json` uses a direct argv vector and requires no JavaScript runtime or
package manager. Servers that ignore `PORT` can be registered with an explicit
upstream address using `dotlocal alias`.

Explicit alternate proxy ports remain available for isolated development and
automated tests, but they are not the normal user-facing setup.

On Linux, build the same `dotlocal-demo` executable and use a running foreground
daemon or user proxy as described in the [Linux guide](../../README.md#linux).
