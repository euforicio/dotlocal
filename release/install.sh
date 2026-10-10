#!/bin/sh
# Install the latest dotlocal release:
#   curl -fsSL https://raw.githubusercontent.com/euforicio/dotlocal/main/release/install.sh | sh [-s -- --nightly]
set -eu
channel=stable
base=${DOTLOCAL_INSTALL_BASE:-https://raw.githubusercontent.com/euforicio/dotlocal/channels}
dir=${DOTLOCAL_INSTALL_DIR:-"$HOME/.local/bin"}
for arg in "$@"; do
    case "$arg" in
        --nightly) channel=nightly ;;
        --stable) channel=stable ;;
        *) echo "usage: install.sh [--stable|--nightly]" >&2; exit 2 ;;
    esac
done
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) target=aarch64-macos ;;
    Darwin-x86_64) target=x86_64-macos ;;
    Linux-aarch64 | Linux-arm64) target=aarch64-linux ;;
    Linux-x86_64) target=x86_64-linux ;;
    *) echo "dotlocal: unsupported platform $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --proto '=https' "$base/$channel.json" -o "$work/manifest.json"
# The manifest lists the newest release first. Put each release on its own
# line (awk, since sed newline escapes differ between BSD and GNU) and keep
# the first, then extract its version and this target's asset.
line=$(tr -d '\n' < "$work/manifest.json" | awk '{ gsub(/[}],[{]"version"/, "}\n{\"version\""); print }' | head -n 1)
version=$(printf '%s' "$line" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
asset=$(printf '%s' "$line" | sed -n "s/.*\"$target\":{\"url\":\"\([^\"]*\)\",\"sha256\":\"\([0-9a-f]\{64\}\)\"}.*/\1 \2/p")
[ -n "$version" ] && [ -n "$asset" ] || { echo "dotlocal: no $target build in the $channel channel" >&2; exit 1; }
url=${asset% *}
sum=${asset#* }
curl --fail --location --silent --show-error --proto '=https' "$url" -o "$work/dotlocal.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$work/dotlocal.tar.gz" | awk '{print $1}'); else actual=$(shasum -a 256 "$work/dotlocal.tar.gz" | awk '{print $1}'); fi
[ "$actual" = "$sum" ] || { echo "dotlocal: checksum mismatch" >&2; exit 1; }
tar -xzf "$work/dotlocal.tar.gz" -C "$work" dotlocal
[ "$("$work/dotlocal" version)" = "$version" ] || { echo "dotlocal: version mismatch" >&2; exit 1; }
mkdir -p "$dir"
cp "$work/dotlocal" "$dir/.dotlocal-install.$$"
chmod 0755 "$dir/.dotlocal-install.$$"
mv -f "$dir/.dotlocal-install.$$" "$dir/dotlocal"
# Record the channel so later self-updates follow it.
if [ "$channel" = nightly ]; then "$dir/dotlocal" config set channel nightly; else "$dir/dotlocal" config unset channel; fi
echo "Installed dotlocal $version ($channel) to $dir/dotlocal"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH: export PATH=\"$dir:\$PATH\"" ;; esac
