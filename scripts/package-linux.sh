#!/usr/bin/env bash
#
# Package a Linux build as a portable tarball.
#
# Usage: scripts/package-linux.sh <target> <version> [channel] [out-dir]
# Example: scripts/package-linux.sh x86_64-unknown-linux-gnu 0.1.0 "" dist
#
set -euo pipefail

target="${1:?usage: package-linux.sh <target> <version> [channel] [out-dir]}"
version="${2:?version required}"
channel="${3:-}"
out_dir="${4:-dist}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$target" in
    x86_64-unknown-linux-gnu) arch="x64" ;;
    aarch64-unknown-linux-gnu) arch="arm64" ;;
    *)
        echo "unsupported Linux target: $target" >&2
        exit 1
        ;;
esac

binary="$root/target/$target/release/pfx-pem"
if [[ ! -x "$binary" ]]; then
    echo "missing release binary: $binary" >&2
    exit 1
fi

stage_name="pfx-pem-$version$channel-linux-$arch"
stage="$root/target/package/$stage_name"

rm -rf "$stage"
mkdir -p "$stage" "$root/$out_dir"

cp "$binary" "$stage/pfx-pem"
chmod +x "$stage/pfx-pem"

# Smaller binary; symbols are not needed in the portable archive.
if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$stage/pfx-pem" || true
fi

cp "$root/LICENSE" "$stage/LICENSE.txt"
cp "$root/THIRD_PARTY.md" "$stage/THIRD_PARTY.md"
cp "$root/LICENSES/OpenSSL.txt" "$stage/OpenSSL-LICENSE.txt"

cat > "$stage/README.txt" <<README
PFX ↔ PEM Converter $version — Linux $arch
================================================

Run the application from this folder:

    ./pfx-pem

It needs a normal desktop session with OpenGL (X11 or Wayland). There is no
system OpenSSL or GTK/WebKit dependency; OpenSSL is bundled in the binary.

This build was produced on Ubuntu 24.04 and needs glibc 2.39 or newer. Build
from source on older distributions if necessary.

The application works fully offline. No installer and no root access needed.

More information and checksums:
https://github.com/mcipovic/pfx-pem-converter/releases
README

tar -C "$root/target/package" -czf "$root/$out_dir/$stage_name.tar.gz" "$stage_name"

echo "created $out_dir/$stage_name.tar.gz"
