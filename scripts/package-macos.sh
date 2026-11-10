#!/usr/bin/env bash
#
# Package a macOS build as a zipped .app bundle.
#
# Usage: scripts/package-macos.sh <target> <version> [channel] [out-dir]
# Example: scripts/package-macos.sh aarch64-apple-darwin 0.1.0 "" dist
#
set -euo pipefail

target="${1:?usage: package-macos.sh <target> <version> [channel] [out-dir]}"
version="${2:?version required}"
channel="${3:-}"
out_dir="${4:-dist}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$target" in
    aarch64-apple-darwin) arch="arm64" ;;
    x86_64-apple-darwin) arch="x64" ;;
    *)
        echo "unsupported macOS target: $target" >&2
        exit 1
        ;;
esac

binary="$root/target/$target/release/pfx-pem"
if [[ ! -x "$binary" ]]; then
    echo "missing release binary: $binary" >&2
    exit 1
fi

stage_name="pfx-pem-$version$channel-macos-$arch"
stage="$root/target/package/$stage_name"
app="$stage/PFX PEM Converter.app"

rm -rf "$stage"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
mkdir -p "$root/$out_dir"

cp "$binary" "$app/Contents/MacOS/pfx-pem"
chmod +x "$app/Contents/MacOS/pfx-pem"

cp "$root/assets/icon.icns" "$app/Contents/Resources/icon.icns"
cp "$root/LICENSE" "$app/Contents/Resources/LICENSE.txt"
cp "$root/THIRD_PARTY.md" "$app/Contents/Resources/THIRD_PARTY.md"
cp "$root/LICENSES/OpenSSL.txt" "$app/Contents/Resources/OpenSSL-LICENSE.txt"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>PFX ↔ PEM</string>
    <key>CFBundleName</key>
    <string>PFX PEM Converter</string>
    <key>CFBundleExecutable</key>
    <string>pfx-pem</string>
    <key>CFBundleIdentifier</key>
    <string>me.mcipovic.pfxpem</string>
    <key>CFBundleIconFile</key>
    <string>icon.icns</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleVersion</key>
    <string>$version</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 Marko Cipovic</string>
</dict>
</plist>
PLIST

cat > "$stage/README.txt" <<README
PFX ↔ PEM Converter $version — macOS $arch
================================================

1. Drag "PFX PEM Converter.app" to your Applications folder.
2. The build is not notarized. On first launch, right-click the app and
   choose Open, or allow it in System Settings → Privacy & Security.

If macOS says the app is damaged, clear the download quarantine flag:

    xattr -dr com.apple.quarantine "/Applications/PFX PEM Converter.app"

The application works fully offline. It contains a static OpenSSL build and
has no runtime dependencies.

More information and checksums:
https://github.com/mcipovic/pfx-pem-converter/releases
README

# Ad-hoc signing keeps Apple Silicon happy and makes the bundle internally
# consistent. It is not Developer ID signing or notarization.
if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$app" >/dev/null
fi

mkdir -p "$root/target/package"
(
    cd "$root/target/package"
    rm -f "$root/$out_dir/$stage_name.zip"
    ditto -c -k --keepParent "$stage_name" "$root/$out_dir/$stage_name.zip"
)

echo "created $out_dir/$stage_name.zip"
