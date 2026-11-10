# Release process

## Workflows

| Workflow | Trigger | Output |
|---|---|---|
| `ci.yml` | pushes/PRs to `develop` and `main` | fmt, clippy, tests |
| `build.yml` | pushes to `develop`/`main`, manual, called by Release | platform artifacts |
| `release.yml` | `v*` tags (and manual build) | GitHub Release with checksums |

`build.yml` builds on native runners:

| Artifact | Runner | Format |
|---|---|---|
| `macos-arm64` | `macos-15` | `.app` in a `.zip` |
| `macos-x64` | `macos-15-intel` | `.app` in a `.zip` |
| `windows-x64` | `windows-2022` | portable `.exe` in a `.zip` |
| `windows-arm64` | `windows-11-arm` | portable ARM64 `.exe` in a `.zip` |
| `linux-x64` | `ubuntu-24.04` | binary in a `.tar.gz` |

Branch builds also run the packaged binary with `--self-test` before uploading.
On `develop`, a rolling prerelease named **Development build** (tag
`develop-latest`) is updated with the latest artifacts. Its files use the
`-develop` channel suffix.

## Artifact names

Tagged release (`v0.1.0`):

```
pfx-pem-0.1.0-macos-arm64.zip
pfx-pem-0.1.0-macos-x64.zip
pfx-pem-0.1.0-windows-x64.zip
pfx-pem-0.1.0-windows-arm64.zip
pfx-pem-0.1.0-linux-x64.tar.gz
SHA256SUMS
```

Branch builds add `-develop` or `-main` before the platform name. This keeps
release assets and snapshot assets from colliding.

## Cutting a release

1. Make sure `develop` is green and `main` is up to date.
2. Bump `version` in `Cargo.toml` (for example `0.1.0` → `0.2.0`).
3. Run the checks locally:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo run --release -- --self-test
   ```
4. Commit, merge to `develop`, then merge `develop` into `main`.
5. Create an annotated tag on `main` and push it:
   ```bash
   git tag -a v0.2.0 -m "PFX PEM Converter 0.2.0"
   git push origin v0.2.0
   ```
6. Watch the **Release** workflow. It validates that the tag matches
   `Cargo.toml`, builds all four artifacts, writes `SHA256SUMS`, and publishes
   the release.
7. Download one artifact and verify:
   ```bash
   shasum -a 256 -c SHA256SUMS
   ```
8. Run the smoke test on at least one platform:
   ```bash
   ./pfx-pem --self-test
   ```

Tags containing a hyphen (for example `v0.2.0-rc.1`) are published as
prereleases.

## Manual QA checklist

Before announcing a release:

- [ ] PFX → PEM with an RSA PFX from Windows.
- [ ] PFX → PEM with an EC PFX.
- [ ] PFX → PEM with a chain; confirm leaf → intermediate → root order.
- [ ] PEM → PFX, then import the PFX into Windows Certificate Manager.
- [ ] PEM → PFX in **Paste PEM** mode using clipboard content.
- [ ] Copy key/cert/chain from the PFX → PEM result and paste into a text editor.
- [ ] Auto/Light/Dark theme switch on each platform.
- [ ] Windows ARM64 build starts and self-tests on a Windows-on-ARM runner.
- [ ] Wrong password shows a clear error.
- [ ] Output folder with existing files is not overwritten.
- [ ] Drag and drop works on each platform.
- [ ] macOS app opens after right-click → Open (and `xattr` fallback).
- [ ] Windows SmartScreen path is documented.
- [ ] Linux binary starts on a clean desktop.
- [ ] `SHA256SUMS` verifies.

## Code signing

Builds are intentionally unsigned for now:

- **macOS:** ad-hoc signed (`codesign -s -`) but not Developer ID signed or
  notarized. Users may need right-click → Open or to clear the quarantine flag.
- **Windows:** no Authenticode signature. SmartScreen may warn.
- **Linux:** checksums only.

If signing is added later, secrets belong in GitHub Actions secrets. Never
commit certificates, passwords, or API keys.

## Linux compatibility

Artifacts are built on Ubuntu 24.04, so they require glibc 2.39+. The binary
still needs a working desktop/OpenGL stack at runtime; it does not bundle
Mesa. For older distributions, build from source or use a newer container.

## Reproducing locally

```bash
cargo build --release
./target/release/pfx-pem --self-test

# macOS (native arch)
bash scripts/package-macos.sh aarch64-apple-darwin 0.1.0 "" dist

# Linux
bash scripts/package-linux.sh x86_64-unknown-linux-gnu 0.1.0 "" dist

# Windows (PowerShell)
./scripts/package-windows.ps1 -Version 0.1.0 -OutDir dist
```
