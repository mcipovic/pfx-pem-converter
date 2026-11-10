# Third-party components

This application is distributed as a single native executable with the
following third-party components linked or embedded into it.

## OpenSSL

- Version: 3.6.x (built from source at compile time with `openssl-src`)
- License: Apache License 2.0
- License text: [`LICENSES/OpenSSL.txt`](LICENSES/OpenSSL.txt)
- Project: <https://www.openssl.org/>

OpenSSL is linked statically. The `legacy` provider is enabled so old
RC2-protected PFX files can be read.

## Rust crates

The Rust dependency tree is recorded in [`Cargo.lock`](Cargo.lock). The direct
dependencies are:

| Crate | License |
|---|---|
| `eframe` / `egui` | MIT OR Apache-2.0 |
| `openssl` | Apache-2.0 |
| `arboard` | MIT OR Apache-2.0 |
| `rfd` | MIT |
| `thiserror` | MIT OR Apache-2.0 |

Transitive dependencies are predominantly MIT, Apache-2.0, BSD, ISC, or
Zlib-licensed. Run `cargo metadata` for the full resolved graph.

## DejaVu Sans

- Used only as a fallback font for symbols such as `↔` and `→`
- License: Bitstream Vera Fonts Copyright + Arev Fonts Copyright (permissive)
- License text: [`assets/fonts/LICENSE-DejaVu.txt`](assets/fonts/LICENSE-DejaVu.txt)
- Project: <https://dejavu-fonts.github.io/>

## Application icon

The application icon is original artwork created for this project and is
covered by the repository's MIT license.
