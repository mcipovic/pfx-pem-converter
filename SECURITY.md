# Security policy

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting on this repository:

<https://github.com/mcipovic/pfx-pem-converter/security/advisories/new>

Please include the affected version, platform, and a minimal reproduction.

## Scope

The application handles private keys and passwords, so reports about the
following are especially relevant:

- accidental private-key or password disclosure,
- output files with unsafe permissions,
- path handling that writes outside the selected folder,
- memory-safety or OpenSSL integration bugs,
- build or release artifacts that do not match the tagged source.

## Design notes

- All conversion happens locally. The app has no network code.
- Outputs are created with `create_new` and are never overwritten.
- Output files use mode `0600` on Unix.
- Passwords are not logged and are not written to disk.
- PFX files created by the app use 3DES/SHA-1 for broad compatibility; this is
  a deliberate compatibility trade-off, not a vulnerability by itself.
- Builds are not code-signed; verify `SHA256SUMS` from the release page.
