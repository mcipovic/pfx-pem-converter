# Test fixtures

These files are **test-only** and must never be used for anything real.

- `legacy-rc2.pfx` — a self-signed RSA certificate encrypted with the legacy
  RC2-40 PKCS#12 profile, used to prove that the bundled OpenSSL legacy
  provider works in `--self-test` and in the integration tests.
- `test-key.pem` / `test-cert.pem` — the throwaway key and certificate inside
  that PFX.

Password: `test-password`

The files were generated with:

```bash
openssl req -x509 -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem \
  -days 36500 -nodes -subj "/CN=PFX PEM Self-Test/O=Test Only"
openssl pkcs12 -export -legacy -in test-cert.pem -inkey test-key.pem \
  -out legacy-rc2.pfx -passout pass:test-password -name "PFX PEM Self-Test"
```

The `.pfx` and `.pem` exceptions in `.gitignore` exist only for this folder.
