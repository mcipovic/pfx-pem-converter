# Contributing

## Branch model

```
feature/PFX-<issue>-<short-description>  ──▶  develop  ──▶  main
hotfix/PFX-<issue>-<short-description>   ──▶  main
chore/<short-description>                ──▶  develop
```

| Branch | Purpose | Direct pushes |
|---|---|---|
| `develop` | Integration; default branch | No — PR only |
| `main` | Released builds | No — PR only |
| `feature/PFX-<n>-...` | One issue/feature | Author |
| `hotfix/PFX-<n>-...` | Urgent fix from `main` | Author |
| `chore/...` | Infra/docs without an issue | Author |

Install the local `pre-push` guard once per clone:

```bash
./scripts/install-hooks.sh
```

It blocks direct pushes to `develop` and `main`. GitHub branch protection is
also recommended; the hook is a local safety net, not a replacement.

## Workflow

1. Open or pick an issue and note its number.
2. Branch from `develop`:
   ```bash
   git switch develop
   git pull
   git switch -c feature/PFX-12-example
   ```
3. Make small commits.
4. Run every check:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```
5. Push and open a PR into `develop`.
6. Squash-merge after green CI.

## Commit messages

- Imperative and capitalized.
- Short subject (≤ ~72 characters).
- Explain what and why, not "fix" or "wip".
- English or Montenegrin, consistent within a PR.

## Code rules

- Keep the conversion core (`src/lib.rs`) independent from the UI.
- Never write outputs before a conversion is fully validated.
- Never overwrite existing files.
- New behavior needs an integration test. Legacy/protocol edge cases are
  especially important.
- Do not log passwords or private key contents.
- Do not commit real certificates, keys, PFX files, or `.env` files.

## Pull request checklist

- [ ] Branch is based on `develop`.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo test` passes.
- [ ] `cargo run -- --self-test` passes.
- [ ] No secrets, keys, or personal certificates in the diff.
- [ ] README/docs updated if the user-facing behavior changed.

## Releases

Only maintainers tag releases. A `vX.Y.Z` tag must match the version in
`Cargo.toml`; the release workflow validates this and builds all platforms.
See [`docs/release.md`](docs/release.md).
