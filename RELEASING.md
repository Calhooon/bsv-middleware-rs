# Releasing bsv-middleware-rs

1. Every change lands through a PR to `main`; nothing is pushed to `main` directly.
2. The PR is green on the four required checks: `test`, `fmt`, `clippy`, `vectors`.
3. The release PR sets `version` in `Cargo.toml` and the `CHANGELOG.md` heading.
4. Merge by rebase (linear history); the owner's account merges its own PR.
5. Tag the merge commit on `main`: `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. `.github/workflows/release.yml` checks the tag against `Cargo.toml`, reruns the checks, and publishes.
7. Nothing publishes from a laptop; no crates.io token is stored anywhere.
8. crates.io Trusted Publishing names owner `Calhooon`, repository `bsv-middleware-rs`, workflow `release.yml`, no environment.
