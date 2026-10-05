# CI and GitHub Releases

Push a `v*` tag matching the version in `Cargo.toml` to publish a GitHub Release. Tests and builds must pass before the workflow publishes it.

## Continuous integration

`.github/workflows/ci.yml` runs on branch pushes and pull requests. The release workflow runs the same checks for the tagged commit:

- Rust formatting (`cargo fmt --all -- --check`).
- Clippy for all Cargo targets, with warnings treated as errors.
- Unit, integration, and documentation tests on Linux x86_64, macOS Intel and Apple Silicon, and Windows x86_64.

Cargo commands use `--locked` to keep dependency versions from changing during CI. Both workflows use Rust 1.96, with build caches separated by job and target. When upgrading Rust, update the toolchain action references and inputs in both workflow files and rerun the checks.

To require CI before merging, add a branch protection rule or ruleset for your default branch. Require the formatting/Clippy check and all four test checks.

## Create a release

1. Update `version` in `Cargo.toml`, then run `cargo check` to refresh the root package entry in `Cargo.lock`. Commit both files with any release changes.
2. Push the commit and wait for branch CI to pass.
3. Tag that same commit with `v` followed by the exact package version:

   ```sh
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

   Replace `1.0.0` with your release version. For a prerelease, use a version such as `1.1.0-rc.1` and the tag `v1.1.0-rc.1`. GitHub marks it as a prerelease.

4. Open Actions → Release to follow the run. The workflow checks the tag against `Cargo.toml`, reruns CI, builds optimized binaries, and smoke-tests `--help` and `--version`.
5. Once every build passes, the workflow creates a draft release, uploads the assets, and publishes it with generated release notes.

The workflow uses the repository's built-in `GITHUB_TOKEN`; you don't need a personal access token or repository secret. Only the publishing job gets `contents: write`. Test and build jobs have read-only access. Enable GitHub Actions and check that your repository and organization policies allow the selected actions and release publishing.

Use a GitHub ruleset to restrict who can push `v*` tags. Release builds execute code from the tagged commit, so reserve that permission for trusted maintainers.

## Downloadable assets

Each archive contains the `ramenv` executable (`ramenv.exe` on Windows), `README.md`, `LICENSE`, and the Markdown files in `docs/`, including the cloud authentication guides. The workflow copies only those files, then packages them with `tar` on Linux/macOS or PowerShell `Compress-Archive` on Windows.

| Platform | Asset |
| --- | --- |
| Linux x86_64 | `ramenv-vVERSION-x86_64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `ramenv-vVERSION-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `ramenv-vVERSION-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `ramenv-vVERSION-x86_64-pc-windows-msvc.zip` |

The Linux binary is dynamically linked and built on Ubuntu 24.04. It requires a compatible Linux environment, including glibc 2.39 or newer. There is no static musl build. macOS and Windows binaries are unsigned and may trigger security prompts. The workflow does not sign or notarize them.

Download `SHA256SUMS` with your archive to check its checksum. On Linux:

```sh
sha256sum --ignore-missing --check SHA256SUMS
```

On macOS, compare `shasum -a 256 <archive>` with its entry. On Windows, use `Get-FileHash <archive> -Algorithm SHA256`. Checksums detect file corruption; they are not code signatures.

Extract the archive and put the executable in a directory on your `PATH`. macOS/Linux archives preserve executable permissions.

## Failed runs and retries

- Fix failed tests or builds before releasing. For a transient failure, rerun the job from Actions; don't bypass the checks.
- If uploading or publishing fails after a draft is created, delete the incomplete draft in GitHub Releases before rerunning the workflow. Leave the tag intact so the retry uses the same commit.
- `gh release create` fails if the release already exists, so rerunning a successful release won't overwrite it. Use a new version and tag for further changes. Don't move a published tag.

## crates.io

The workflow publishes to GitHub Releases only. To publish to crates.io, authenticate with crates.io and run these commands separately:

```sh
cargo publish --dry-run --locked
cargo publish --locked
```
