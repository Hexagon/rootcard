# rootcard: releasing

How a release is prepared, published and checked. **Agents prepare releases; only the owner publishes them**, by
publishing a GitHub release. Publishing is done by CI ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
with trusted publishing, never from a laptop and never with a registry token (AGENTS.md rule 6).

---

## 1. What a release is

- One version for everything: the crates `rootcard`, `rootcard-host` and `rootcard-cli` and the npm package `rootcard`
  are released together, in lockstep, with the same `MAJOR.MINOR.PATCH` (optionally `-rc.N`, `-alpha.N`, `-beta.N`).
- The git tag is `v` + the version (`v0.1.0`) on the release commit on `main`.
- Before `1.0.0`: a minor bump (`0.1 → 0.2`) for any breaking API change or any **format change** (SPEC §22); a patch
  bump for everything else. From `1.0.0`: semantic versioning, and a format change never removes the reading of `v: 1`.
- A version with a `-` is a pre-release: its GitHub release is marked pre-release, and npm publishes it under the `next`
  tag instead of `latest`.

## 2. One-time setup (owner)

1. **Names exist** (PLAN D2): trusted publishing can only be configured for packages that already exist, so the owner
   publishes the `0.0.0` placeholders once by hand.
2. **crates.io:** for each of the three crates, add a trusted publisher: repository `Hexagon/rootcard`, workflow
   `release.yml`, environment `release`.
3. **npm:** for `rootcard`, add a trusted publisher: GitHub Actions, repository `Hexagon/rootcard`, workflow
   `release.yml`, environment `release`. Then disallow token publishing in the package settings.
4. **GitHub:** create the environment `release` with the owner as required reviewer and deployments limited to tags
   `v*`. Protect `main` and the tag pattern `v*`.

No secret is added to the repository for any of this.

## 3. Preparing a release (agents)

An agent prepares a release only when the owner asks for one. Do exactly these steps, in one pull request that contains
nothing else.

1. **Start from a green `main`.** Fetch `main`, check that CI is green on it, and branch from it (use the branch you were
   given, otherwise `release/vX.Y.Z`). Read the open items of docs/PLAN.md: if one must land before this release (it says
   "before X.Y.Z", "before the release" or "before it is published"), tell the owner before continuing. 0.2.1 went out
   without the release-pipeline pins that were planned for it because nobody checked.
2. **Choose the version** by §1 from the changelogs' `Unreleased` sections. If any entry is a format change or breaking,
   say so in the pull request. If unsure between minor and patch, choose minor and ask.
3. **Bump the version** in all three places:
   - `Cargo.toml`: `[workspace.package] version` and the `version` of `rootcard` in `[workspace.dependencies]`;
   - `packages/rootcard/package.json`: `version`;
   - `Cargo.lock`: run `cargo update --workspace` (it changes only the workspace's own entries).
4. **Update the documents that name the version:** the status line of `README.md` (`Status: **X.Y.Z, ...**`) and, for a
   new minor (or major) version, the supported versions table of `SECURITY.md` (the new line `Yes`, the previous one
   `No`). `xtask repo-check`, which `release-check` runs, fails until both match. Then search the docs for the previous
   version number and fix any mention that is not history.
5. **Write the changelogs.** In each of the four `CHANGELOG.md` files, move the `Unreleased` entries under a new heading
   `## X.Y.Z - YYYY-MM-DD` (today's date, UTC) and leave an empty `## Unreleased` above it. A package without changes gets
   the line `No changes.` Entries describe user-visible changes; format changes say which structure and `v`.
6. **Run every check:**
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   (cd packages/rootcard && npm test)
   cargo run -p xtask -- release-check --tag vX.Y.Z     # versions, changelogs, tag, vectors, label registry, repo-check
   cargo publish --workspace --locked --dry-run         # packages every crate and builds it from its tarball
   (cd packages/rootcard && npm publish --dry-run)      # lists exactly the files that would be published
   ```
   Read the file lists of both dry runs: nothing outside `src/`, the README, the changelog and the license may be in them.
7. **Commit** as `Release vX.Y.Z` and open a pull request with the same title. Its description has the changelog
   entries, the result of every check above, and whether the release contains a format change.
8. **Stop.** Tell the owner the pull request is ready and that, after merging, they publish a GitHub release with tag
   `vX.Y.Z` on the merge commit (marked pre-release for a `-` version), using the changelog entries as release notes.

Agents never: create or push tags, create or publish GitHub releases, run `cargo publish` or `npm publish` without
`--dry-run`, add registry tokens or secrets, yank crates or deprecate npm versions, or edit the release workflow in a
release pull request.

## 4. What CI does on a published release

`.github/workflows/release.yml`, triggered by `release: published`:

1. **verify**: format, clippy, all tests, `xtask release-check --tag <tag>`, the pre-release flag matches the version,
   `cargo publish --dry-run` and `npm publish --dry-run`. Nothing is published if any step fails.
2. **crates** (environment `release`): a short-lived crates.io token from OIDC (`rust-lang/crates-io-auth-action`), then
   `cargo publish --workspace`, which publishes `rootcard` first and then the crates that depend on it.
3. **npm** (environment `release`): `npm publish --provenance` with trusted publishing; the package gets a provenance
   statement that links it to this workflow run and commit.
4. **assets**: builds the `.crate` files and the npm tarball from the tag and attaches them to the GitHub release with
   `SHA256SUMS`.

## 5. After the release

The owner, or an agent asked to check, confirms:

- the workflow run is green;
- the three crates show the new version on crates.io and their docs build on docs.rs;
- `npm view rootcard@X.Y.Z` shows the version, the `latest` or `next` tag as intended, and provenance
  (`npm audit signatures` in a project that installs it);
- the release has the assets and `SHA256SUMS`.

## 6. When something goes wrong

- **verify failed:** nothing was published. Fix on `main` with a normal pull request, delete the GitHub release and its
  tag (owner), and prepare the release again.
- **A publish job failed after another succeeded** (for example the crates are out and npm is not): never change or
  re-tag a published version. If the failed job published nothing (its log shows no upload), the owner re-runs it. If
  it published part of its packages (the crates job stopped after `rootcard`), a re-run fails on the published ones, so
  fix forward with the next patch version for all packages.
- **A bad version is out:** release a fixed patch version. Yanking a crate or deprecating an npm version is the owner's
  decision; a security problem additionally follows `SECURITY.md`.
