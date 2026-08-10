# Changelog

All notable changes to this crate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

### Changed

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. The Apache-2.0
  appendix said 2025, but every commit in this repository dates to 2026. No functional
  change.
- Dropped the deprecated `authors` field and repointed `repository` at the organisation.
  The URL also carried a trailing slash, which is now removed.
- CI gained formatting, clippy, and documentation gates. It previously ran only
  `cargo test` and `cargo doc`, so lint and formatting regressions went uncaught —
  the tree was in fact unformatted. Clippy runs `--all-targets`, and the docs job
  denies rustdoc warnings.
- Releases now verify that the tag matches the version declared in `Cargo.toml`, and
  refuse to publish a commit that is not contained in `main`.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.1.0]

Initial release.
