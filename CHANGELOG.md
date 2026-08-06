# Changelog

All notable changes to DockerLs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

`dockerls recommend` overhaul: clean terminal output, the root cause of the
Trivy scan errors removed, and no image recommended without proof it was
scanned and that its tag exists.

### Fixed
- **Trivy cache lock contention (root cause of the scan errors).** Parallel
  scans shared one `--cache-dir` and fought over Trivy's exclusive lock,
  making the losers exit non-zero with `cache may be in use by another
  process: timeout`. The DB is now downloaded once up front, then each
  concurrent worker gets its own cache directory with the DB hard-linked in
  (no multi-hundred-MB copies), torn down at the end of the run. Where
  hard-linking is unavailable the pool degrades to a single shared slot,
  which serializes scans rather than letting them collide.
- Secret masking leaked credentials when an auth scheme was nested in a
  key-value pair: in `auth: Bearer <token>` the key-value pattern consumed
  only the word `Bearer`, leaving the token in the clear. Scheme patterns
  now run first.
- A cache hit is no longer taken as proof of a successful scan; a cached
  analysis whose scan is not verified is discarded and rescanned.

### Added
- **Verification gate.** `ScanResult.is_verified` requires a completed
  (`OK`) scan with a timestamp. Anything else -- error, timeout, partial,
  or a default-constructed placeholder -- is reported in a separate
  `Unverified (technical error)` section with no score and no tier, and
  `_assert_verified` raises `UnverifiedRecommendationError` if an unverified
  image ever reaches the results.
- **Cross-scanner validation.** The top candidates are re-scanned with the
  secondary scanner; a material disagreement on CRITICAL/HIGH counts
  replaces the numeric score with `!disputed` plus the discrepancy.
- **Scan evidence.** Raw scanner JSON is written to `.dockerls/scans/`, with
  a per-run manifest linking every displayed score to the output it came
  from (`DOCKERLS_EVIDENCE_DIR`).
- **Docker Hub links.** `build_dockerhub_url()` emits the correct form for
  official (`/_/<repo>?tab=tags&name=<tag>`) and third-party
  (`/r/<ns>/<repo>/tags?name=<tag>`) images, skipping non-Hub registries.
  Tags are confirmed against the Hub API (TTL-cached to stay inside the
  anonymous rate limit) and dropped if confirmed missing.
- New flags: `--verbose`, `--no-progress`, `--no-cross-validate`,
  `--no-hub-check`. New settings: `DOCKERLS_LOG_DIR`,
  `DOCKERLS_EVIDENCE_DIR`, `DOCKERLS_TRIVY_CACHE_DIR`,
  `DOCKERLS_CROSS_VALIDATE`, `DOCKERLS_VERIFY_HUB_TAGS`.

### Changed
- Logging is file-only by default (`logs/dockerls_<timestamp>.log`); the
  loguru stderr sink is removed so nothing interleaves with the Rich
  progress display. `--verbose` re-attaches it.
- Scan progress renders as a single transient Rich spinner line
  (`Scanning node:26.7-slim... [3/24]`), followed by a run summary
  (`OK 12/24 analyzed | X 12 skipped (technical error)`) before the table.
- The results table was narrowed to fit an 80-column terminal without
  truncating image references: severity counts collapse into one `C/H/M`
  cell, and full Hub URLs are listed below the table rather than in it.
- Cache schema bumped to `v2` for the new verification metadata.

## [1.1.0]

Production-readiness pass covering correctness fixes, functional
improvements, new production features, and engineering hardening.

### Fixed (blockers)
- Scans that fail or time out are no longer treated as "clean" images.
  A `ScanStatus` (OK/ERROR/TIMEOUT/PARTIAL) is tracked end-to-end and
  `SecurityScore` refuses to score anything but OK/PARTIAL scans.
- Docker Hub authentication is now actually used: `build_repository()`
  loads keyring credentials and calls `authenticate()`, and `dockerls
  login` validates credentials before storing them.
- Tags sharing the same manifest digest are scanned once and share the
  result instead of being rescanned per tag.
- Trivy's vulnerability DB is refreshed once per run and individual scans
  pass `--skip-db-update`.
- The SQLite cache no longer blocks the event loop (`asyncio.to_thread`);
  cache keys are schema-versioned and a stale/incompatible cached payload
  is treated as a miss instead of crashing.
- EOL detection now maps Docker Hub image names to the correct
  endoflife.date product slugs and uses SemVer-aware version matching
  instead of naive string prefixes.

### Added / Changed (functional and production features)
- Docker Hub client: per-request retry (not whole-batch), `Retry-After`
  handling on 429, graceful degradation to partial results on network
  errors, and multi-arch reporting (`available_architectures`).
- Image name validation accepts digest references and private-registry
  prefixes with a port.
- Deterministic CVSS selection (NVD > vendor > first available, CVSS v4
  preferred over v3) in both the Trivy and Grype parsers.
- Full secret masking in logs (no partial values leaked).
- `recommend`/`advisor` gain CI-friendly exit codes, `--fail-on`,
  `--format json`, and `--no-color`; `analyze`/`compare` gain `--no-color`.
- New `sbom` command (CycloneDX/SPDX via Trivy) and `export --format
  sarif` (SARIF 2.1.0).
- `.dockerls-ignore.yaml` support for CVE ignores with justification and
  expiration.
- CISA KEV + EPSS threat-intel signal factored into `SecurityScore`
  (best-effort, degrades gracefully if unreachable).
- Hardened-vendor images (Chainguard, Wolfi, Bitnami) count toward the
  "minimal base" scoring bonus.

### Engineering
- `mypy --strict` passes across the whole package (not just the domain
  layer); `ruff`'s blanket `S603`/`S607` ignores were removed in favor of
  narrow per-call-site `noqa`s on the two verified-safe subprocess calls.
- Test suite expanded to 190+ tests covering scanner error/timeout paths,
  cache versioning, fallback mode, HTTP partial-result handling, EOL
  parsing, and all CLI commands; coverage raised from the 80% floor to ~89%.
- Dockerfile hardened: base images pinned by digest, Trivy copied from its
  official image instead of `curl | sh`.
- Release workflow now attaches a GitHub-native SLSA build provenance
  attestation and Sigstore-signed artifacts.
- `__version__` now reads from installed package metadata
  (`importlib.metadata`) instead of a hand-maintained string.
- Settings migrated to `pydantic-settings` with `DOCKERLS_`-prefixed env
  vars and an optional `~/.config/dockerls/config.toml`.
- NVD API key support (`NVD_API_KEY`) with correct rate limiting (5 vs 50
  requests/30s).
- Removed the unused, never-wired Docker Scout integration stub.

## [1.0.0] - 2024-01-01

### Added
- Initial release
- `search` command: search Docker Hub tags
- `recommend` command: recommend secure images with scoring
- `advisor` command: security advisor with remediation plans
- `analyze` command: deep analysis of a specific image tag
- `compare` command: side-by-side comparison of images
- `export` command: export reports in JSON, CSV, HTML, Markdown
- `login` command: Docker Hub authentication via keyring
- `doctor` command: system dependency check
- `health` command: external service connectivity check
- `cache` subcommands: cache management (clear, cleanup)
- Trivy integration (primary scanner)
- Grype integration (fallback scanner)
- Docker Scout integration (complementary)
- NVD API integration
- endoflife.date integration
- Security scoring algorithm (0-100)
- Security tier classification (S/A/B/C)
- Remediation score calculation
- Intelligent fallback when no image meets baseline
- SQLite-based scan cache with TTL
- Structured logging with secret masking
- Input validation and sanitization
- Secure Dockerfile (multi-stage, non-root, read-only)
- CI/CD workflows (lint, test, security, CodeQL)
- Dependabot configuration
