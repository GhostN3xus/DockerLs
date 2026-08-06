# Changelog

All notable changes to DockerLs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
