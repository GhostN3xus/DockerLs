# Changelog

All notable changes to DockerLs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (audit of claims vs. code)

- **No CI had ever run on this repository.** All four workflows triggered
  on `pull_request: branches: [main]`, and there is no `main` branch -- the
  default is `claude/docker-secure-finder-q7ikdh`. Lint, mypy and the test
  matrix had never executed on a single commit or pull request, so every
  quality claim rested on local runs alone. The branch filter is removed
  from `pull_request` (fires on any base, and survives the default branch
  being renamed), `push` ignores dependabot branches, and a concurrency
  group collapses the duplicate push/PR runs.
- **The NVD integration was removed rather than advertised.** `NVDClient`
  was only ever instantiated in tests and nothing under `dockerls/`
  imported it, so `NVD_API_KEY` never had any effect. Its one real signal
  -- known-exploited status -- is already provided by `ThreatIntelClient`
  (CISA KEV + EPSS), which *is* wired in and tested; wiring NVD too would
  have added a redundant network dependency to make a documentation line
  true. The module, its setting and its README entries are gone. It
  remains in git history if it is wanted later.
- **`health` probed a service the tool no longer uses and missed the ones
  it does.** It now checks Docker Hub, Chainguard, Distroless,
  endoflife.date, CISA KEV and EPSS -- the catalogues that feed the scan
  pipeline and the feeds that weight the score.

- **Credential redaction leaked in 10 of 17 realistic log formats.** The
  key/value pattern required the key name to be followed *immediately* by
  `=` or `:`, and every JSON-shaped line has a quote in between
  (`"token": "..."`) -- so the formats an HTTP client is most likely to
  produce passed straight through. Redaction now covers JSON (nested,
  compact, single-quoted, multiline), TOML, querystrings, multipart bodies,
  URL userinfo, `curl -u`, `Settings(...)` reprs and auth schemes, plus
  self-identifying credential formats (Docker PAT, GitHub token, JWT, AWS
  key, Slack token) that appear with no key at all. 60 adversarial cases in
  `test_secret_masking.py`, each asserting the secret is *absent* rather
  than that some masked form is present.
- **`health` reported the Docker Hub API as degraded on every healthy
  run** -- it probed `https://hub.docker.com/v2/`, which answers 404 by
  design. An alarm that is always on tells you nothing. It also always
  exited 0, so it could not gate anything; it now exits 1 when any service
  is unreachable or returns an error status.
- **Age penalty was uncapped**, growing a point per year, so a 10-year-old
  image lost as much as two HIGH findings on staleness alone. Capped at 3
  points, where it can still order equally-clean images without competing
  with measured severity.

An audit of every README/CHANGELOG claim against the code that implements
it, checking each is reached on the real execution path. Findings:

- **Documented configuration did nothing.** `Settings` declared
  `max_tags`, `workers`, `max_critical`, `max_high` and `max_medium`, and
  the README documented `DOCKERLS_<SETTING>` and `config.toml` as the way
  to change them -- but the CLI carried hard-coded `typer.Option` defaults
  that shadowed `Settings` entirely. The README's own example
  (`DOCKERLS_MAX_TAGS=200`, `max_tags = 200` in config.toml) was a no-op.
  Flags now default to `None` and fall back to the configured value; an
  explicit flag still wins. Covered by `test_settings_are_wired.py`, which
  fails 11 tests against the previous code.
- **`validate_threshold` was never called.** `--max-critical -5` and
  `--max-medium 999999` were accepted silently. Thresholds are now
  validated, and an invalid one prints a message and exits 1 instead of
  raising a traceback.
- **`SecurityTier.production_ready` was never read** and "Tier B =
  conditional" lived only in the README, so a Tier B row in the terminal
  carried no indication it needs human review. The CLI now prints a
  `Requires review` section naming each affected image.
- **The NVD integration is not wired into any command** -- `NVDClient` is
  only ever instantiated in tests, so `NVD_API_KEY` had no effect despite
  the README advertising a rate-limit benefit. Documented as reserved
  rather than removed; wiring it is separate work.
- README's `--max-medium 10` example read as contradicting the documented
  default of 5; it is an override and now says so.

Follow-up to the `recommend` overhaul, driven by a real run of
`dockerls recommend node`.

### Fixed
- **The security score could not tell images apart.** Bonuses totalled +19
  against a base of 100, so anything reasonably decorated hit the clamp: a
  clean image, a 1-HIGH image, a 2-HIGH image and a 5-MEDIUM image all
  reported exactly `100.0` -- the number claimed a vulnerable image was as
  safe as a clean one. Scoring now starts at 96 with qualitative bonuses
  capped at 4.0, strictly below a single HIGH penalty, so no combination of
  "official + minimal + signed + LTS + recent" can lift an image with an
  extra HIGH or CRITICAL above a cleaner one. Bonuses can still outweigh a
  MEDIUM or two, which is intended. The redundant "zero vulnerabilities"
  bonus is gone -- zero findings already means zero penalty.
- **Cross-validation was pathologically slow** (~4m12s for five images).
  Two causes, both addressed: Grype re-checks its vulnerability DB on every
  invocation, so the batch now runs `grype db update` once and scans with
  `GRYPE_DB_AUTO_UPDATE=false`; and the validations ran in a sequential
  `for` loop despite being independent, so they now run concurrently under
  a worker cap (`DOCKERLS_CROSS_VALIDATE_WORKERS`, default 5).
- Images from registries that list tag names only were charged the maximum
  age penalty and denied the recency bonus for metadata the registry simply
  does not publish. Age now moves the score only when the source actually
  reported a date.

### Added
- **Free hardened catalogues are searched alongside Docker Hub**:
  Chainguard (`cgr.dev/chainguard/<image>`) and Distroless
  (`gcr.io/distroless/<image>`). Their tags run through the same scan
  pipeline, so a hardened image wins on measured vulnerabilities rather
  than reputation. New `Source` column names each row's origin, and the run
  summary lists which catalogues answered. `--no-hardened` opts out.
- Registry listings are filtered to actual images: cosign `.sig`/`.att`/
  `.sbom` artifacts (~1000 per Chainguard repo), single-arch aliases and
  commit-pinned duplicates are dropped.
- "No image found matching baseline" now prints the exact criteria that
  were not met.
- The `Details` block gives every image its own evidence paths, marking
  `(shared digest)` where tags sharing a manifest were scanned once.
- `AnalysisResult.sources_searched` and `AnalysisResult.baseline` expose
  both facts to `--format json`.
- Acceptance suite (`tests/acceptance/`) asserting the end-to-end budget
  (<30s for five images), one progress display with no leakage into the
  results stream, per-image evidence on disk, and that both hardened
  sources are consulted.

### Changed
- The progress display renders to **stderr**, results to **stdout**, so the
  two streams cannot interleave and piping stdout keeps the spinner on the
  terminal. The observer is single-use and rejects re-entry; a test asserts
  the package contains exactly one Rich live display.
- Tag verification generalised beyond Docker Hub: each tag is confirmed by
  the registry that owns it. The table's `Hub` column is now `Tag`.



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
