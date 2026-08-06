# DockerLs

Enterprise Docker Image Security Advisor. Discovers the most secure Docker images
available on Docker Hub by scanning vulnerabilities, checking EOL status, and
producing actionable remediation plans.

DockerLs is not just a scanner -- it is a security advisor that recommends the best
image for production use and tells you exactly how to fix what it finds.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Scoring Algorithm](#scoring-algorithm)
- [Security Tiers](#security-tiers)
- [Fallback Mode](#fallback-mode)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Docker Usage](#docker-usage)
- [Development](#development)
- [CI/CD](#cicd)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## Installation

### From PyPI

```bash
pip install dockerls
```

### From source

```bash
git clone https://github.com/GhostN3xus/DockerLs.git
cd DockerLs
pip install .
```

### With keyring support (for credential storage)

```bash
pip install "dockerls[keyring]"
```

### Requirements

- Python 3.11+
- Trivy (primary scanner) -- install from https://aquasecurity.github.io/trivy
- Grype (optional fallback) -- install from https://github.com/anchore/grype

---

## Quick Start

```bash
# Find the most secure Node.js image
dockerls recommend node

# Deep-analyze a specific tag
dockerls analyze node:22-alpine

# Get a full remediation plan
dockerls advisor node

# Compare two images side by side
dockerls compare node:22-alpine node:22-bookworm-slim

# Export report as JSON
dockerls export node --format json --output report.json
```

---

## Commands

### search

Search Docker Hub for available tags.

```bash
dockerls search node
dockerls search python --limit 50
```

### recommend

Recommend the most secure tags based on vulnerability scanning.

```bash
dockerls recommend node
dockerls recommend node --max-medium 10          # loosen the default of 5
dockerls recommend nginx --workers 20
dockerls recommend node --format json
dockerls recommend node --fail-on high --no-color
```

`recommend` and `advisor` accept `--format json` (machine-readable output)
and `--no-color` (plain text, no ANSI codes), and exit with a status code
that reflects the outcome so it can be used as a CI gate:

| Exit code | Meaning                                          |
|-----------|---------------------------------------------------|
| 0         | An image meeting the baseline was found            |
| 1         | Hard error, or `--fail-on` threshold was violated  |
| 2         | No baseline image, but fallback alternatives exist |
| 3         | Nothing usable was found at all                    |

`--fail-on {critical,high,medium}` forces exit code 1 if the top result
still carries vulnerabilities at or above that severity, even in fallback
mode -- useful for failing a CI job on a fallback recommendation you don't
consider acceptable.

#### What a recommendation guarantees

Every row in the **Recommended Images** table has cleared three gates. If a
tag cannot clear all three, it is reported separately and never scored:

1. **Proven scan.** The scanner process exited cleanly and its JSON was
   parsed. A failed, timed-out or partial scan sends the tag to the
   `Unverified (technical error)` section -- it gets no score and no tier.
2. **Undisputed score.** The top candidates are re-scanned with the second
   scanner (Grype when Trivy is primary, and vice versa). If the two
   disagree materially on CRITICAL/HIGH counts, the score is shown as
   `!disputed` instead of a number, with the discrepancy printed below.
3. **Tag confirmed in its source registry.** Docker Hub tags are checked
   against the Hub API (`GET /v2/repositories/<ns>/<repo>/tags/<tag>`);
   hardened-source tags are checked against that registry's own listing.
   Either way the `Tag` column reflects a real registry answer, never a
   constructed string.

The run opens with a one-line summary of how many tags were analyzed versus
skipped, which catalogues were searched, and the path to that run's log file:

```
OK 12/24 analyzed | X 12 skipped (technical error) | sources: Docker Hub, Chainguard, Distroless
log: logs/dockerls_2026-08-06_13-36-15.log
```

When nothing clears the baseline, the exact criteria are printed rather than
just the verdict:

```
No image found matching baseline.
Baseline: 0 Critical, 0 High, 5 Medium (and not EOL).
No image met it -- showing the closest alternatives.
```

#### Image sources

Docker Hub is searched alongside two free, security-hardened catalogues, and
all of their tags go through the same scan pipeline -- a hardened image wins
on measured vulnerabilities, not on reputation. The `Source` column says
where each row came from.

| Source | Registry | Notes |
|--------|----------|-------|
| Docker Hub | `docker.io` | Full tag listing with sizes and dates |
| Chainguard | `cgr.dev/chainguard/<image>` | Free tier tracks moving tags (`latest`, `latest-dev`); pinned versions are a paid feature |
| Distroless | `gcr.io/distroless/<image>` | GCR reports publish dates and sizes, so these tags are ranked newest-first |

Cosign signatures, attestations, SBOMs, single-arch aliases and
commit-pinned duplicates are filtered out of registry listings -- they are
not images anyone would pull. A source that is unreachable is logged and
skipped; it never takes down a search the other sources can still answer.
Use `--no-hardened` for Docker Hub only.

#### Output, logs and evidence

The terminal shows only a progress spinner and the results. All diagnostics
-- including scanner stderr -- go to `logs/dockerls_<timestamp>.log`; pass
`--verbose` to mirror them to stderr as well. Set `DOCKERLS_LOG_DIR` to move
the log directory.

The raw JSON from every scan is written to
`.dockerls/scans/<image>_<tag>__<scanner>__<timestamp>.json`, and the
`Details` block under the table points each image at its own files:

```
Details
  1. node:trixie-slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=trixie-slim
     trivy:    .dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json
     grype:    .dockerls/scans/node_trixie-slim__grype__20260806T153119491147.json
  2. node:slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=slim
     trivy:    .dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json  (shared digest)
```

`(shared digest)` marks evidence produced under a sibling tag's name: tags
pointing at the same manifest digest are scanned once and share the result.
A per-run manifest linking every displayed score to its evidence is written
alongside. Set `DOCKERLS_EVIDENCE_DIR` to relocate the directory.

The progress display renders to **stderr** and results to **stdout**, so
`dockerls recommend node > out.txt` leaves the spinner on your terminal and
writes clean results to the file.

| Flag | Effect |
|------|--------|
| `--verbose` / `-v` | Also print logs to stderr |
| `--no-progress` | Disable the progress spinner |
| `--no-cross-validate` | Skip second-scanner validation (faster) |
| `--no-hub-check` | Skip registry tag verification (offline use) |
| `--no-hardened` | Search Docker Hub only |

#### Scan concurrency

Trivy takes an exclusive lock on its cache directory, so parallel scans
sharing one cache dir fail with `cache may be in use by another process:
timeout`. DockerLs downloads the vulnerability DB once up front, then gives
each concurrent worker its own cache directory with the DB hard-linked in,
and removes those directories when the run ends. If hard-linking is not
possible, it falls back to a single shared cache dir and serializes scans --
slower, but never lock-contended. `DOCKERLS_TRIVY_CACHE_DIR` overrides the
cache root.

Grype checks its vulnerability DB for updates on *every* invocation, which
is a network round trip per image. Cross-validation therefore runs
`grype db update` once for the batch and then scans with
`GRYPE_DB_AUTO_UPDATE=false`, and the validations themselves run
concurrently (`DOCKERLS_CROSS_VALIDATE_WORKERS`, default 5) since they are
independent. The acceptance suite holds the whole command to a 30-second
budget for five images.

### advisor

Full security advisor with remediation steps.

```bash
dockerls advisor node
dockerls advisor node --format json
```

Output includes: current best image, security score, vulnerability breakdown,
remediation score, and a step-by-step fix plan.

### sbom

Generate a Software Bill of Materials for an image via Trivy.

```bash
dockerls sbom node:22-alpine --format cyclonedx
dockerls sbom node:22-alpine --format spdx --output node.spdx.json
```

### analyze

Deep analysis of a specific image tag.

```bash
dockerls analyze node:22-alpine
```

Shows all CVEs found, CVSS scores, affected packages, fix availability.

### compare

Side-by-side comparison of two or more images.

```bash
dockerls compare node:22-alpine node:22-bookworm-slim
```

### export

Export analysis results.

```bash
dockerls export node --format json
dockerls export node --format csv --output report.csv
dockerls export node --format html --output report.html
dockerls export node --format markdown --output report.md
dockerls export node --format sarif --output report.sarif
```

The `sarif` format produces SARIF 2.1.0, suitable for upload to GitHub code
scanning or other SARIF-aware tooling.

### login

Authenticate with Docker Hub (increases rate limits).

```bash
dockerls login
```

Credentials are stored in your system keyring. Alternatively, set environment variables:

```bash
export DOCKERHUB_USERNAME=myuser
export DOCKERHUB_TOKEN=mytoken
```

### doctor

Check system dependencies.

```bash
dockerls doctor
```

### health

Check connectivity to external services.

```bash
dockerls health
```

### cache

Manage the scan cache.

```bash
dockerls cache clear
dockerls cache cleanup
```

### version

```bash
dockerls version
```

---

## Scoring Algorithm

Each image receives a security score from 0 to 100:

```
score = 96 - penalties + bonuses      # clamped to [0, 100]
```

Measured vulnerabilities drive the score. Penalties:

| Condition                                        | Penalty       |
|--------------------------------------------------|---------------|
| CRITICAL vulnerability                            | -20 each     |
| HIGH vulnerability                                | -5 each      |
| MEDIUM vulnerability                              | -1 each      |
| EOL                                               | -20          |
| Vulnerability with a confirmed exploit (CISA KEV) | -10 per vuln |
| Vulnerability with EPSS >= 0.5 (high predicted exploitation probability) | -5 per vuln |
| Image age                                         | -age_days/365 |

Qualitative signals act as tie-breakers. They total **4.0** -- deliberately
less than a single HIGH finding, so no combination of them can lift an
image with an extra HIGH or CRITICAL above a cleaner one:

| Condition                                          | Bonus |
|-----------------------------------------------------|-------|
| Official image                                       | +1    |
| Minimal base (Alpine, Distroless, or a hardened vendor image -- Chainguard, Wolfi, Bitnami) | +1 |
| Digitally signed                                     | +1    |
| LTS version                                          | +0.5  |
| Updated in last 30 days                              | +0.5  |

The minimal-base bonus is applied once even if an image matches more than
one signal (e.g. an Alpine-based Chainguard image does not get +2).

They *can* outweigh a MEDIUM or two, which is intended: a signed official
distroless image with two mediums is a defensible pick over an unremarkable
image with none.

Scoring starts at 96 rather than 100 so a fully-decorated clean image lands
exactly on 100 without being clamped. This matters: with bonuses totalling
+19 against a base of 100, anything reasonably decorated hit the ceiling and
a clean image, a 1-HIGH image, a 2-HIGH image and a 5-MEDIUM image all
reported exactly `100.0`. There is no separate "zero vulnerabilities" bonus
-- zero findings already means zero penalty, and rewarding it again
double-counted the same fact.

Age only moves the score when the source actually reported a publish date.
Registries that list tag names only (Chainguard, most OCI catalogues) are
neither charged the age penalty nor given the recency bonus, so they are not
punished for metadata the registry does not publish.

CISA KEV and EPSS lookups are best-effort: if those feeds are unreachable,
DockerLs scores without that signal rather than failing the scan. Both are
only queried when the scan has CRITICAL or HIGH findings to check.

---

## Security Tiers

| Tier | Criteria                                     | Production Ready |
|------|----------------------------------------------|------------------|
| S    | Critical = 0, High = 0                       | Yes*             |
| A    | Critical = 0, High <= 3, all fixable         | Yes*             |
| B    | Critical = 0, High <= 10                     | Conditional*     |
| C    | Any Critical, or many High                   | No               |

\* An EOL image is never reported production-ready, regardless of tier.

---

## Ignoring Known Findings

Create a `.dockerls-ignore.yaml` in the directory you run `dockerls` from
to suppress specific CVEs from scoring and recommendations:

```yaml
ignores:
  - cve: CVE-2024-0001
    justification: "Not reachable in our usage of this package"
    expires: 2026-12-31
```

`expires` is optional; once the date passes, the rule stops applying and
the CVE counts again. Malformed or missing ignore files are treated as
"no rules" rather than failing the scan.

Tier C images are never recommended for production.

---

## Fallback Mode

When no image meets the baseline (Critical=0, High=0), DockerLs does not return
an empty result. Instead it:

1. Finds all images with Critical = 0
2. Sorts by fewest HIGH vulnerabilities
3. Evaluates fix availability
4. Calculates a Remediation Score
5. Presents the best alternative with a fix plan

### Remediation Score

| Score | Meaning                      |
|-------|------------------------------|
| 100   | All vulns have fixes         |
| 80    | Most vulns have fixes        |
| 60    | About half have fixes        |
| 40    | Few have fixes               |
| 20    | No fixes available           |

---

## Architecture

DockerLs follows Clean Architecture with clear layer separation:

```
dockerls/
  cli/              # Typer CLI commands and output formatting
  domain/
    entities/        # DockerImage, Vulnerability, ScanResult, Recommendation
    value_objects/   # SecurityScore, SecurityTier, RemediationScore
    interfaces/      # Abstract interfaces (ports)
  application/
    use_cases/       # SearchImages, RecommendImages, AnalyzeImage, CompareImages
    services/        # ScannerFactory
    dto/             # AnalysisResult, ComparisonResult
  infrastructure/
    config/          # Settings (Pydantic)
    database/        # SQLAlchemy models
    logging/         # Loguru setup with secret masking
  integrations/
    dockerhub/       # Docker Hub API client
    trivy/           # Trivy scanner integration
    grype/           # Grype scanner integration (fallback)
    endoflife/       # endoflife.date checker
  cache/             # SQLite cache implementation
  exporters/         # JSON, CSV, HTML, Markdown exporters
  utils/             # Input validation, auth helpers
```

Data flows inward: CLI -> Use Cases -> Domain. External integrations implement
domain interfaces and are injected via the dependency builder.

---

## Configuration

Settings are resolved in priority order: environment variables, then
`~/.config/dockerls/config.toml` (or `$XDG_CONFIG_HOME/dockerls/config.toml`),
then built-in defaults.

### Environment variables

| Variable                        | Description                              |
|----------------------------------|-------------------------------------------|
| DOCKERHUB_USERNAME               | Docker Hub username                       |
| DOCKERHUB_TOKEN                  | Docker Hub access token                   |
| XDG_CACHE_HOME                   | Override cache directory                  |
| XDG_CONFIG_HOME                  | Override config file directory            |
| DOCKERLS_DISABLE_THREAT_INTEL    | Disable CISA KEV / EPSS lookups           |
| DOCKERLS_<SETTING_NAME>          | Override any other setting below (e.g. `DOCKERLS_MAX_TAGS=200`) |

### Config file

```toml
# ~/.config/dockerls/config.toml
max_tags = 200
workers = 20
log_level = "DEBUG"
```

Keys match the setting names in the table below (snake_case, no prefix).

Every threshold flag (`--max-critical`, `--max-high`, `--max-medium`,
`--workers`, `--limit`) falls back to its configured value when omitted, so
`DOCKERLS_MAX_MEDIUM=10` and a `config.toml` entry both take effect. An
explicit flag always wins over configuration.

### Default thresholds

| Parameter     | Default |
|---------------|---------|
| max-critical  | 0       |
| max-high      | 0       |
| max-medium    | 5       |
| workers       | 10      |
| limit (tags)  | 100     |
| cache TTL     | 24h     |

---

## Docker Usage

### Build

```bash
docker build -t dockerls:latest .
```

### Run securely

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  dockerls:latest recommend node
```

### Docker Compose

```bash
docker compose run dockerls recommend node
```

The Docker image follows OWASP Docker Security best practices: multi-stage
build, base images pinned by digest (Python and Trivy), Trivy copied from
its official image rather than installed via `curl | sh`, a non-root user,
read-only filesystem support, and all capabilities dropped.

---

## Development

```bash
# Install dev dependencies
make dev

# Run linter
make lint

# Run type checker
make type-check

# Run tests
make test

# Run full audit (lint + type-check + test + security)
make audit

# Format code
make format
```

---

## CI/CD

GitHub Actions workflows included:

- **CI**: Ruff linting, Mypy type checking, Pytest across Python 3.11/3.12/3.13
- **Security**: Bandit SAST, pip-audit dependency check, Trivy container scan
- **CodeQL**: GitHub code scanning
- **Release**: Automated PyPI publish on tag push, with a GitHub-native SLSA
  build provenance attestation and Sigstore-signed artifacts attached to the release
- **Dependabot**: Weekly dependency updates

---

## Security Model

### Threat model

DockerLs operates as a read-only advisory tool. It:
- Reads from Docker Hub API (public data)
- Executes Trivy/Grype as local subprocesses
- Queries endoflife.date, CISA KEV and EPSS APIs
- Caches results locally in SQLite

It does not:
- Pull or run Docker images
- Modify any Docker configuration
- Access private registries without explicit credentials
- Transmit user data to third parties

### OWASP alignment

- Input validation on all image names (injection prevention)
- No shell=True in subprocess calls (command injection prevention)
- Credential masking in all log output
- Path traversal detection in image names
- Secure credential storage via system keyring
- Dependency scanning in CI (pip-audit, Dependabot)
- SAST scanning (Bandit, CodeQL)
- Container scanning (Trivy)

---

## Troubleshooting

### "No scanner available"

Install Trivy:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Or install Grype as fallback:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### "Rate limited by Docker Hub"

Authenticate to increase rate limits:
```bash
dockerls login
```

### Slow scans

- Reduce tag count: `--limit 20`
- Increase workers: `--workers 20`
- Results are cached for 24 hours

### Cache issues

```bash
dockerls cache clear
```

---

## FAQ

**Q: Does DockerLs pull Docker images?**
A: No. Trivy/Grype handle image pulling internally for scanning.
DockerLs only queries metadata from Docker Hub.

**Q: Can I use it with private registries?**
A: `analyze` and `compare` accept any valid reference, including private
registries with a port (`registry.internal:5000/team/app:tag`), common
private registry hosts (GHCR, Harbor, ECR, GAR), and digest references
(`node@sha256:...`). Scanning still goes through Trivy/Grype, so
authenticate against the registry the way you normally would for those
tools (e.g. `TRIVY_USERNAME`/`TRIVY_PASSWORD`, or a logged-in
`~/.docker/config.json`) -- DockerLs does not manage registry credentials
itself. `search` and `recommend` still query Docker Hub's tag listing API,
so they are limited to Docker Hub repositories.

**Q: How accurate is the scoring?**
A: The score combines vulnerability counts, image age, and base type.
It is a heuristic -- always review the detailed CVE list for critical decisions.

**Q: What if Trivy and Grype are both unavailable?**
A: DockerLs will report the issue. Run `dockerls doctor` to check dependencies.

---

## License

MIT License. See [LICENSE](LICENSE).
