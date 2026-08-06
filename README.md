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
dockerls recommend node --max-critical 0 --max-high 0 --max-medium 10
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
score = 100
score -= critical_vulns * 20
score -= high_vulns * 5
score -= medium_vulns * 1
score -= image_age_days / 365
```

Bonuses:

| Condition                                          | Bonus |
|-----------------------------------------------------|-------|
| Official image                                       | +5    |
| Zero vulnerabilities                                 | +5    |
| Minimal base (Alpine, Distroless, or a hardened vendor image -- Chainguard, Wolfi, Bitnami) | +3 |
| Updated in last 30 days                              | +2    |
| Digitally signed                                     | +2    |
| LTS version                                          | +2    |

The minimal-base bonus is applied once even if an image matches more than
one signal (e.g. an Alpine-based Chainguard image does not get +6).

Penalties:

| Condition                                    | Penalty        |
|------------------------------------------------|----------------|
| EOL                                             | -20            |
| Vulnerability with a confirmed exploit (CISA KEV)| -10 per vuln  |
| Vulnerability with EPSS >= 0.5 (high predicted exploitation probability) | -5 per vuln |

CISA KEV and EPSS lookups are best-effort: if those feeds are unreachable,
DockerLs scores without that signal rather than failing the scan. Both are
only queried when the scan has CRITICAL or HIGH findings to check.

Score is clamped to the range [0, 100].

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
    scout/           # Docker Scout integration
    nvd/             # NVD API client
    endoflife/       # endoflife.date checker
  cache/             # SQLite cache implementation
  exporters/         # JSON, CSV, HTML, Markdown exporters
  utils/             # Input validation, auth helpers
```

Data flows inward: CLI -> Use Cases -> Domain. External integrations implement
domain interfaces and are injected via the dependency builder.

---

## Configuration

### Environment variables

| Variable            | Description                  |
|---------------------|------------------------------|
| DOCKERHUB_USERNAME  | Docker Hub username          |
| DOCKERHUB_TOKEN     | Docker Hub access token      |
| XDG_CACHE_HOME      | Override cache directory     |

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

The Docker image follows OWASP Docker Security best practices:
multi-stage build, specific base image version, non-root user,
read-only filesystem support, all capabilities dropped.

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
- **Release**: Automated PyPI publish on tag push
- **Dependabot**: Weekly dependency updates

---

## Security Model

### Threat model

DockerLs operates as a read-only advisory tool. It:
- Reads from Docker Hub API (public data)
- Executes Trivy/Grype as local subprocesses
- Queries NVD and endoflife.date APIs
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
