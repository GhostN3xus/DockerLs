# Changelog

All notable changes to DockerLs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
