# DockerLs execution profiles (SIMULATED registry, scanner and feeds)

Environment: date=2026-09-30T15:08:49+00:00, dockerls=1.0.16, git_commit=0bd421c, git_dirty=yes, python=3.11.15, os=Linux 6.18.44-fc-v50, machine=x86_64, cpus=4
Parameters:  repeat=7, tags_in_repository=60, scan_latency_s=0.2, resolve_latency_s=0.03, intel_latency_s=0.05, not_simulated=second-scanner cross-validation

| scenario | n | median s | p95 s | intel_requests | measured | pending_checks | scans |
|---|---|---|---|---|---|---|---|
| profile quick (scan budget 8, enrichment finalists) | 7 | 0.575 | 0.576 | 12 | 8 | 5 | 8 |
| profile standard (scan budget 25, enrichment all) | 7 | 1.624 | 1.712 | 38 | 25 | 3 | 25 |
| profile audit (scan budget all, enrichment all) | 7 | 3.367 | 3.369 | 90 | 60 | 3 | 60 |

JSON written to benchmarks/results/profiles.json
