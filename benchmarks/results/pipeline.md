# DockerLs pipeline benchmark (SIMULATED registry and scanner)

Environment: date=2026-09-30T15:08:10+00:00, dockerls=1.0.16, git_commit=0bd421c, git_dirty=yes, python=3.11.15, os=Linux 6.18.44-fc-v50, machine=x86_64, cpus=4
Parameters:  repeat=7, scan_latency_s=0.2, resolve_latency_s=0.03, intel_latency_s=0.05, slow_intel_latency_s=1.0

| scenario | n | median s | p95 s | cache_hits | concurrency | dedup | kev_requests | scans |
|---|---|---|---|---|---|---|---|---|
| recommend small (6 tags), cold cache | 7 | 0.468 | 0.471 | 0 | - | 0 | - | 6 |
| recommend small (6 tags), warm cache | 7 | 0.033 | 0.040 | 0 | - | 0 | - | 0 |
| recommend large (36 tags), cold cache | 7 | 2.009 | 2.037 | 0 | - | 0 | - | 36 |
| recommend large (36 tags), warm cache | 7 | 0.162 | 0.168 | 0 | - | 0 | - | 0 |
| recommend 36 tags -> 6 distinct digests | 7 | 0.596 | 0.597 | 0 | - | 30 | - | 6 |
| compare 2 images (limit 4) | 7 | 0.233 | 0.234 | - | 2 | - | - | 2 |
| compare 8 images (limit 4) | 7 | 0.467 | 0.468 | - | 4 | - | - | 8 |
| recommend 6 tags, intel healthy | 7 | 0.519 | 0.573 | 0 | - | 0 | 4 | 6 |
| recommend 6 tags, intel slow | 7 | 1.469 | 1.679 | 0 | - | 0 | 4 | 6 |
| recommend 6 tags, intel unavailable | 7 | 0.518 | 0.536 | 0 | - | 0 | 4 | 6 |
| 3 simultaneous recommend runs (6 tags, shared store) | 7 | 0.474 | 0.477 | - | - | - | - | 18 |

- recommend small (6 tags), warm cache: second run over the same store: scans should be 0

- recommend large (36 tags), warm cache: second run over the same store: scans should be 0

- recommend 36 tags -> 6 distinct digests: scans should equal the number of distinct digests, not of tags

- recommend 6 tags, intel unavailable: the fake reports 'no answer'; telling absent / error / rate limited / invalid apart is covered by tests/unit/integrations/test_threat_intel_sharing.py, not timed here

- 3 simultaneous recommend runs (6 tags, shared store): separate runs have separate single-flights: without a warm store each may scan; the persisted store is what stops the *next* run from repeating them

JSON written to benchmarks/results/pipeline.json
