# DockerLs end-to-end timings (REAL CLI, real Trivy, real registries)

Environment: date=2026-09-30T15:20:32+00:00, dockerls=1.0.16, git_commit=59ad9e5, git_dirty=yes, python=3.11.15, os=Linux 6.18.44-fc-v50, machine=x86_64, cpus=4, trivy=Version: dev, grype=Application:         grype, image=mirror.gcr.io/library/alpine:3.20, network=real, unthrottled by this script
Parameters:  repeat=5, engine=both

| scenario | n | median s | p95 s | exit |
|---|---|---|---|---|
| [python] analyze, cold everything | 1 | 15.800 | 15.800 | 0 |
| [python] analyze amd64, store cold | 5 | 5.637 | 5.783 | 0 |
| [python] analyze amd64, store warm | 5 | 3.046 | 3.393 | 0 |
| [python] analyze arm64, store cold | 5 | 5.985 | 6.410 | 0 |
| [python] compare 2 images, store cold | 5 | 6.779 | 7.575 | 0 |
| [python] compare 2 images, store warm | 5 | 3.046 | 3.276 | 0 |
| [go] analyze, cold everything | 1 | 13.494 | 13.494 | 0 |
| [go] analyze amd64, store cold | 5 | 5.857 | 6.466 | 0 |
| [go] analyze amd64, store warm | 5 | 3.186 | 3.279 | 0 |
| [go] analyze arm64, store cold | 5 | 5.925 | 6.300 | 0 |
| [go] compare 2 images, store cold | 5 | 6.436 | 6.663 | 0 |
| [go] compare 2 images, store warm | 5 | 2.814 | 3.209 | 0 |

- [python] analyze, cold everything: exit codes [0]; origin ['scan']

- [python] analyze amd64, store cold: exit codes [0]; origin ['scan']

- [python] analyze amd64, store warm: exit codes [0]; origin ['cache']

- [python] analyze arm64, store cold: exit codes [0]; origin ['scan']

- [python] compare 2 images, store cold: exit codes [0]; origin n/a

- [python] compare 2 images, store warm: exit codes [0]; origin n/a

- [go] analyze, cold everything: exit codes [0]; origin ['scan']

- [go] analyze amd64, store cold: exit codes [0]; origin ['scan']

- [go] analyze amd64, store warm: exit codes [0]; origin ['cache']

- [go] analyze arm64, store cold: exit codes [0]; origin ['scan']

- [go] compare 2 images, store cold: exit codes [0]; origin n/a

- [go] compare 2 images, store warm: exit codes [0]; origin n/a

JSON written to benchmarks/results/real.json
