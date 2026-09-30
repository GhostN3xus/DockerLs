# DockerLs end-to-end timings (REAL CLI, real Trivy, real registries)

Environment: date=2026-09-30T15:10:58+00:00, dockerls=1.0.16, git_commit=0bd421c, git_dirty=yes, python=3.11.15, os=Linux 6.18.44-fc-v50, machine=x86_64, cpus=4, trivy=Version: dev, grype=Application:         grype, image=mirror.gcr.io/library/alpine:3.20, network=real, unthrottled by this script
Parameters:  repeat=3, engine=both

| scenario | n | median s | p95 s | exit |
|---|---|---|---|---|
| [python] analyze amd64, store cold | 3 | 6.116 | 6.225 | 0 |
| [python] analyze amd64, store warm | 3 | 3.494 | 3.976 | 0 |
| [python] analyze arm64, store cold | 3 | 6.504 | 6.983 | 0 |
| [python] compare 2 images, store cold | 3 | 8.308 | 8.337 | 0 |
| [python] compare 2 images, store warm | 3 | 4.560 | 4.623 | 0 |
| [go] analyze amd64, store cold | 3 | 6.101 | 6.159 | 0 |
| [go] analyze amd64, store warm | 3 | 3.549 | 3.685 | 0 |
| [go] analyze arm64, store cold | 3 | 6.491 | 6.511 | 0 |
| [go] compare 2 images, store cold | 3 | 7.518 | 7.765 | 0 |
| [go] compare 2 images, store warm | 3 | 4.763 | 4.768 | 0 |

- [python] analyze amd64, store cold: exit codes [0]; origin ['scan']

- [python] analyze amd64, store warm: exit codes [0]; origin ['cache']

- [python] analyze arm64, store cold: exit codes [0]; origin ['scan']

- [python] compare 2 images, store cold: exit codes [0]; origin n/a

- [python] compare 2 images, store warm: exit codes [0]; origin n/a

- [go] analyze amd64, store cold: exit codes [0]; origin ['scan']

- [go] analyze amd64, store warm: exit codes [0]; origin ['cache']

- [go] analyze arm64, store cold: exit codes [0]; origin ['scan']

- [go] compare 2 images, store cold: exit codes [0]; origin n/a

- [go] compare 2 images, store warm: exit codes [0]; origin n/a

JSON written to benchmarks/results/real.json
