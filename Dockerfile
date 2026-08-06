# syntax=docker/dockerfile:1
# Base images pinned by digest (python:3.12.4-slim-bookworm,
# aquasec/trivy:0.55.2). Both digests are manifest-list digests, so the
# pin still resolves to the correct platform on multi-arch builds
# (linux/amd64, linux/arm64, ...).
ARG PYTHON_DIGEST=sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85
ARG TRIVY_DIGEST=sha256:addfb8fd6b9e520c25b22c61d8aa5d58ecd7879177aa959f952bf4734f4e3f60

FROM python:3.12.4-slim-bookworm@${PYTHON_DIGEST} AS builder

WORKDIR /build

COPY pyproject.toml .
COPY dockerls/ dockerls/

RUN pip install --no-cache-dir --prefix=/install .

FROM aquasec/trivy:0.55.2@${TRIVY_DIGEST} AS trivy

FROM python:3.12.4-slim-bookworm@${PYTHON_DIGEST}

RUN groupadd --gid 1001 dockerls && \
    useradd --uid 1001 --gid dockerls --shell /bin/false --create-home dockerls

COPY --from=builder /install /usr/local
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN mkdir -p /home/dockerls/.cache/dockerls && \
    chown -R dockerls:dockerls /home/dockerls

USER dockerls
WORKDIR /home/dockerls

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["dockerls", "version"]

ENTRYPOINT ["dockerls"]
CMD ["--help"]
