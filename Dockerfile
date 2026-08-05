FROM python:3.12.4-slim-bookworm AS builder

WORKDIR /build

COPY pyproject.toml .
COPY dockerls/ dockerls/

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12.4-slim-bookworm

RUN groupadd --gid 1001 dockerls && \
    useradd --uid 1001 --gid dockerls --shell /bin/false --create-home dockerls

COPY --from=builder /install /usr/local

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

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
