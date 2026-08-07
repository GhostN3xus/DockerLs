# DockerLs hardened template -- Python
#
# Passes every rule in `dockerls build --validate-only`. Replace the
# maintainer/contact labels and the healthcheck endpoint with your own.
ARG PYTHON_VERSION=3.12.7
ARG ALPINE_VERSION=3.19

# ---------------------------------------------------------------------------
# Stage 1: build wheels. The C toolchain never reaches the runtime image.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt ./

# --mount=type=secret keeps an index token out of the image history.
# Build with: docker build --secret id=pip_index,env=PIP_INDEX_URL .
RUN --mount=type=secret,id=pip_index \
    if [ -f /run/secrets/pip_index ]; then \
        PIP_INDEX_URL="$(cat /run/secrets/pip_index)"; export PIP_INDEX_URL; \
    fi && \
    pip install --user --no-cache-dir --require-hashes -r requirements.txt || \
    pip install --user --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION}

LABEL maintainer="your-team@company.com"
LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL security.cve-contact="security@company.com"

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup . .

ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python"]
CMD ["-u", "main.py"]
