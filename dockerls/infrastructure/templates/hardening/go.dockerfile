# DockerLs hardened template -- Go
#
# The runtime stage is `scratch`: no shell, no package manager, no libc --
# nothing for a scanner to find and nothing for an attacker to call.
ARG GO_VERSION=1.23.4
ARG ALPINE_VERSION=3.19

# ---------------------------------------------------------------------------
# Stage 1: build a fully static binary.
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# -s -w strips the symbol table; CGO_ENABLED=0 removes the libc dependency
# that would otherwise make `scratch` impossible.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/app .

# ---------------------------------------------------------------------------
# Stage 2: runtime.
# ---------------------------------------------------------------------------
FROM scratch

LABEL maintainer="your-team@company.com"
LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL security.cve-contact="security@company.com"

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=65532:65532 /out/app /app

# Numeric because scratch has no /etc/passwd to resolve a name against.
USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app", "-healthcheck"]

ENTRYPOINT ["/app"]
