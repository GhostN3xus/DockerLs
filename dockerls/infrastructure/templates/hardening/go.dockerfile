# Dockerfile.hardened.go
# Template hardened para Go - Minimal Production Ready

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Instalar certificados CA e git
RUN apk add --no-cache ca-certificates git && update-ca-certificates && rm -rf /var/cache/apk/*

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

# Build estático com CGO desabilitado e flags de stripping
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app .

# Stage 2: Runtime minimal (scratch)
FROM scratch

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# Metadados de build
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# Copiar certificados raiz SSL para chamadas HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copiar apenas o binário estático
COPY --from=builder /app/app /app

# Expor porta padrão
EXPOSE 8080

# Non-root user numérico (nobody) para scratch
USER 65534:65534

# Health check seguro em formato exec
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app", "-health"]

# No shell - exec form apenas
ENTRYPOINT ["/app"]
