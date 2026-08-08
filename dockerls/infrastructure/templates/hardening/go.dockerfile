# Dockerfile.hardened.go
# Template hardened para Go - Minimal Production Ready

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Instalar dependências de build se necessário
RUN apk add --no-cache git && rm -rf /var/cache/apk/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build estático com CGO desabilitado
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

# Copiar apenas o binário
COPY --from=builder /app/app /app

# Expor porta
EXPOSE 8080

# Health check (se o binário suportar)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app", "-health"] || exit 0

# No shell - exec form apenas
ENTRYPOINT ["/app"]
