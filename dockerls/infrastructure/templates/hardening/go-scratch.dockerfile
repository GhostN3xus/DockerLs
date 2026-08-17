# Dockerfile.hardened.go-scratch
# Template hardened para Go (Scratch - Zero OS CVEs)

ARG GO_VERSION=1.23-alpine

# Stage 1: Builder
FROM golang:${GO_VERSION} AS builder

RUN apk update && apk add --no-cache git ca-certificates tzdata \
    && update-ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilação estática segura (sem CGO)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /app/binary .

# Stage 2: Scratch Runtime
FROM scratch

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

# Importar certificados TLS e fuso horário do builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copiar apenas o binário estático
COPY --from=builder /app/binary /app/binary

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# Usuário nobody (UID 65534:65534)
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/app/binary"]
