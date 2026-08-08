# Dockerfile.hardened.node
# Template hardened para Node.js - Production Ready

ARG NODE_VERSION=22.11.0
ARG ALPINE_VERSION=3.19

# Stage 1: Builder
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /app

# Instalar apenas necessário
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Copy package*.json e instalar
COPY package*.json ./
RUN npm ci --only=production \
    && npm cache clean --force

# Copy source
COPY . .

# Build (se houver)
RUN npm run build || true

# Stage 2: Runtime
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}

# Labels de segurança
LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# Non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

WORKDIR /app

# Copy apenas o necessário
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup . .

# Metadados de build
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

EXPOSE 3000

# No shell - exec form
ENTRYPOINT ["node"]
CMD ["--enable-source-maps", "dist/index.js"]
