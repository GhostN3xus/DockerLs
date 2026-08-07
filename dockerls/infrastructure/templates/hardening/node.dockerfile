# DockerLs hardened template -- Node.js
#
# Passes every rule in `dockerls build --validate-only`. Replace the
# maintainer/contact labels and the healthcheck endpoint with your own.
ARG NODE_VERSION=22.11.0
ARG ALPINE_VERSION=3.19

# ---------------------------------------------------------------------------
# Stage 1: build. Compilers and dev dependencies live here and are discarded.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /app

# Native module toolchain; --no-cache keeps the index out of the layer.
RUN apk add --no-cache python3 make g++

# Manifests first: this layer is cached until the dependencies change.
COPY package*.json ./

# --mount=type=secret keeps a registry token out of the image history.
# Build with: docker build --secret id=npm_token,env=NPM_TOKEN .
RUN --mount=type=secret,id=npm_token \
    if [ -f /run/secrets/npm_token ]; then \
        npm config set //registry.npmjs.org/:_authToken="$(cat /run/secrets/npm_token)"; \
    fi && \
    npm ci --omit=dev && \
    npm cache clean --force && \
    rm -f /root/.npmrc

COPY . .

RUN npm run build --if-present

# ---------------------------------------------------------------------------
# Stage 2: runtime. Only the artefacts, running unprivileged.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}

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

COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --chown=appuser:appgroup package*.json ./

ENV NODE_ENV=production

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

ENTRYPOINT ["node"]
CMD ["--enable-source-maps", "dist/index.js"]
