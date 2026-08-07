# DockerLs hardened template -- Java (JRE runtime, jlink-free)
#
# The JDK, Maven and the whole dependency cache stay in the builder stage;
# only the fat jar and a JRE reach the runtime image.
ARG JDK_VERSION=21.0.5_11-jdk-alpine
ARG JRE_VERSION=21.0.5_11-jre-alpine

# ---------------------------------------------------------------------------
# Stage 1: build.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:${JDK_VERSION} AS builder

WORKDIR /src

COPY mvnw pom.xml ./
COPY .mvn ./.mvn
RUN ./mvnw -B dependency:go-offline

COPY src ./src
RUN ./mvnw -B -DskipTests package && \
    cp target/*.jar /app.jar

# ---------------------------------------------------------------------------
# Stage 2: runtime.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:${JRE_VERSION}

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

COPY --from=builder --chown=appuser:appgroup /app.jar /app/app.jar

# Container-aware heap sizing; without it the JVM reads the host's RAM.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["java", "-XX:+ExitOnOutOfMemoryError", "-cp", "/app/app.jar", "HealthCheck"]

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
