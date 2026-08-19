# Dockerfile.hardened.maven-alpine
# Template hardened para aplicação Java construída com Maven (Alpine).
#
# O build usa a imagem oficial do Maven, que carrega JDK e a ferramenta; o
# runtime usa apenas o JRE. Essa separação é o que tira compilador, cache do
# Maven e a árvore de dependências de build da imagem que vai para produção --
# nada disso é necessário para *rodar* a aplicação, e cada um deles é
# superfície de ataque e CVE para triar depois.

ARG MAVEN_VERSION=3.9-eclipse-temurin-21-alpine
ARG JRE_VERSION=21-jre-alpine

# Stage 1: Build
FROM maven:${MAVEN_VERSION} AS builder

WORKDIR /app

# O POM entra sozinho primeiro: assim a camada de dependências só é refeita
# quando o POM muda, e não a cada alteração de código.
COPY pom.xml ./
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:${JRE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN apk upgrade --no-cache \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/target/*.jar /app/app.jar

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD [ -f /app/app.jar ] || exit 1

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
