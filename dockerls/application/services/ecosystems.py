"""Conhecimento especializado de ecossistemas, runtimes e particularidades de segurança."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EcosystemInsight:
    ecosystem: str
    version: str
    runtime_features: list[str] = field(default_factory=list)
    base_distro_advice: list[str] = field(default_factory=list)
    security_guidelines: list[str] = field(default_factory=list)
    common_pitfalls: list[str] = field(default_factory=list)
    recommended_dockerfile_snippets: list[str] = field(default_factory=list)


def detect_ecosystem_and_version(image_reference: str) -> tuple[str, str, str]:
    """Detecta ecossistema (node, python, go, etc.), versão e distribuição base."""
    ref_lower = image_reference.lower()

    # 1. Ecossistema
    ecosystem = "generic"
    if any(k in ref_lower for k in ("node", "npm", "yarn", "bun")):
        ecosystem = "node"
    elif any(k in ref_lower for k in ("python", "pypy", "pip")):
        ecosystem = "python"
    elif "golang" in ref_lower or "go" in ref_lower.split(":")[-1] or ref_lower.startswith("go:"):
        ecosystem = "go"
    elif "rust" in ref_lower:
        ecosystem = "rust"
    elif any(k in ref_lower for k in ("temurin", "openjdk", "java", "corretto")):
        ecosystem = "java"
    elif "php" in ref_lower:
        ecosystem = "php"
    elif "ruby" in ref_lower:
        ecosystem = "ruby"
    elif "dotnet" in ref_lower or "aspnet" in ref_lower:
        ecosystem = "dotnet"

    # 2. Versão
    version = ""
    tag_part = ref_lower.split(":")[-1] if ":" in ref_lower else ref_lower
    v_match = re.search(r"(\d+(?:\.\d+)*)", tag_part)
    if v_match:
        version = v_match.group(1)

    # 3. Distro base
    distro = "debian/ubuntu"
    if "alpine" in ref_lower:
        distro = "alpine"
    elif "distroless" in ref_lower:
        distro = "distroless"
    elif "wolfi" in ref_lower or "chainguard" in ref_lower:
        distro = "wolfi/chainguard"
    elif "scratch" in ref_lower:
        distro = "scratch"
    elif "slim" in ref_lower:
        distro = "debian-slim"

    return ecosystem, version, distro


def get_ecosystem_insights(image_reference: str) -> EcosystemInsight:
    """Gera insights técnicos e de segurança detalhados para a imagem e versão."""
    ecosystem, version, distro = detect_ecosystem_and_version(image_reference)

    if ecosystem == "node":
        major = version.split(".")[0] if version else "22"
        runtime_features = [
            f"Node.js {major}.x V8 Engine com suporte otimizado a ECMAScript Modules (ESM).",
            "Suporte nativo a variáveis de ambiente (--env-file=.env) dispensando dotenv.",
            "Cliente WebSocket nativo e suporte nativo a fetch API (Undici).",
            "Suporte nativo a Corepack para gerenciamento de yarn/pnpm.",
        ]
        base_advice = []
        if distro == "alpine":
            base_advice.extend(
                [
                    "⚠️ Alpine usa musl libc: Pacotes nativos C++ (sharp, bcrypt, sqlite3) "
                    "exigem compilação ou 'libc6-compat'.",
                    "💡 Para máxima compatibilidade sem overhead de compilação, "
                    "considere 'node:22-bookworm-slim' (glibc).",
                    "💡 Imagens oficiais 'node:alpine' já contêm o usuário "
                    "non-root 'node' (UID: 1000, GID: 1000).",
                ]
            )
        else:
            base_advice.extend(
                [
                    "✅ Debian Slim oferece compatibilidade total com binários "
                    "pré-compilados glibc.",
                    "💡 Considere 'distroless/nodejs22-debian12' para remover o shell.",
                ]
            )

        security = [
            "Defina 'ENV NODE_ENV=production' para ativar otimizações de runtime "
            "e desativar devDependencies.",
            "O CLI do npm embutido possui ciclo de CVEs independente: execute "
            "'RUN npm install -g npm@latest' ou remova-o no multi-stage.",
            "Ajuste '--max-old-space-size' para evitar que o Node exceda o limite "
            "de memória do container.",
            "Utilize 'USER node' (ou crie UID 10001) para nunca executar como root.",
        ]
        pitfalls = [
            "Evite rodar 'npm start' como PID 1 (o npm não repassa sinais SIGTERM); "
            'use \'CMD ["node", "dist/index.js"]\'.',
            "Não inclua 'node_modules' na raiz do build context sem .dockerignore.",
        ]
        snippets = [
            'ENV NODE_ENV=production\nUSER node\nCMD ["--enable-source-maps", "dist/index.js"]',
            'HEALTHCHECK --interval=30s --timeout=5s CMD node -e "'
            "require('http').get('http://localhost:3000/health', (r) => {"
            "if (r.statusCode !== 200) process.exit(1)"
            "}).on('error', () => process.exit(1))\"",
        ]
        return EcosystemInsight(
            ecosystem="Node.js",
            version=version or "22.x",
            runtime_features=runtime_features,
            base_distro_advice=base_advice,
            security_guidelines=security,
            common_pitfalls=pitfalls,
            recommended_dockerfile_snippets=snippets,
        )

    elif ecosystem == "python":
        runtime_features = [
            "Python runtime com isolamento de dependências via multi-stage builder.",
            "Suporte a Python 3.11/3.12/3.13 com melhorias de velocidade de execução.",
        ]
        base_advice = []
        if distro == "alpine":
            base_advice.extend(
                [
                    "⚠️ Alpine musl não suporta wheels manylinux. Bibliotecas como pandas, "
                    "numpy e cryptography compilam do zero (lento e exige gcc).",
                    "💡 Para Python com dependências C/C++, 'python:3.12-slim-bookworm' "
                    "é muito mais rápido no build e gera imagens menores.",
                ]
            )
        else:
            base_advice.extend(
                [
                    "✅ Debian Slim suporta todos os wheels pré-compilados manylinux "
                    "do PyPI sem necessidade de compiladores no container final.",
                ]
            )

        security = [
            "Configure 'ENV PYTHONUNBUFFERED=1' para logs em tempo real sem buffering.",
            "Configure 'ENV PYTHONDONTWRITEBYTECODE=1' para não gerar arquivos .pyc.",
            "Instale dependências com 'pip install --no-cache-dir --user -r requirements.txt' "
            "no builder e copie '/root/.local' para o usuário não-root.",
            "Crie um usuário 'appuser' (UID 10001) para executar o processo.",
        ]
        pitfalls = [
            "Não use healthchecks dependentes de 'requests' externos; "
            "use 'urllib.request.urlopen' da biblioteca padrão.",
        ]
        snippets = [
            (
                "ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1\n"
                'USER appuser\nCMD ["python", "-u", "main.py"]'
            ),
            (
                'HEALTHCHECK --interval=30s --timeout=5s CMD python -c "'
                "import urllib.request; "
                "urllib.request.urlopen('http://localhost:8000/health', timeout=3)\" || exit 1"
            ),
        ]
        return EcosystemInsight(
            ecosystem="Python",
            version=version or "3.12.x",
            runtime_features=runtime_features,
            base_distro_advice=base_advice,
            security_guidelines=security,
            common_pitfalls=pitfalls,
            recommended_dockerfile_snippets=snippets,
        )

    elif ecosystem == "go":
        return EcosystemInsight(
            ecosystem="Go",
            version=version or "1.23.x",
            runtime_features=[
                "Binários nativos estáticos sem dependência de interpretadores ou runtime.",
            ],
            base_distro_advice=[
                "✅ Imagens 'scratch' ou distroless oferecem a menor superfície (ZERO CVEs).",
                "💡 Copie '/etc/ssl/certs/ca-certificates.crt' do builder para chamadas HTTPS.",
            ],
            security_guidelines=[
                "Compile com 'CGO_ENABLED=0 GOOS=linux go build -ldflags=\"-s -w\" -o app .'.",
                "Em 'scratch', use 'USER 65534:65534' (nobody) pois não existe /etc/passwd.",
            ],
            common_pitfalls=[
                "Não use healthchecks em formato shell em scratch; "
                'use exec: CMD ["/app", "-health"].',
            ],
            recommended_dockerfile_snippets=[
                "FROM scratch\n"
                "COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/\n"
                'COPY --from=builder /app/app /app\nUSER 65534:65534\nENTRYPOINT ["/app"]',
            ],
        )

    elif ecosystem == "java":
        return EcosystemInsight(
            ecosystem="Java / JVM",
            version=version or "21 LTS",
            runtime_features=[
                "Eclipse Temurin / Amazon Corretto JRE com suporte a containers.",
            ],
            base_distro_advice=[
                "✅ Use 'eclipse-temurin:21-jre-alpine' em vez do JDK completo "
                "para reduzir mais de 300MB de ferramentas desnecessárias.",
            ],
            security_guidelines=[
                "Configure 'JAVA_OPTS=\"-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 "
                "-Djava.security.egd=file:/dev/./urandom\"'.",
                "Execute como usuário non-root 'appuser' (UID 10001).",
            ],
            common_pitfalls=[
                "Evite alocar memória fixa (-Xmx) sem considerar o limite do container.",
            ],
            recommended_dockerfile_snippets=[
                'ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"\n'
                "USER appuser\n"
                'ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]',
            ],
        )

    elif ecosystem == "rust":
        return EcosystemInsight(
            ecosystem="Rust",
            version=version or "1.82",
            runtime_features=[
                "Binários nativos estáticos com musl e target-feature=+crt-static.",
            ],
            base_distro_advice=[
                "✅ Imagens 'scratch' ou distroless reduzem CVEs a zero.",
            ],
            security_guidelines=[
                "Use 'cargo build --release --target x86_64-unknown-linux-musl'.",
                "Execute como non-root 'USER 65534:65534'.",
            ],
            common_pitfalls=[],
            recommended_dockerfile_snippets=[
                (
                    "FROM scratch\n"
                    "COPY --from=builder /app/binary /app\n"
                    'USER 65534:65534\nENTRYPOINT ["/app"]'
                ),
            ],
        )

    elif ecosystem == "php":
        return EcosystemInsight(
            ecosystem="PHP",
            version=version or "8.3",
            runtime_features=[
                "PHP 8.3 com JIT e Opcache habilitado.",
            ],
            base_distro_advice=[
                "✅ Use multi-stage com 'composer:2' no builder e copie apenas '/app/vendor'.",
            ],
            security_guidelines=[
                "Habilite Opcache para desempenho e execute com non-root (UID 10001).",
            ],
            common_pitfalls=[],
            recommended_dockerfile_snippets=[
                'USER appuser\nCMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]',
            ],
        )

    return EcosystemInsight(
        ecosystem="Generic Container",
        version=version or "latest",
        runtime_features=["Container Linux padrão."],
        base_distro_advice=["Prefira distribuições minimalistas como Alpine ou Distroless."],
        security_guidelines=[
            "Nunca execute como root (USER 10001).",
            "Mantenha um .dockerignore limpo.",
            "Use healthchecks para monitoramento de liveness/readiness.",
        ],
        common_pitfalls=[],
        recommended_dockerfile_snippets=[],
    )
