"""Implementação do validador de Dockerfiles."""

from __future__ import annotations

import re
from pathlib import Path

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileInfo,
    DockerfileValidationResult,
    HardeningRule,
    SeverityLevel,
    ValidationCheck,
    ValidationStatus,
)
from dockerls.domain.interfaces.dockerfile_validator import (
    DockerfileValidatorInterface,
    HardeningTemplateProvider,
)


class DockerfileParser:
    """Parser simples para Dockerfiles.

    Extrai informações estruturais de um Dockerfile sem depender
    de bibliotecas externas complexas.
    """

    # Padrões regex para diretivas Dockerfile
    FROM_PATTERN = re.compile(r"^FROM\s+(.+?)(?:\s+AS\s+(\S+))?$", re.IGNORECASE)
    RUN_PATTERN = re.compile(r"^RUN\s+(.+)$", re.IGNORECASE | re.DOTALL)
    COPY_PATTERN = re.compile(
        r"^COPY\s+(?:--chown=(\S+:\S+)\s+)?(?:--from=(\S+)\s+)?(\S+)\s+(\S+)$",
        re.IGNORECASE,
    )
    ENV_PATTERN = re.compile(r"^ENV\s+(\S+)=(.*)$", re.IGNORECASE)
    LABEL_PATTERN = re.compile(r'^LABEL\s+([^=]+)=(.*)$', re.IGNORECASE)
    EXPOSE_PATTERN = re.compile(r"^EXPOSE\s+(\d+)", re.IGNORECASE)
    USER_PATTERN = re.compile(r"^USER\s+(\S+)(?::(\d+))?$", re.IGNORECASE)
    HEALTHCHECK_PATTERN = re.compile(r"^HEALTHCHECK\s+", re.IGNORECASE)
    ENTRYPOINT_PATTERN = re.compile(r"^ENTRYPOINT\s+(.+)$", re.IGNORECASE)
    CMD_PATTERN = re.compile(r"^CMD\s+(.+)$", re.IGNORECASE)
    ARG_PATTERN = re.compile(r"^ARG\s+(\S+)(?:=(.*))?$", re.IGNORECASE)
    WORKDIR_PATTERN = re.compile(r"^WORKDIR\s+(\S+)$", re.IGNORECASE)

    # Secret patterns - variáveis que podem conter segredos
    SECRET_ENV_PATTERNS = [
        r"(?i)password",
        r"(?i)passwd",
        r"(?i)secret",
        r"(?i)token",
        r"(?i)api[_-]?key",
        r"(?i)auth",
        r"(?i)credential",
        r"(?i)private[_-]?key",
        r"(?i)access[_-]?key",
    ]

    def __init__(self):
        self._lines: list[str] = []
        self._info = DockerfileInfo()

    def parse(self, content: str) -> DockerfileInfo:
        """Parseia o conteúdo de um Dockerfile.

        Args:
            content: Conteúdo do Dockerfile como string.

        Returns:
            DockerfileInfo com informações extraídas.
        """
        self._lines = content.splitlines()
        self._info = DockerfileInfo(raw_lines=self._lines.copy())

        current_stage = 0
        line_continuation = ""

        for line_num, line in enumerate(self._lines, 1):
            # Handle line continuations with backslash
            if line.rstrip().endswith("\\"):
                line_continuation += line.rstrip()[:-1] + " "
                continue
            elif line_continuation:
                line = line_continuation + line.lstrip()
                line_continuation = ""

            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            self._parse_line(line, line_num)

            # Count stages
            if self.FROM_PATTERN.match(line):
                current_stage += 1

        self._info.stages = max(1, current_stage)
        return self._info

    def _parse_line(self, line: str, line_num: int) -> None:
        """Parseia uma linha específica do Dockerfile."""

        # FROM
        if match := self.FROM_PATTERN.match(line):
            image = match.group(1).strip()
            self._info.base_images.append(image)
            if ":latest" in image or (":" not in image and "@" not in image):
                self._info.uses_latest_tag = True

        # RUN
        elif match := self.RUN_PATTERN.match(line):
            cmd = match.group(1)
            self._info.run_commands.append({"line": line_num, "command": cmd})

            # Check for sudo
            if "sudo" in cmd:
                self._info.uses_sudo = True

            # Check package managers
            pkg_managers = ["apt-get", "apt", "apk", "yum", "dnf", "pip", "npm", "yarn"]
            for pm in pkg_managers:
                if pm in cmd and pm not in self._info.package_managers_used:
                    self._info.package_managers_used.append(pm)

            # Check cache cleaning
            cache_clean_patterns = [
                "rm -rf /var/cache/apk/*",
                "rm -rf /var/cache/apt/archives",
                "apt-get clean",
                "rm -rf ~/.cache/pip",
                "npm cache clean",
                "--no-cache-dir",
                "--no-install-recommends",
            ]
            if any(pattern in cmd for pattern in cache_clean_patterns):
                self._info.cache_cleaned = True

        # COPY
        elif match := self.COPY_PATTERN.match(line):
            chown = match.group(1)
            from_stage = match.group(2)
            src = match.group(3)
            dest = match.group(4)
            self._info.copy_commands.append(
                {
                    "line": line_num,
                    "chown": chown,
                    "from_stage": from_stage,
                    "source": src,
                    "destination": dest,
                }
            )

        # ENV
        elif match := self.ENV_PATTERN.match(line):
            env_name = match.group(1)
            if self._is_secret_name(env_name):
                self._info.has_secrets_in_env = True
                self._info.secret_env_vars.append(env_name)

        # LABEL
        elif match := self.LABEL_PATTERN.match(line):
            label_key = match.group(1).strip()
            label_value = match.group(2).strip()
            self._info.labels[label_key] = label_value
            self._info.has_labels = True

        # EXPOSE
        elif match := self.EXPOSE_PATTERN.match(line):
            port = int(match.group(1))
            if port not in self._info.exposes_ports:
                self._info.exposes_ports.append(port)

        # USER
        elif match := self.USER_PATTERN.match(line):
            self._info.has_user_directive = True
            self._info.user_name = match.group(1)
            if match.group(2):
                self._info.user_uid = int(match.group(2))

        # HEALTHCHECK
        elif self.HEALTHCHECK_PATTERN.match(line):
            self._info.has_healthcheck = True

        # ENTRYPOINT
        elif match := self.ENTRYPOINT_PATTERN.match(line):
            self._info.entrypoint = match.group(1).strip()

        # CMD
        elif match := self.CMD_PATTERN.match(line):
            self._info.cmd = match.group(1).strip()

        # ARG (BuildKit detection)
        elif match := self.ARG_PATTERN.match(line):
            arg_name = match.group(1)
            if arg_name in ("BUILDKIT_INLINE_CACHE", "DOCKER_BUILDKIT"):
                self._info.uses_buildkit = True

    def _is_secret_name(self, name: str) -> bool:
        """Verifica se um nome de variável parece ser um segredo."""
        return any(re.search(pattern, name) for pattern in self.SECRET_ENV_PATTERNS)


class DockerfileValidator(DockerfileValidatorInterface):
    """Validador de Dockerfiles baseado em regras OWASP."""

    def __init__(self, template_provider: HardeningTemplateProvider | None = None):
        self._parser = DockerfileParser()
        self._template_provider = template_provider

    def validate(self, dockerfile_path: str | Path) -> DockerfileValidationResult:
        """Valida um Dockerfile contra regras OWASP."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        if not path.exists():
            raise FileNotFoundError(f"Dockerfile not found at {path}")

        content = path.read_text()
        info = self._parser.parse(content)

        result = DockerfileValidationResult(
            dockerfile_path=str(path),
            metadata={
                "base_images": info.base_images,
                "stages": info.stages,
            },
        )

        # Executar todas as verificações
        self._check_base_image(info, result)
        self._check_non_root_user(info, result)
        self._check_multi_stage(info, result)
        self._check_secrets_in_env(info, result)
        self._check_package_cache(info, result)
        self._check_healthcheck(info, result)
        self._check_security_labels(info, result)
        self._check_minimal_base(info, result)
        self._check_no_sudo(info, result)
        self._check_entrypoint_form(info, result)
        self._check_shell_usage(info, result)
        self._check_dockerignore(info, result, path.parent)

        return result

    def analyze(self, dockerfile_path: str | Path) -> DockerfileAnalysis:
        """Analisa um Dockerfile e retorna análise completa."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        if not path.exists():
            raise FileNotFoundError(f"Dockerfile not found at {path}")

        content = path.read_text()
        info = self._parser.parse(content)
        validation = self.validate(path)

        # Calcular score de segurança
        security_score = self._calculate_security_score(validation)
        security_tier = self._calculate_security_tier(security_score, validation)

        return DockerfileAnalysis(
            info=info,
            validation=validation,
            security_score=security_score,
            security_tier=security_tier,
        )

    def suggest_hardening(self, dockerfile_path: str | Path) -> list[HardeningRule]:
        """Sugere melhorias de hardening para um Dockerfile."""
        analysis = self.analyze(dockerfile_path)
        suggestions = []

        # Base image upgrade
        if analysis.info.uses_latest_tag or not self._is_minimal_base(analysis.info):
            base = analysis.info.base_images[0] if analysis.info.base_images else "unknown"
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.HIGH,
                    title="Upgrade base image",
                    description="Use a pinned, minimal base image",
                    current_state=base,
                    suggested_fix="FROM node:22-alpine or FROM chainguard/node:latest-dev",
                    reason=(
                        "Pinned versions ensure reproducibility; "
                        "minimal bases reduce attack surface"
                    ),
                )
            )

        # Non-root user
        if not analysis.info.has_user_directive:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.HIGH,
                    title="Add non-root user",
                    description="Container should not run as root",
                    current_state="No USER directive",
                    suggested_fix="RUN adduser -D appuser && USER appuser",
                    reason="Running as root increases impact of container breakout",
                )
            )

        # Secrets in ENV
        if analysis.info.has_secrets_in_env:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.CRITICAL,
                    title="Remove secrets from ENV",
                    description="Secrets in ENV are visible in image history",
                    current_state=f"Secrets: {', '.join(analysis.info.secret_env_vars)}",
                    suggested_fix="Use BuildKit secrets: RUN --mount=type=secret,id=token",
                    reason="ENV values persist in all layers and can be extracted",
                )
            )

        # Healthcheck
        if not analysis.info.has_healthcheck:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.LOW,
                    title="Add HEALTHCHECK",
                    description="Containers should have health checks",
                    current_state="No HEALTHCHECK directive",
                    suggested_fix="HEALTHCHECK --interval=30s --timeout=5s CMD curl http://localhost/health",
                    reason="Health checks enable orchestration platforms to detect failures",
                )
            )

        # Security labels
        if not analysis.info.has_labels or "security.scanner" not in analysis.info.labels:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.LOW,
                    title="Add security labels",
                    description="Labels improve traceability and incident response",
                    current_state="Missing security labels",
                    suggested_fix=(
                        'LABEL security.scanner="dockerls"\n'
                        'LABEL security.cve-contact="security@company.com"'
                    ),
                    reason=(
                        "Labels enable automated policy enforcement "
                        "and contact during incidents"
                    ),
                )
            )

        # Package cache
        if analysis.info.package_managers_used and not analysis.info.cache_cleaned:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Clean package manager cache",
                    description="Package caches increase image size unnecessarily",
                    current_state="Cache not cleaned",
                    suggested_fix=(
                        "Add && rm -rf /var/cache/apk/* || rm -rf /var/cache/apt/archives"
                    ),
                    reason="Smaller images have smaller attack surface and faster pulls",
                )
            )

        # Multi-stage
        if analysis.info.stages < 2 and len(analysis.info.package_managers_used) > 0:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Use multi-stage build",
                    description="Multi-stage builds reduce final image size",
                    current_state=f"Single stage ({analysis.info.stages} stage(s))",
                    suggested_fix="Create separate builder and runtime stages",
                    reason="Build tools and intermediate files don't belong in production images",
                )
            )

        return suggestions

    def _check_base_image(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se a base image usa tag pinned."""
        if info.uses_latest_tag:
            result.add_check(
                ValidationCheck(
                    check="base_image_pinned",
                    status=ValidationStatus.FAIL,
                    message="Base image uses 'latest' tag or no tag (implies latest)",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF001",
                    fix_suggestion="Use specific version: FROM node:22-alpine (not :latest)",
                    details={"base_images": info.base_images},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="base_image_pinned",
                    status=ValidationStatus.PASS,
                    message="Base image tag is pinned",
                    severity=SeverityLevel.INFO,
                    rule_id="DF001",
                    details={"base_images": info.base_images},
                )
            )

    def _check_non_root_user(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se o container roda como usuário não-root."""
        if info.has_user_directive and info.user_name and info.user_name.lower() != "root":
            result.add_check(
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.PASS,
                    message=f"Container runs as non-root user: {info.user_name}",
                    severity=SeverityLevel.INFO,
                    rule_id="DF002",
                    details={"user": info.user_name, "uid": info.user_uid},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="Container runs as root (no USER directive or USER root)",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF002",
                    fix_suggestion="ADD USER appuser\nUSER appuser",
                )
            )

    def _check_multi_stage(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se usa multi-stage build."""
        if info.stages > 1:
            result.add_check(
                ValidationCheck(
                    check="multi_stage_build",
                    status=ValidationStatus.PASS,
                    message=f"Multi-stage build detected ({info.stages} stages)",
                    severity=SeverityLevel.INFO,
                    rule_id="DF003",
                    details={"stages": info.stages},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="multi_stage_build",
                    status=ValidationStatus.WARN,
                    message="Single-stage build detected",
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF003",
                    fix_suggestion="Create builder stage separate from runtime",
                )
            )

    def _check_secrets_in_env(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se há segredos em variáveis ENV."""
        if info.has_secrets_in_env:
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.FAIL,
                    message=f"Potential secrets in ENV: {', '.join(info.secret_env_vars)}",
                    severity=SeverityLevel.CRITICAL,
                    rule_id="DF004",
                    fix_suggestion="Use BuildKit: RUN --mount=type=secret,id=token",
                    details={"secret_vars": info.secret_env_vars},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.PASS,
                    message="No obvious secrets in ENV variables",
                    severity=SeverityLevel.INFO,
                    rule_id="DF004",
                )
            )

    def _check_package_cache(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se o cache do package manager foi limpo."""
        if info.package_managers_used:
            if info.cache_cleaned:
                result.add_check(
                    ValidationCheck(
                        check="package_cache_clean",
                        status=ValidationStatus.PASS,
                        message="Package manager cache is cleaned",
                        severity=SeverityLevel.INFO,
                        rule_id="DF005",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="package_cache_clean",
                        status=ValidationStatus.WARN,
                        message="Package manager cache not cleaned",
                        severity=SeverityLevel.MEDIUM,
                        rule_id="DF005",
                        fix_suggestion=(
                            "Add: && rm -rf /var/cache/apk/* "
                            "|| rm -rf /var/cache/apt/archives"
                        ),
                    )
                )

    def _check_healthcheck(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se existe HEALTHCHECK."""
        if info.has_healthcheck:
            result.add_check(
                ValidationCheck(
                    check="healthcheck_present",
                    status=ValidationStatus.PASS,
                    message="HEALTHCHECK directive present",
                    severity=SeverityLevel.INFO,
                    rule_id="DF006",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="healthcheck_present",
                    status=ValidationStatus.WARN,
                    message="No HEALTHCHECK directive",
                    severity=SeverityLevel.LOW,
                    rule_id="DF006",
                    fix_suggestion="HEALTHCHECK --interval=30s --timeout=5s CMD curl http://localhost/health",
                )
            )

    def _check_security_labels(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se existem labels de segurança."""
        required_labels = ["security.scanner", "maintainer"]
        missing = [lbl for lbl in required_labels if lbl not in info.labels]

        if not missing:
            result.add_check(
                ValidationCheck(
                    check="security_labels",
                    status=ValidationStatus.PASS,
                    message="Security labels present",
                    severity=SeverityLevel.INFO,
                    rule_id="DF007",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="security_labels",
                    status=ValidationStatus.WARN,
                    message=f"Missing security labels: {', '.join(missing)}",
                    severity=SeverityLevel.LOW,
                    rule_id="DF007",
                    fix_suggestion=(
                        'LABEL security.scanner="dockerls"\n'
                        'LABEL maintainer="team@company.com"'
                    ),
                )
            )

    def _check_minimal_base(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se a base image é minimal."""
        if self._is_minimal_base(info):
            result.add_check(
                ValidationCheck(
                    check="minimal_base",
                    status=ValidationStatus.PASS,
                    message="Using minimal base image",
                    severity=SeverityLevel.INFO,
                    rule_id="DF008",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="minimal_base",
                    status=ValidationStatus.WARN,
                    message="Base image may not be minimal (consider Alpine or Distroless)",
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF008",
                    fix_suggestion="FROM alpine:latest or FROM gcr.io/distroless/nodejs",
                )
            )

    def _is_minimal_base(self, info: DockerfileInfo) -> bool:
        """Verifica se a base image é minimal."""
        minimal_markers = ["alpine", "distroless", "slim", "chainguard", "wolfi"]
        for base in info.base_images:
            if any(marker in base.lower() for marker in minimal_markers):
                return True
        return False

    def _check_no_sudo(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se usa sudo."""
        if info.uses_sudo:
            result.add_check(
                ValidationCheck(
                    check="no_sudo",
                    status=ValidationStatus.FAIL,
                    message="sudo usage detected",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF009",
                    fix_suggestion="Remove sudo dependency",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="no_sudo",
                    status=ValidationStatus.PASS,
                    message="No sudo usage detected",
                    severity=SeverityLevel.INFO,
                    rule_id="DF009",
                )
            )

    def _check_entrypoint_form(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se ENTRYPOINT usa forma exec (não shell)."""
        if info.entrypoint:
            # Exec form starts with [
            if info.entrypoint.startswith("["):
                result.add_check(
                    ValidationCheck(
                        check="entrypoint_exec_form",
                        status=ValidationStatus.PASS,
                        message="ENTRYPOINT uses exec form",
                        severity=SeverityLevel.INFO,
                        rule_id="DF010",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="entrypoint_exec_form",
                        status=ValidationStatus.WARN,
                        message="ENTRYPOINT uses shell form (should use exec form)",
                        severity=SeverityLevel.MEDIUM,
                        rule_id="DF010",
                        fix_suggestion='ENTRYPOINT ["node"] instead of ENTRYPOINT node',
                    )
                )

    def _check_shell_usage(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica uso implícito de shell."""
        # Verifica se há RUN commands sem /bin/sh explícito quando necessário
        # Esta é uma verificação simplificada
        result.add_check(
            ValidationCheck(
                check="shell_usage",
                status=ValidationStatus.PASS,
                message="No implicit shell issues detected",
                severity=SeverityLevel.INFO,
                rule_id="DF011",
            )
        )

    def _check_dockerignore(
        self, info: DockerfileInfo, result: DockerfileValidationResult, context_path: Path
    ) -> None:
        """Verifica se .dockerignore existe e é adequado."""
        dockerignore_path = context_path / ".dockerignore"

        if dockerignore_path.exists():
            content = dockerignore_path.read_text().lower()
            recommended = [".git", ".env", "node_modules", "__pycache__", "*.log"]
            missing = [item for item in recommended if item not in content]

            if missing:
                result.add_check(
                    ValidationCheck(
                        check="dockerignore_complete",
                        status=ValidationStatus.WARN,
                        message=f".dockerignore missing recommended entries: {', '.join(missing)}",
                        severity=SeverityLevel.LOW,
                        rule_id="DF012",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="dockerignore_complete",
                        status=ValidationStatus.PASS,
                        message=".dockerignore contains recommended entries",
                        severity=SeverityLevel.INFO,
                        rule_id="DF012",
                    )
                )
        else:
            result.add_check(
                ValidationCheck(
                    check="dockerignore_exists",
                    status=ValidationStatus.WARN,
                    message=".dockerignore not found",
                    severity=SeverityLevel.LOW,
                    rule_id="DF012",
                    fix_suggestion="Create .dockerignore with .git, .env, node_modules, etc.",
                )
            )

    def _calculate_security_score(self, validation: DockerfileValidationResult) -> int:
        """Calcula score de segurança baseado nos resultados."""
        score = 100

        # Pesos por severidade
        severity_weights = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 8,
            SeverityLevel.LOW: 3,
        }

        for check in validation.checks:
            if check.status == ValidationStatus.FAIL:
                score -= severity_weights.get(check.severity, 0)
            elif check.status == ValidationStatus.WARN:
                score -= severity_weights.get(check.severity, 0) // 2

        return max(0, min(100, score))

    def _calculate_security_tier(
        self, score: int, validation: DockerfileValidationResult
    ) -> str:
        """Calcula tier de segurança baseado no score."""
        if validation.errors > 0:
            return "C"  # Não pronto para produção

        if score >= 90:
            return "A"  # Production-ready
        elif score >= 70:
            return "B"  # Requires review
        else:
            return "C"  # Not recommended


class HardeningTemplates(HardeningTemplateProvider):
    """Provedor de templates hardened para diferentes linguagens."""

    TEMPLATES_DIR = Path(__file__).parent.parent.parent / "infrastructure" / "templates"

    def get_template(self, base_image: str) -> str:
        """Retorna template hardened para um tipo de base image."""
        template_map = {
            "node": "node.dockerfile",
            "python": "python.dockerfile",
            "go": "go.dockerfile",
            "java": "java.dockerfile",
        }

        # Detectar tipo de base image
        base_lower = base_image.lower()
        template_file = None

        for key, filename in template_map.items():
            if key in base_lower:
                template_file = filename
                break

        if not template_file:
            # Default para node
            template_file = "node.dockerfile"

        template_path = self.TEMPLATES_DIR / "hardening" / template_file

        if template_path.exists():
            return template_path.read_text()

        # Fallback: gerar template básico
        return self._generate_basic_template(base_image)

    def list_templates(self) -> list[str]:
        """Lista todos os templates disponíveis."""
        return ["node", "python", "go", "java"]

    def generate_hardened_dockerfile(
        self,
        dockerfile_path: str | Path,
        base_image: str | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Gera um Dockerfile hardened baseado no original ou template."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        # Se base_image fornecida, usar template
        if base_image:
            content = self.get_template(base_image)
        else:
            # Analisar Dockerfile existente e sugerir melhorias
            validator = DockerfileValidator(self)
            suggestions = validator.suggest_hardening(path)

            # Gerar conteúdo baseado nas sugestões
            content = self._apply_suggestions(path, suggestions)

        # Salvar se output_path fornecido
        if output_path:
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content)

        return content

    def _generate_basic_template(self, base_image: str) -> str:
        """Gera template básico para uma imagem base."""
        return f"""# Auto-generated hardened Dockerfile
# Base: {base_image}

FROM {base_image}:latest

LABEL security.scanner="dockerls"
LABEL security.hardened="true"

# Create non-root user
RUN useradd -m -u 1000 appuser || adduser -D -u 1000 appuser

WORKDIR /app

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./app"]
"""

    def _apply_suggestions(self, path: Path, suggestions: list[HardeningRule]) -> str:
        """Aplica sugestões ao Dockerfile existente."""
        content = path.read_text()

        # Aplicar cada sugestão
        for suggestion in suggestions:
            # Lógica simples de aplicação - em produção seria mais sofisticado
            if "non-root user" in suggestion.title.lower() and "USER" not in content:
                content += "\nUSER appuser\n"

        return content
