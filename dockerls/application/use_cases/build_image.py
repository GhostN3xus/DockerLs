"""Use case para construir imagens Docker com segurança."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileValidationResult,
    HardeningRule,
    ValidationStatus,
)
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable

if TYPE_CHECKING:
    from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
    from dockerls.domain.interfaces.dockerfile_validator import (
        DockerfileValidatorInterface,
        HardeningTemplateProvider,
    )


@dataclass
class BuildOptions:
    """Opções de build."""

    tag: str
    dockerfile_path: str = "Dockerfile"
    context_path: str = "."
    no_cache: bool = False
    build_args: dict[str, str] | None = None
    labels: dict[str, str] | None = None
    platform: str | None = None
    target: str | None = None
    pull: bool = True
    buildkit: bool = True
    secrets: dict[str, str] | None = None  # id -> file_path
    ssh: list[str] | None = None  # SSH agents


@dataclass
class BuildResult:
    """Resultado do build."""

    success: bool
    image_tag: str | None = None
    image_id: str | None = None
    image_sha256: str | None = None
    build_time_seconds: float = 0.0
    layers_count: int = 0
    image_size_bytes: int = 0
    error_message: str | None = None
    logs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Resultado do scan de segurança."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total_vulnerabilities: int = 0
    fixable: int = 0
    scan_tool: str = "trivy"
    scan_time_seconds: float = 0.0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    sbom_components_count: int = 0


@dataclass
class BuildReport:
    """Relatório completo de build."""

    build_id: str
    timestamp: str
    image: str
    dockerfile_path: str
    validation: dict[str, Any]
    scan_results: dict[str, Any] | None = None
    security_score: int = 0
    security_tier: str = "F"
    layers: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    sbom: dict[str, Any] | None = None
    build_metadata: dict[str, Any] | None = None


@dataclass
class BuildImageRequest:
    """Request para build de imagem."""

    context_path: str
    tag: str
    dockerfile_path: str = "Dockerfile"
    hardened: bool = False
    base_template: str | None = None
    scan: bool = True
    validate_only: bool = False
    suggest_only: bool = False
    no_cache: bool = False
    build_args: dict[str, str] | None = None
    labels: dict[str, str] | None = None
    fail_on: str | None = None  # "critical", "high"
    ci_mode: bool = False
    verbose: bool = False
    force: bool = False


@dataclass
class BuildImageResponse:
    """Resposta do build de imagem.

    `validation` e `analysis` carregam o resultado bruto da validação para
    que a camada CLI possa renderizar a tabela de checks. Sem eles o
    comando só sabia dizer "falhou", sem qual regra falhou.
    """

    success: bool
    image_tag: str | None = None
    image_sha256: str | None = None
    report: BuildReport | None = None
    validation: DockerfileValidationResult | None = None
    analysis: DockerfileAnalysis | None = None
    recommendations: list[HardeningRule] = field(default_factory=list)
    error: str | None = None
    exit_code: int = EXIT_OK


class BuildImageUseCase:
    """Caso de uso para construção segura de imagens Docker."""

    def __init__(
        self,
        validator: DockerfileValidatorInterface,
        template_provider: HardeningTemplateProvider,
    ):
        self.validator = validator
        self.template_provider = template_provider

    def execute(self, request: BuildImageRequest) -> BuildImageResponse:
        """Executa o build seguro da imagem."""
        logger.debug(f"Iniciando build seguro: {request.context_path}")

        try:
            # 1. Validar Dockerfile. Uma falha aqui (Dockerfile ausente,
            #    ilegível) é erro de execução, não violação de política, e
            #    --force não cria um Dockerfile que não existe.
            validation_result = self._validate_dockerfile(request)
            if not validation_result.success:
                return BuildImageResponse(
                    success=False,
                    error=validation_result.error or "Dockerfile validation could not run",
                    exit_code=EXIT_ERROR,
                )

            # 2. Modo validate-only
            if request.validate_only:
                return self._format_validation_response(validation_result)

            # 3. Modo suggest-only
            if request.suggest_only:
                return self._format_suggestions_response(validation_result)

            # 3b. Validação com erros barra o build (a menos que --force).
            #     A resposta carrega os checks para o CLI dizer o que falhou.
            validation = validation_result.validation
            if validation is not None and validation.errors > 0 and not request.force:
                return self._format_validation_response(validation_result)

            # 4. Gerar Dockerfile hardened se solicitado
            dockerfile_path = request.dockerfile_path
            if request.hardened or request.base_template:
                dockerfile_path = self._generate_hardened_dockerfile(
                    request.context_path,
                    request.base_template or "node",
                )

            # 5. Construir imagem
            build_result = self._build_image(
                context_path=request.context_path,
                dockerfile_path=dockerfile_path,
                tag=request.tag,
                options=BuildOptions(
                    tag=request.tag,
                    dockerfile_path=dockerfile_path,
                    context_path=request.context_path,
                    no_cache=request.no_cache,
                    build_args=request.build_args,
                    labels=request.labels,
                    buildkit=True,
                ),
            )

            if not build_result.success:
                return BuildImageResponse(
                    success=False,
                    error=build_result.error_message,
                    exit_code=EXIT_ERROR,
                )

            # 6. Scan pós-build
            scan_result = None
            if request.scan:
                scan_result = self._scan_image(request.tag)

            # 7. Verificar thresholds de falha
            if request.fail_on and scan_result and self._should_fail(scan_result, request.fail_on):
                return BuildImageResponse(
                    success=False,
                    image_tag=request.tag,
                    image_sha256=build_result.image_sha256,
                    validation=validation,
                    analysis=validation_result.analysis,
                    error=f"Vulnerabilities exceed threshold ({request.fail_on})",
                    exit_code=EXIT_POLICY,
                )

            # 8. Gerar relatório
            report = self._generate_report(
                validation=validation_result,
                build=build_result,
                scan=scan_result,
                image_tag=request.tag,
                dockerfile_path=request.dockerfile_path,
            )

            return BuildImageResponse(
                success=True,
                image_tag=request.tag,
                image_sha256=build_result.image_sha256,
                report=report,
                validation=validation,
                analysis=validation_result.analysis,
                recommendations=list(validation_result.suggestions or []),
                exit_code=EXIT_OK,
            )

        except Exception as e:
            logger.exception(f"Erro no build: {e}")
            return BuildImageResponse(
                success=False,
                error=str(e),
                exit_code=EXIT_ERROR,
            )

    def _validate_dockerfile(self, request: BuildImageRequest) -> AnalyzeDockerfileResponse:
        """Valida o Dockerfile."""
        from dockerls.application.use_cases.analyze_dockerfile import (
            AnalyzeDockerfileRequest,
            AnalyzeDockerfileUseCase,
        )

        analyze_request = AnalyzeDockerfileRequest(
            dockerfile_path=Path(request.context_path) / request.dockerfile_path,
            include_suggestions=True,
            validate_only=False,
        )

        analyze_use_case = AnalyzeDockerfileUseCase(self.validator, self.template_provider)
        return analyze_use_case.execute(analyze_request)

    def _format_validation_response(
        self, validation_result: AnalyzeDockerfileResponse
    ) -> BuildImageResponse:
        """Formata resposta apenas de validação.

        Propaga o `DockerfileValidationResult` inteiro -- checks, contagens e
        score -- porque é ele que a CLI renderiza. Devolver só `success` e
        `exit_code` deixava o comando sem nada para imprimir.
        """
        validation = validation_result.validation
        if validation is None:
            return BuildImageResponse(
                success=False,
                error="Dockerfile validation produced no result",
                exit_code=EXIT_ERROR,
            )

        analysis = validation_result.analysis
        suggestions = list(validation_result.suggestions or [])
        failed = validation.errors > 0

        return BuildImageResponse(
            success=not failed,
            report=self._build_validation_report(validation_result, validation, analysis),
            validation=validation,
            analysis=analysis,
            recommendations=suggestions,
            error=self._validation_error_summary(validation) if failed else None,
            exit_code=EXIT_POLICY if failed else EXIT_OK,
        )

    def _format_suggestions_response(
        self, validation_result: AnalyzeDockerfileResponse
    ) -> BuildImageResponse:
        """Formata resposta apenas com sugestões.

        Carrega também a validação: mostrar as sugestões sem dizer quais
        checks as motivaram não é acionável.
        """
        validation = validation_result.validation
        analysis = validation_result.analysis
        return BuildImageResponse(
            success=True,
            report=self._build_validation_report(validation_result, validation, analysis)
            if validation is not None
            else None,
            validation=validation,
            analysis=analysis,
            recommendations=list(validation_result.suggestions or []),
            exit_code=EXIT_OK,
        )

    def _build_validation_report(
        self,
        validation_result: AnalyzeDockerfileResponse,
        validation: DockerfileValidationResult,
        analysis: DockerfileAnalysis | None,
    ) -> BuildReport:
        """Relatório de um run que só validou -- sem imagem, sem scan.

        Existe para que `--ci-mode` emita o mesmo JSON estruturado nos dois
        modos, em vez de um objeto vazio quando nada foi construído.
        """
        score = (
            analysis.security_score
            if analysis is not None
            else self._calculate_security_score(validation_result, None)
        )
        tier = (
            analysis.security_tier if analysis is not None else self._calculate_security_tier(score)
        )
        return BuildReport(
            build_id=self._new_build_id(validation.dockerfile_path),
            timestamp=datetime.now(tz=UTC).isoformat(),
            image="",
            dockerfile_path=validation.dockerfile_path,
            validation=self._validation_dict(validation),
            security_score=score,
            security_tier=tier,
            recommendations=self._recommendation_dicts(validation_result.suggestions or []),
        )

    @staticmethod
    def _validation_error_summary(validation: DockerfileValidationResult) -> str:
        """Resumo textual das regras violadas, para `error` e para logs de CI."""
        failures = [c for c in validation.checks if c.status == ValidationStatus.FAIL]
        header = f"Dockerfile validation failed: {validation.errors} error(s)"
        if not failures:
            return header
        details = "; ".join(
            f"{check.check}"
            f"{f' (line {check.line})' if check.line is not None else ''}: {check.message}"
            for check in failures
        )
        return f"{header} -- {details}"

    @staticmethod
    def _validation_dict(validation: DockerfileValidationResult) -> dict[str, Any]:
        return {
            "dockerfile_path": validation.dockerfile_path,
            "passed": validation.passed,
            "warnings": validation.warnings,
            "errors": validation.errors,
            "checks": [
                {
                    "check": check.check,
                    "status": check.status.value,
                    "message": check.message,
                    "severity": check.severity.value,
                    "line": check.line,
                }
                for check in validation.checks
            ],
        }

    @staticmethod
    def _recommendation_dicts(rules: list[HardeningRule]) -> list[dict[str, Any]]:
        return [
            {
                "priority": rule.priority.value,
                "title": rule.title,
                "current": rule.current_state,
                "suggested": rule.suggested_fix,
                "reason": rule.reason,
            }
            for rule in rules
        ]

    @staticmethod
    def _new_build_id(seed: str) -> str:
        stamp = datetime.now(tz=UTC).isoformat()
        return hashlib.sha256(f"{seed}{stamp}".encode()).hexdigest()[:16]

    def _generate_hardened_dockerfile(self, context_path: str, template: str) -> str:
        """Gera Dockerfile hardened delegando à infraestrutura.

        Escrever arquivo é responsabilidade do provider, não do caso de uso:
        aqui só decidimos onde ele deve sair.
        """
        output_path = Path(context_path) / "Dockerfile.hardened"
        self.template_provider.generate_hardened_dockerfile(
            dockerfile_path=Path(context_path),
            base_image=template,
            output_path=output_path,
        )
        logger.debug(f"Dockerfile hardened gerado: {output_path}")
        return str(output_path)

    def _build_image(
        self,
        context_path: str,
        dockerfile_path: str,
        tag: str,
        options: BuildOptions,
    ) -> BuildResult:
        """Executa o build da imagem Docker."""
        start_time = datetime.now()
        logs: list[str] = []
        warnings: list[str] = []

        try:
            # Comando docker build. O binário é resolvido para caminho
            # absoluto: deixar a escolha para o $PATH é o próprio PATH
            # hijacking que esta ferramenta reporta nas imagens dos outros.
            # BuildKit é ativado via variável de ambiente, não por argumento.
            cmd = [resolve_executable("docker"), "build"]

            cmd.extend(["-t", tag])
            cmd.extend(["-f", dockerfile_path])

            if options.no_cache:
                cmd.append("--no-cache")

            if options.pull:
                cmd.append("--pull")

            if options.platform:
                cmd.extend(["--platform", options.platform])

            if options.target:
                cmd.extend(["--target", options.target])

            if options.build_args:
                for key, value in options.build_args.items():
                    cmd.extend(["--build-arg", f"{key}={value}"])

            if options.labels:
                for key, value in options.labels.items():
                    cmd.extend(["--label", f"{key}={value}"])

            # Adicionar contexto
            cmd.append(context_path)

            logger.debug(f"Executando comando: {' '.join(cmd)}")

            # Executar build
            env = {}
            if options.buildkit:
                env["DOCKER_BUILDKIT"] = "1"

            result = subprocess.run(  # noqa: S603 -- argv, sem shell; argv[0] resolvido
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hora timeout
                env={**os.environ, **env},
                check=False,
            )

            logs.append(result.stdout)
            if result.stderr:
                logs.append(result.stderr)
                warnings.append(result.stderr)

            if result.returncode != 0:
                return BuildResult(
                    success=False,
                    error_message=f"Build failed: {result.stderr}",
                    logs=logs,
                    warnings=warnings,
                )

            # Extrair informações da imagem
            image_info = self._get_image_info(tag)

            end_time = datetime.now()
            build_time = (end_time - start_time).total_seconds()

            return BuildResult(
                success=True,
                image_tag=tag,
                image_id=image_info.get("Id"),
                image_sha256=image_info.get("Id"),
                build_time_seconds=build_time,
                layers_count=len(image_info.get("RootFS", {}).get("Layers", [])),
                image_size_bytes=image_info.get("Size", 0),
                logs=logs,
                warnings=warnings,
            )

        except ExecutableNotFoundError as e:
            return BuildResult(success=False, error_message=str(e), logs=logs)
        except subprocess.TimeoutExpired:
            return BuildResult(
                success=False,
                error_message="Build timeout (1 hour)",
                logs=logs,
            )
        except Exception as e:
            logger.exception(f"Erro no build: {e}")
            return BuildResult(
                success=False,
                error_message=str(e),
                logs=logs,
            )

    def _get_image_info(self, tag: str) -> dict[str, Any]:
        """Obtém informações da imagem construída."""
        try:
            result = subprocess.run(  # noqa: S603 -- argv, sem shell; argv[0] resolvido
                [resolve_executable("docker"), "image", "inspect", tag],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                images = json.loads(result.stdout)
                if images:
                    info: dict[str, Any] = images[0]
                    return info

            return {}
        except Exception as e:
            logger.warning(f"Não foi possível obter info da imagem: {e}")
            return {}

    def _scan_image(self, image_tag: str) -> ScanResult | None:
        """Executa scan de segurança na imagem."""
        logger.info(f"Iniciando scan da imagem: {image_tag}")
        start_time = datetime.now()

        try:
            # Tentar usar Trivy
            result = subprocess.run(  # noqa: S603 -- argv, sem shell; argv[0] resolvido
                [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    "json",
                    "--severity",
                    "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
                    image_tag,
                ],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutos
                check=False,
            )

            if result.returncode == 0:
                scan_data = json.loads(result.stdout)

                # Parsear resultados do Trivy
                critical = high = medium = low = unknown = fixable = 0
                vulnerabilities = []

                for finding in scan_data.get("Results", []):
                    for vuln in finding.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN")
                        if severity == "CRITICAL":
                            critical += 1
                        elif severity == "HIGH":
                            high += 1
                        elif severity == "MEDIUM":
                            medium += 1
                        elif severity == "LOW":
                            low += 1
                        else:
                            unknown += 1

                        if vuln.get("FixedVersion"):
                            fixable += 1

                        vulnerabilities.append(
                            {
                                "cve_id": vuln.get("VulnerabilityID"),
                                "package": vuln.get("PkgName"),
                                "severity": severity,
                                "installed_version": vuln.get("InstalledVersion"),
                                "fixed_version": vuln.get("FixedVersion"),
                            }
                        )

                end_time = datetime.now()
                scan_time = (end_time - start_time).total_seconds()

                return ScanResult(
                    critical=critical,
                    high=high,
                    medium=medium,
                    low=low,
                    unknown=unknown,
                    total_vulnerabilities=critical + high + medium + low + unknown,
                    fixable=fixable,
                    scan_tool="trivy",
                    scan_time_seconds=scan_time,
                    vulnerabilities=vulnerabilities[:100],  # Limitar a 100
                )

        except ExecutableNotFoundError:
            logger.warning("Trivy não encontrado, tentando Grype...")
        except Exception as e:
            logger.warning(f"Erro no scan com Trivy: {e}")

        # Fallback: tentar Grype
        try:
            result = subprocess.run(  # noqa: S603 -- argv, sem shell; argv[0] resolvido
                [
                    resolve_executable("grype"),
                    image_tag,
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

            if result.returncode == 0:
                scan_data = json.loads(result.stdout)
                # Parse similar ao Trivy...
                return ScanResult(scan_tool="grype")

        except Exception as e:
            logger.warning(f"Grype também falhou: {e}")

        logger.warning("Nenhuma ferramenta de scan disponível")
        return None

    def _should_fail(self, scan_result: ScanResult, threshold: str) -> bool:
        """Verifica se deve falhar o build baseado no threshold."""
        if threshold == "critical":
            return scan_result.critical > 0
        elif threshold == "high":
            return scan_result.critical > 0 or scan_result.high > 0
        return False

    def _generate_report(
        self,
        validation: Any,
        build: BuildResult,
        scan: ScanResult | None,
        image_tag: str,
        dockerfile_path: str,
    ) -> BuildReport:
        """Gera relatório completo do build."""
        now = datetime.now(tz=UTC)
        build_id = self._new_build_id(image_tag)

        # Calcular score de segurança
        security_score = self._calculate_security_score(validation, scan)
        security_tier = self._calculate_security_tier(security_score)

        # Extrair checks de validação
        validation_dict = self._validation_dict(validation.validation)

        # Resultados do scan
        scan_dict = None
        if scan:
            scan_dict = {
                "trivy" if scan.scan_tool == "trivy" else "grype": {
                    "critical": scan.critical,
                    "high": scan.high,
                    "medium": scan.medium,
                    "low": scan.low,
                },
            }

        # Metadados do build
        git_sha = self._get_git_sha()
        metadata = {
            "timestamp": now.isoformat(),
            "git_sha": git_sha,
            "built_by": os.environ.get("USER", "unknown"),
            "docker_version": self._get_docker_version(),
            "buildkit": True,
        }

        # Recomendações: vêm das sugestões de hardening. `DockerfileAnalysis`
        # nunca teve um atributo `recommendations` -- o acesso antigo só não
        # explodia porque `analysis` era sempre None nos testes.
        recommendations = self._recommendation_dicts(list(validation.suggestions or []))

        return BuildReport(
            build_id=build_id,
            timestamp=now.isoformat(),
            image=image_tag,
            dockerfile_path=dockerfile_path,
            validation=validation_dict,
            scan_results=scan_dict,
            security_score=security_score,
            security_tier=security_tier,
            recommendations=recommendations,
            build_metadata=metadata,
        )

    def _calculate_security_score(self, validation: Any, scan: ScanResult | None) -> int:
        """Calcula score de segurança (0-100)."""
        score = 100

        # Penalizar erros de validação
        if validation.validation:
            score -= validation.validation.errors * 10
            score -= validation.validation.warnings * 3

        # Penalizar vulnerabilidades
        if scan:
            score -= scan.critical * 15
            score -= scan.high * 10
            score -= scan.medium * 3
            score -= scan.low * 1

        return max(0, min(100, score))

    def _calculate_security_tier(self, score: int) -> str:
        """Calcula tier de segurança baseado no score."""
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"

    def _get_git_sha(self) -> str | None:
        """Obtém SHA do git atual.

        Metadado opcional do relatório: fora de um repositório, ou sem git
        instalado, o relatório sai sem ele em vez de falhar o build.
        """
        return self._capture_output(["git", "rev-parse", "HEAD"], "git SHA")

    def _get_docker_version(self) -> str:
        """Obtém versão do Docker."""
        return self._capture_output(["docker", "--version"], "versão do Docker") or "unknown"

    @staticmethod
    def _capture_output(argv: list[str], what: str) -> str | None:
        """Roda `argv` e devolve seu stdout, ou None se não der.

        A falha é registrada em DEBUG em vez de engolida em silêncio: um
        `except: pass` esconde exatamente o caso que a gente quer investigar
        quando o metadado sai vazio.
        """
        try:
            resolved = [resolve_executable(argv[0]), *argv[1:]]
            result = subprocess.run(  # noqa: S603 -- argv, sem shell; argv[0] resolvido
                resolved,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (ExecutableNotFoundError, OSError, subprocess.SubprocessError) as e:
            logger.debug(f"Não foi possível obter {what}: {e}")
            return None

        if result.returncode != 0:
            logger.debug(f"Não foi possível obter {what}: exit {result.returncode}")
            return None
        return result.stdout.strip()
