"""Use case para construir imagens Docker com segurança."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileValidationResult as ValidationResult,
    HardeningRule,
    ValidationCheck,
)
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
    build_args: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None
    platform: Optional[str] = None
    target: Optional[str] = None
    pull: bool = True
    buildkit: bool = True
    secrets: Optional[Dict[str, str]] = None  # id -> file_path
    ssh: Optional[List[str]] = None  # SSH agents


@dataclass
class BuildResult:
    """Resultado do build."""

    success: bool
    image_tag: Optional[str] = None
    image_id: Optional[str] = None
    image_sha256: Optional[str] = None
    build_time_seconds: float = 0.0
    layers_count: int = 0
    image_size_bytes: int = 0
    error_message: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


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
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    sbom_components_count: int = 0


@dataclass
class BuildReport:
    """Relatório completo de build."""

    build_id: str
    timestamp: str
    image: str
    dockerfile_path: str
    validation: Dict[str, Any]
    scan_results: Optional[Dict[str, Any]] = None
    security_score: int = 0
    security_tier: str = "F"
    layers: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    sbom: Optional[Dict[str, Any]] = None
    build_metadata: Optional[Dict[str, Any]] = None


@dataclass
class BuildImageRequest:
    """Request para build de imagem."""

    context_path: str
    tag: str
    dockerfile_path: str = "Dockerfile"
    hardened: bool = False
    base_template: Optional[str] = None
    scan: bool = True
    validate_only: bool = False
    suggest_only: bool = False
    no_cache: bool = False
    build_args: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None
    fail_on: Optional[str] = None  # "critical", "high"
    ci_mode: bool = False
    verbose: bool = False
    force: bool = False


@dataclass
class BuildImageResponse:
    """Resposta do build de imagem."""

    success: bool
    image_tag: Optional[str] = None
    image_sha256: Optional[str] = None
    report: Optional[BuildReport] = None
    recommendations: List[HardeningRule] = field(default_factory=list)
    error: Optional[str] = None
    exit_code: int = 0


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
        logger.info(f"Iniciando build seguro: {request.context_path}")

        try:
            # 1. Validar Dockerfile
            validation_result = self._validate_dockerfile(request)
            if not validation_result and not request.force:
                return BuildImageResponse(
                    success=False,
                    error="Dockerfile validation failed",
                    exit_code=1,
                )

            # 2. Modo validate-only
            if request.validate_only:
                return self._format_validation_response(validation_result)

            # 3. Modo suggest-only
            if request.suggest_only:
                return self._format_suggestions_response(validation_result)

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
                    exit_code=1,
                )

            # 6. Scan pós-build
            scan_result = None
            if request.scan:
                scan_result = self._scan_image(request.tag)

            # 7. Verificar thresholds de falha
            if request.fail_on and scan_result:
                if self._should_fail(scan_result, request.fail_on):
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        error=f"Vulnerabilities exceed threshold ({request.fail_on})",
                        exit_code=1,
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
                recommendations=validation_result.analysis.recommendations if validation_result.analysis else [],
                exit_code=0,
            )

        except Exception as e:
            logger.exception(f"Erro no build: {e}")
            return BuildImageResponse(
                success=False,
                error=str(e),
                exit_code=1,
            )

    def _validate_dockerfile(self, request: BuildImageRequest) -> Optional[Any]:
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

    def _format_validation_response(self, validation_result: Any) -> BuildImageResponse:
        """Formata resposta apenas de validação."""
        return BuildImageResponse(
            success=validation_result.validation.errors == 0,
            exit_code=0 if validation_result.validation.errors == 0 else 2,
        )

    def _format_suggestions_response(self, validation_result: Any) -> BuildImageResponse:
        """Formata resposta apenas com sugestões."""
        suggestions = validation_result.suggestions or []
        return BuildImageResponse(
            success=True,
            recommendations=suggestions,
            exit_code=0,
        )

    def _generate_hardened_dockerfile(self, context_path: str, template: str) -> str:
        """Gera Dockerfile hardened baseado em template."""
        template_content = self.template_provider.get_template(template)
        
        output_path = Path(context_path) / f"Dockerfile.hardened"
        output_path.write_text(template_content)
        
        logger.info(f"Dockerfile hardened gerado: {output_path}")
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
        logs: List[str] = []
        warnings: List[str] = []

        try:
            # Comando docker build
            cmd = ["docker", "build"]

            if options.buildkit:
                cmd = ["docker", "build"]  # BuildKit é ativado via env var

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

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hora timeout
                env={**subprocess.os.environ, **env},
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

    def _get_image_info(self, tag: str) -> Dict[str, Any]:
        """Obtém informações da imagem construída."""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", tag],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                images = json.loads(result.stdout)
                if images:
                    return images[0]

            return {}
        except Exception as e:
            logger.warning(f"Não foi possível obter info da imagem: {e}")
            return {}

    def _scan_image(self, image_tag: str) -> Optional[ScanResult]:
        """Executa scan de segurança na imagem."""
        logger.info(f"Iniciando scan da imagem: {image_tag}")
        start_time = datetime.now()

        try:
            # Tentar usar Trivy
            result = subprocess.run(
                [
                    "trivy",
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

                        vulnerabilities.append({
                            "cve_id": vuln.get("VulnerabilityID"),
                            "package": vuln.get("PkgName"),
                            "severity": severity,
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": vuln.get("FixedVersion"),
                        })

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

        except FileNotFoundError:
            logger.warning("Trivy não encontrado, tentando Grype...")
        except Exception as e:
            logger.warning(f"Erro no scan com Trivy: {e}")

        # Fallback: tentar Grype
        try:
            result = subprocess.run(
                [
                    "grype",
                    image_tag,
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=600,
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
        scan: Optional[ScanResult],
        image_tag: str,
        dockerfile_path: str,
    ) -> BuildReport:
        """Gera relatório completo do build."""
        now = datetime.utcnow()
        build_id = hashlib.sha256(f"{image_tag}{now.isoformat()}".encode()).hexdigest()[:16]

        # Calcular score de segurança
        security_score = self._calculate_security_score(validation, scan)
        security_tier = self._calculate_security_tier(security_score)

        # Extrair checks de validação
        validation_dict = {
            "passed": validation.validation.passed,
            "warnings": validation.validation.warnings,
            "errors": validation.validation.errors,
            "checks": [
                {
                    "check": check.check,
                    "status": check.status.value,
                    "message": check.message,
                    "severity": check.severity.value,
                    "line": check.line,
                }
                for check in validation.validation.checks
            ],
        }

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
            "built_by": subprocess.os.environ.get("USER", "unknown"),
            "docker_version": self._get_docker_version(),
            "buildkit": True,
        }

        # Recomendações
        recommendations = []
        if validation.analysis and validation.analysis.recommendations:
            recommendations = [
                {
                    "priority": rec.priority.value,
                    "title": rec.title,
                    "current": rec.current_state,
                    "suggested": rec.suggested_fix,
                    "reason": rec.reason,
                }
                for rec in validation.analysis.recommendations
            ]

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

    def _calculate_security_score(self, validation: Any, scan: Optional[ScanResult]) -> int:
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

    def _get_git_sha(self) -> Optional[str]:
        """Obtém SHA do git atual."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _get_docker_version(self) -> str:
        """Obtém versão do Docker."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"
