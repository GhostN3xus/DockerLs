from __future__ import annotations

import asyncio
import hashlib
import re
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import ValidationError

from dockerls.application.dto.analysis import (
    AnalysisResult,
    BaselineCriteria,
    ImageAnalysis,
    UnverifiedImage,
)
from dockerls.application.services.progress import NullObserver
from dockerls.domain.entities.recommendation import (
    ActionType,
    Recommendation,
    RemediationStep,
)
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier
from dockerls.integrations.registry.urls import source_url
from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.services.cross_validation import CrossValidator
    from dockerls.application.services.progress import ScanObserver
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface
    from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.integrations.threat_intel.client import ThreatIntelClient

# How many ranked candidates are surfaced to the user.
TOP_N = 5


class UnverifiedRecommendationError(RuntimeError):
    """Raised when an image without a proven successful scan would have been
    presented as a recommendation. This is a programming error, not a user
    error: it means a code path bypassed the verification gate."""


class RecommendImagesUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
        cache: CacheStoreInterface | None = None,
        max_critical: int = 0,
        max_high: int = 0,
        max_medium: int = 5,
        workers: int = 10,
        ignore_path: Path | None = None,
        threat_intel: ThreatIntelClient | None = None,
        observer: ScanObserver | None = None,
        cross_validator: CrossValidator | None = None,
        evidence: EvidenceStore | None = None,
        verify_hub_tags: bool = True,
        log_file: Path | None = None,
        cache_ttl_seconds: int = 86400,
    ):
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker
        self._cache = cache
        self._max_critical = max_critical
        self._max_high = max_high
        self._max_medium = max_medium
        self._workers = workers
        self._ignored_cves = active_ignored_cve_ids(load_ignore_rules(ignore_path))
        self._threat_intel = threat_intel
        self._observer: ScanObserver = observer or NullObserver()
        self._cross_validator = cross_validator
        self._evidence = evidence
        self._verify_hub_tags = verify_hub_tags
        self._log_file = log_file
        self._cache_ttl_seconds = cache_ttl_seconds
        self._analysis_fingerprint = self._compute_analysis_fingerprint()

    def _compute_analysis_fingerprint(self) -> str:
        """Identifica as entradas, fora a própria imagem, que mudam o
        `ImageAnalysis` guardado em cache.

        As regras de ignore e o enriquecimento de threat intel são aplicados
        *antes* de cachear, mas a chave era só a referência da imagem. Um CVE
        que deixava de ser ignorado -- porque a regra foi removida, ou porque
        o `expires` dela venceu -- continuava suprimido até o TTL expirar
        (24h no padrão). O arquivo de ignore promete que uma isenção vencida
        deixa de valer; o cache desfazia essa promessa em silêncio.
        """
        material = "|".join(
            [
                ",".join(sorted(self._ignored_cves)),
                "threat-intel" if self._threat_intel is not None else "no-threat-intel",
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:12]

    def _cache_key(self, image_reference: str) -> str:
        return f"analysis:{self._analysis_fingerprint}:{image_reference}"

    async def execute(self, image_name: str, limit: int = 100) -> AnalysisResult:
        try:
            return await self._execute(image_name, limit)
        finally:
            await self._close_scanners()

    def _baseline(self) -> BaselineCriteria:
        return BaselineCriteria(
            max_critical=self._max_critical,
            max_high=self._max_high,
            max_medium=self._max_medium,
        )

    async def _execute(self, image_name: str, limit: int = 100) -> AnalysisResult:
        self._observer.phase("Preparing vulnerability database")
        refresh_db = getattr(self._scanner, "refresh_db", None)
        if callable(refresh_db):
            await refresh_db()

        self._observer.phase(f"Fetching tags for {image_name}")
        tags = await self._repository.search_tags(image_name, limit=limit)
        if not tags:
            return AnalysisResult(
                query=image_name,
                total_tags_scanned=0,
                baseline_met=False,
                errors=["No tags found for image"],
                log_file=str(self._log_file or ""),
                baseline=self._baseline(),
            )

        analyses, unverified, errors = await self._scan_all(tags)
        analyses.sort(key=lambda a: a.security_score, reverse=True)

        baseline_images = [
            a
            for a in analyses
            if a.scan.critical_count <= self._max_critical
            and a.scan.high_count <= self._max_high
            and a.scan.medium_count <= self._max_medium
            and not a.is_eol
        ]

        if baseline_images:
            baseline_met = True
            pool = baseline_images
        else:
            baseline_met = False
            pool = [a for a in analyses if a.scan.critical_count == 0 and not a.is_eol]
            pool.sort(key=lambda a: (a.scan.high_count, -a.remediation_score))

        selected = await self._finalize(pool, unverified)

        result = AnalysisResult(
            query=image_name,
            total_tags_scanned=len(tags),
            total_tags_analyzed=len(analyses),
            baseline_met=baseline_met and bool(selected),
            recommendations=selected if baseline_met else [],
            alternatives=[] if baseline_met else selected,
            errors=errors,
            unverified=unverified,
            log_file=str(self._log_file or ""),
            baseline=self._baseline(),
            sources_searched=_sources_of(tags),
        )
        result.evidence_manifest = await self._write_manifest(image_name, selected)
        return result

    async def _scan_all(
        self, tags: list[DockerImage]
    ) -> tuple[list[ImageAnalysis], list[UnverifiedImage], list[str]]:
        semaphore = asyncio.Semaphore(self._workers)
        errors: list[str] = []
        unverified: list[UnverifiedImage] = []

        # P0-3: dedupe scans by digest so tags sharing the same manifest
        # digest are only scanned once and share the result.
        scan_locks: dict[str, asyncio.Lock] = {}
        scan_cache: dict[str, Any] = {}

        def _dedup_key(image: DockerImage) -> str:
            return image.digest or image.full_reference

        async def get_scan(image: DockerImage) -> Any:
            key = _dedup_key(image)
            lock = scan_locks.setdefault(key, asyncio.Lock())
            async with lock:
                if key in scan_cache:
                    return scan_cache[key]
                async with semaphore:
                    scan = await self._scanner.scan(image.full_reference)
                scan_cache[key] = scan
                return scan

        def _skip(image: DockerImage, status: str, reason: str) -> None:
            logger.warning(f"Skipping {image.full_reference}: {status} ({reason})")
            unverified.append(
                UnverifiedImage(
                    image_reference=image.full_reference,
                    status=status,
                    reason=reason or "no details",
                )
            )
            errors.append(f"{image.full_reference}: {status} ({reason or 'no details'})")

        async def analyze_tag(image: DockerImage) -> ImageAnalysis | None:
            self._observer.scanning(image.full_reference)
            analysis: ImageAnalysis | None = None
            try:
                cached = await self._get_cached(image.full_reference)
                if cached:
                    analysis = cached
                    return cached

                scan = await get_scan(image)
                # Single verification gate: anything short of a completed,
                # parsed scan is reported as unverified and is never scored.
                if not scan.is_verified:
                    _skip(image, scan.status.value, scan.error_message)
                    return None

                if self._ignored_cves:
                    scan = _apply_ignore_rules(scan, self._ignored_cves)
                if self._threat_intel is not None:
                    scan = await _enrich_with_threat_intel(scan, self._threat_intel)

                product, version = _extract_product_version(image)
                is_eol = await self._eol_checker.is_eol(product, version)
                is_lts = await self._eol_checker.is_lts(product, version)

                score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts)
                tier = SecurityTier(scan, is_eol=is_eol)
                rem_score = RemediationScore(scan)

                analysis = ImageAnalysis(
                    image=image,
                    scan=scan,
                    security_score=score.value,
                    tier=tier.tier.value,
                    production_ready=tier.production_ready,
                    remediation_score=rem_score.value,
                    is_eol=is_eol,
                    is_lts=is_lts,
                    evidence_paths=(
                        {scan.scanner: scan.evidence_path} if scan.evidence_path else {}
                    ),
                )

                await self._set_cached(image.full_reference, analysis)
                return analysis
            except Exception as e:
                logger.warning(f"Failed to analyze {image.full_reference}: {e}")
                _skip(image, "ERROR", str(e))
                return None
            finally:
                self._observer.finished(image.full_reference, analysis is not None)

        self._observer.start(len(tags))
        results = await asyncio.gather(*[analyze_tag(tag) for tag in tags])
        return [r for r in results if r is not None], unverified, errors

    async def _finalize(
        self, pool: list[ImageAnalysis], unverified: list[UnverifiedImage]
    ) -> list[ImageAnalysis]:
        """Cross-validate, confirm Docker Hub tags, and enforce the
        no-scan-no-recommendation invariant on the final candidate list."""
        # Verify a wider slice than TOP_N so candidates dropped for a
        # missing Hub tag can be backfilled from the next best ones.
        candidates = pool[: TOP_N * 2]

        # A verificação de tag vem primeiro, e a cross-validation só depois,
        # sobre quem sobreviveu. Na ordem inversa, um candidato promovido
        # para o top N no lugar de um descartado entrava na tabela sem nunca
        # ter passado pelo segundo scanner -- ou seja, com a pontuação
        # apresentada sem contestação justamente por não ter sido checada.
        # De quebra, deixa de gastar um scan secundário em quem vai cair.
        if self._verify_hub_tags and candidates:
            self._observer.phase("Verifying tags in their source registries")
            await self._verify_tags(candidates, unverified)
            candidates = [c for c in candidates if c.hub_tag_verified is not False]

        selected = candidates[:TOP_N]

        if self._cross_validator is not None and self._cross_validator.enabled and selected:
            self._observer.phase(f"Cross-validating top {len(selected)} candidates")
            await self._cross_validator.validate(selected)
        _assert_verified(selected)
        for analysis in selected:
            analysis.recommendation = build_recommendation(analysis)
        return selected

    async def _verify_tags(
        self, candidates: list[ImageAnalysis], unverified: list[UnverifiedImage]
    ) -> None:
        """Confirm each candidate tag against the registry that owns it.

        Docker Hub tags are checked through the Hub API; hardened-source
        tags are checked against that source's own listing. Either way the
        answer comes from the registry, never from a constructed string.
        """
        checker = getattr(self._repository, "tag_exists", None)

        async def check(analysis: ImageAnalysis) -> None:
            analysis.hub_url = source_url(analysis.image.name, analysis.image.tag)
            if not callable(checker):
                return
            exists = await checker(analysis.image.name, analysis.image.tag)
            analysis.hub_tag_verified = exists
            if exists is False:
                logger.warning(
                    f"Dropping {analysis.image.full_reference}: "
                    f"tag not found in {analysis.image.source}"
                )
                unverified.append(
                    UnverifiedImage(
                        image_reference=analysis.image.full_reference,
                        status="TAG_NOT_FOUND",
                        reason=f"Tag does not exist in {analysis.image.source}",
                    )
                )

        await asyncio.gather(*[check(c) for c in candidates])

    async def _write_manifest(self, query: str, selected: list[ImageAnalysis]) -> str:
        if self._evidence is None or not selected:
            return ""
        entries = [
            {
                "image": a.image.full_reference,
                "security_score": a.security_score,
                "tier": a.tier,
                "critical": a.scan.critical_count,
                "high": a.scan.high_count,
                "medium": a.scan.medium_count,
                "scan_status": a.scan.status.value,
                "scan_timestamp": a.scan.scan_timestamp,
                "scan_divergence": a.scan_divergence,
                "hub_url": a.hub_url,
                "hub_tag_verified": a.hub_tag_verified,
                "evidence": a.evidence_paths,
            }
            for a in selected
        ]
        return await self._evidence.record_manifest(query, entries)

    async def _close_scanners(self) -> None:
        secondary = self._cross_validator.scanner if self._cross_validator else None
        for scanner in (self._scanner, secondary):
            close = getattr(scanner, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception as e:  # pragma: no cover - cleanup must not mask results
                    logger.warning(f"Scanner cleanup failed: {e}")

    async def _get_cached(self, key: str) -> ImageAnalysis | None:
        if not self._cache:
            return None
        cache_key = self._cache_key(key)
        data = await self._cache.get(cache_key)
        if not (data and isinstance(data, dict)):
            return None
        try:
            analysis: ImageAnalysis = ImageAnalysis.model_validate(data)
        except ValidationError as e:
            logger.warning(f"Discarding stale cache entry for {key}: {e}")
            await self._cache.delete(cache_key)
            return None
        # A cache hit is not proof of a successful scan: an entry written by
        # an older build could carry a failed scan. Re-apply the gate.
        if not analysis.scan.is_verified:
            logger.warning(f"Discarding cache entry for {key}: cached scan is not verified")
            await self._cache.delete(cache_key)
            return None
        return analysis

    async def _set_cached(self, key: str, analysis: ImageAnalysis) -> None:
        if self._cache:
            await self._cache.set(
                self._cache_key(key),
                analysis.model_dump(),
                ttl_seconds=self._cache_ttl_seconds,
            )


def _sources_of(tags: list[DockerImage]) -> list[str]:
    """Distinct catalogues that contributed a candidate, in first-seen
    order, so the run can report what it actually looked at."""
    seen: list[str] = []
    for tag in tags:
        if tag.source not in seen:
            seen.append(tag.source)
    return seen


def _assert_verified(analyses: list[ImageAnalysis]) -> None:
    """Final gate before results leave the use case.

    Nothing reaches the user's "Recommended Images" table without a scan
    result that exists, completed successfully, and produced a timestamp.
    """
    offenders = [
        a.image.full_reference for a in analyses if a.scan is None or not a.scan.is_verified
    ]
    if offenders:
        raise UnverifiedRecommendationError(
            f"Refusing to recommend images without a verified scan: {', '.join(offenders)}"
        )


async def _enrich_with_threat_intel(scan: Any, threat_intel: ThreatIntelClient) -> Any:
    """Tag CRITICAL/HIGH vulnerabilities with CISA KEV / EPSS signal so
    SecurityScore can weigh confirmed-exploited or high-probability CVEs
    more heavily than an unweighted severity count would."""
    notable_ids = [
        v.cve_id
        for v in scan.vulnerabilities
        if v.severity.value in ("CRITICAL", "HIGH") and v.cve_id
    ]
    if not notable_ids:
        return scan

    kev_ids = await threat_intel.known_exploited(notable_ids)
    epss = await threat_intel.epss_scores(notable_ids)
    if not kev_ids and not epss:
        return scan

    updated = [
        v.model_copy(
            update={
                "exploit_known": v.cve_id.upper() in kev_ids,
                "epss_score": epss.get(v.cve_id.upper(), v.epss_score),
            }
        )
        for v in scan.vulnerabilities
    ]
    return scan.model_copy(update={"vulnerabilities": updated})


def _apply_ignore_rules(scan: Any, ignored_cves: set[str]) -> Any:
    """Return a copy of `scan` with vulnerabilities matching an active
    .dockerls-ignore.yaml rule removed, so ignored CVEs never affect
    scoring, tiering, or the baseline decision."""
    filtered = [v for v in scan.vulnerabilities if v.cve_id.upper() not in ignored_cves]
    if len(filtered) == len(scan.vulnerabilities):
        return scan
    return scan.model_copy(update={"vulnerabilities": filtered})


_LEADING_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}")


def _extract_product_version(image: DockerImage) -> tuple[str, str]:
    name = image.name.split("/")[-1]
    match = _LEADING_VERSION_RE.match(image.tag)
    version = match.group(0) if match else ""
    return name, version


def build_recommendation(analysis: ImageAnalysis) -> Recommendation:
    steps: list[RemediationStep] = []
    step_num = 1

    if analysis.scan.fixable_high_count > 0 or analysis.scan.fixable_critical_count > 0:
        fixable_pkgs = [
            v
            for v in analysis.scan.vulnerabilities
            if v.is_fixable and v.severity.value in ("CRITICAL", "HIGH")
        ]
        for vuln in fixable_pkgs[:5]:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    action=ActionType.UPDATE_PACKAGE,
                    description=f"Update {vuln.package_name}",
                    from_value=vuln.installed_version,
                    to_value=vuln.fixed_version,
                    expected_impact=f"Fix {vuln.severity.value} {vuln.cve_id}",
                )
            )
            step_num += 1

    if not analysis.image.is_alpine and not analysis.image.is_distroless:
        steps.append(
            RemediationStep(
                step_number=step_num,
                action=ActionType.SWITCH_BASE,
                description="Consider switching to Alpine or Distroless variant",
                expected_impact="Reduced attack surface",
            )
        )
        step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.REBUILD_IMAGE,
            description="Rebuild image to pick up latest base layer patches",
        )
    )
    step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.RESCAN,
            description="Re-run vulnerability scan to verify fixes",
        )
    )

    summary_parts = []
    if analysis.scan.critical_count == 0 and analysis.scan.high_count == 0:
        summary_parts.append("Image meets security baseline.")
    elif analysis.scan.critical_count == 0:
        summary_parts.append(
            f"Image has {analysis.scan.high_count} HIGH vulnerabilities "
            f"({analysis.scan.fixable_high_count} fixable)."
        )
    else:
        summary_parts.append(
            f"Image has {analysis.scan.critical_count} CRITICAL and "
            f"{analysis.scan.high_count} HIGH vulnerabilities."
        )
    if analysis.remediation_score == 100:
        summary_parts.append("All vulnerabilities have available fixes.")
    if analysis.scan_divergence:
        summary_parts.append(f"Scanner disagreement: {analysis.scan_divergence}.")

    return Recommendation(
        image_reference=analysis.image.full_reference,
        security_score=analysis.security_score,
        tier=analysis.tier,
        remediation_score=analysis.remediation_score,
        steps=steps,
        summary=" ".join(summary_parts),
    )
