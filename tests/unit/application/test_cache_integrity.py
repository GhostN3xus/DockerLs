"""A cache hit is a claim about a past scan; it must be re-validated.

1.1.0 shipped a bug where a cached entry was trusted on sight. The gate is
only worth something if it survives the shapes a real cache goes bad in:
truncated JSON, a payload from an older schema, a persisted ERROR status,
and a stale entry with no scan at all.

The cache now has layers (see `measurement_store`): a raw scan keyed by the
*confirmed platform manifest* identity, and an evaluation derived from it.
The properties below are the same as before -- corrupt or foreign rows are
misses, failure statuses are never trusted, tags are never identities -- and
each is exercised against the layer that can actually hold the bad row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface
from tests.unit.application.measurement_fakes import FakeRegistryResolver, digest_of

MANIFEST = digest_of("a")
TAG = DockerImage(name="node", tag="22-alpine", is_official=True)


class _Repo(ImageRepositoryInterface):
    def __init__(self, tags=None):
        self._tags = tags or [TAG.model_copy()]

    async def search_tags(self, image_name, limit=100):
        return [t.model_copy() for t in self._tags]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        return True


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class _CountingScanner(ScannerInterface):
    def __init__(self):
        self.scans = 0
        self.references: list[str] = []

    async def is_available(self):
        return True

    async def scan(self, image_reference, platform=None):
        self.scans += 1
        self.references.append(image_reference)
        return ScanResult(
            image_reference=image_reference,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            platform=platform or "",
        )


class _Cache(CacheStoreInterface):
    def __init__(self):
        self.store: dict[str, Any] = {}
        self.deleted: list[str] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self.store[key] = value

    async def delete(self, key):
        self.deleted.append(key)
        self.store.pop(key, None)

    async def clear(self):
        self.store.clear()


def _resolver(**manifests: str) -> FakeRegistryResolver:
    resolver = FakeRegistryResolver()
    resolver.publish("node", "22-alpine", digest_of("1"), **(manifests or {"linux_amd64": MANIFEST}))
    return resolver


def _use_case(cache, scanner=None, resolver=None, repo=None, **kwargs):
    scanner = scanner or _CountingScanner()
    use_case = RecommendImagesUseCase(
        repository=repo or _Repo(),
        scanner=scanner,
        eol_checker=_EOL(),
        cache=cache,
        **kwargs,
    )
    # Identity confirmation is the registry's job; the fake stands in for it.
    use_case._measurement._resolver = resolver or _resolver()  # noqa: SLF001
    return use_case, scanner


async def _primed():
    """A cache holding one good scan row and one good evaluation row."""
    cache = _Cache()
    use_case, scanner = _use_case(cache)
    await use_case.execute("node")
    assert scanner.scans == 1
    return cache


def _key(cache, prefix):
    (key,) = [k for k in cache.store if k.startswith(prefix)]
    return key


SCAN, EVAL = "m:scan:", "m:eval:"


class TestCorruptedPayloadsAreDiscarded:
    PAYLOADS = [
        pytest.param({"garbage": True}, id="unknown_shape"),
        pytest.param({"schema_version": 1, "layer": "scan", "digest": 5}, id="truncated"),
        pytest.param({}, id="empty_dict"),
        pytest.param("not-a-dict", id="wrong_type"),
        pytest.param([1, 2, 3], id="list_instead_of_object"),
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    @pytest.mark.asyncio
    async def test_a_corrupt_scan_row_forces_a_real_scan(self, payload):
        cache = await _primed()
        cache.store[_key(cache, SCAN)] = payload
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 1, "the corrupted entry was trusted"
        assert result.recommendations
        assert result.recommendations[0].scan.is_verified

    @pytest.mark.parametrize("payload", PAYLOADS)
    @pytest.mark.asyncio
    async def test_a_corrupt_evaluation_row_recomputes_without_a_new_scan(self, payload):
        cache = await _primed()
        cache.store[_key(cache, EVAL)] = payload
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 0, "a bad *derived* row must not cost a raw scan"
        assert result.recommendations

    @pytest.mark.asyncio
    async def test_an_unusable_row_is_evicted_not_reread_forever(self):
        cache = await _primed()
        key = _key(cache, SCAN)
        cache.store[key] = {"garbage": True}
        use_case, _ = _use_case(cache)

        await use_case.execute("node")

        assert key in cache.deleted


class TestPersistedFailureStatusIsNeverTrusted:
    @pytest.mark.parametrize("status", ["ERROR", "TIMEOUT", "PARTIAL"])
    @pytest.mark.asyncio
    async def test_cached_failed_scan_is_rescanned(self, status):
        cache = await _primed()
        cache.store[_key(cache, SCAN)]["scan"]["status"] = status
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 1, f"a cached {status} scan was reused"
        assert result.recommendations[0].scan.status.value == "OK"

    @pytest.mark.asyncio
    async def test_cached_scan_without_a_timestamp_is_rescanned(self):
        """A default-constructed ScanResult has status OK and no timestamp
        -- the shape a "no data" fallback would persist."""
        cache = await _primed()
        cache.store[_key(cache, SCAN)]["scan"]["scan_timestamp"] = ""
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 1
        assert result.recommendations[0].scan.scan_timestamp != ""

    @pytest.mark.asyncio
    async def test_a_perfect_score_does_not_buy_trust(self):
        """A poisoned evaluation carries a perfect score; the gate keys on the
        scan underneath it, never on the number."""
        cache = await _primed()
        cache.store[_key(cache, SCAN)]["scan"]["status"] = "ERROR"
        cache.store[_key(cache, EVAL)]["analysis"]["security_score"] = 100.0
        use_case, scanner = _use_case(cache)

        await use_case.execute("node")

        assert scanner.scans == 1


class TestValidCacheEntriesAreStillUsed:
    """The gate must not degrade the cache into a no-op."""

    @pytest.mark.asyncio
    async def test_verified_entry_skips_the_scanner(self):
        cache = await _primed()
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 0, "a valid cache entry was ignored"
        assert cache.deleted == []
        assert result.recommendations[0].provenance.origin == "cache"


class TestCanonicalCacheIdentity:
    @pytest.mark.asyncio
    async def test_an_unresolved_tag_is_never_a_security_cache_key(self):
        cache = _Cache()
        resolver = _resolver()
        resolver.unreachable = True
        use_case, scanner = _use_case(cache, resolver=resolver)

        result = await use_case.execute("node")

        assert scanner.scans == 1 and result.recommendations
        assert cache.store == {}

    @pytest.mark.asyncio
    async def test_a_malformed_external_digest_is_a_cache_miss_not_an_exception(self):
        cache = _Cache()
        resolver = _resolver(linux_amd64="sha256:not-a-digest")
        use_case, scanner = _use_case(cache, resolver=resolver)

        result = await use_case.execute("node")

        assert scanner.scans == 1
        assert result.recommendations
        assert cache.store == {}
        assert scanner.references == ["node:22-alpine"], "an unpinned tag is scanned as a tag"

    @pytest.mark.asyncio
    async def test_a_hint_digest_from_discovery_is_not_an_identity(self):
        """Docker Hub reports a digest with every tag. It is a hint: the
        registry has to confirm it before a result may be filed under it."""
        hinted = TAG.model_copy(update={"digest": MANIFEST})
        cache = _Cache()
        resolver = _resolver()
        resolver.unreachable = True
        use_case, scanner = _use_case(cache, resolver=resolver, repo=_Repo([hinted]))

        await use_case.execute("node")

        assert cache.store == {}

    @pytest.mark.asyncio
    async def test_tag_mutation_changes_the_cache_key(self):
        cache = await _primed()
        moved = _resolver(linux_amd64=digest_of("b"))
        use_case, scanner = _use_case(cache, resolver=moved)

        await use_case.execute("node")

        assert scanner.scans == 1, "a moved tag reused the previous image's verdict"
        assert len([k for k in cache.store if k.startswith(SCAN)]) == 2

    @pytest.mark.asyncio
    async def test_platform_changes_the_cache_key(self):
        from dockerls.domain.value_objects.platform import Platform

        cache = await _primed()
        resolver = _resolver(linux_amd64=MANIFEST, linux_arm64=digest_of("c"))
        use_case, scanner = _use_case(cache, resolver=resolver, platform=Platform.parse("linux/arm64"))

        await use_case.execute("node")

        assert scanner.scans == 1, "amd64's verdict was served for arm64"
        assert scanner.references == [f"node@{digest_of('c')}"]

    @pytest.mark.asyncio
    async def test_payload_for_another_digest_is_never_served(self):
        cache = await _primed()
        key = _key(cache, SCAN)
        row = cache.store[key]
        row["digest"] = digest_of("f")
        row["scan"]["image_reference"] = f"node@{digest_of('f')}"
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert scanner.scans == 1
        assert result.recommendations[0].scan.image_reference == f"node@{MANIFEST}"

    @pytest.mark.asyncio
    async def test_an_evaluation_for_another_identity_is_never_served(self):
        cache = await _primed()
        key = _key(cache, EVAL)
        cache.store[key]["analysis"]["image"]["digest"] = digest_of("e")
        use_case, scanner = _use_case(cache)

        result = await use_case.execute("node")

        assert result.recommendations[0].image.digest == MANIFEST
        assert scanner.scans == 0, "the scan row is still good; only the evaluation is foreign"


class TestCacheKeyIsSchemaVersioned:
    def test_entries_from_an_older_schema_cannot_be_read(self, tmp_path):
        """Bumping CACHE_SCHEMA_VERSION must orphan old rows rather than
        letting them deserialize into the new shape."""
        from dockerls.cache import sqlite_cache
        from dockerls.cache.sqlite_cache import SQLiteCache

        cache = SQLiteCache(tmp_path / "cache.db")
        import asyncio

        asyncio.run(cache.set("analysis:node:22", {"security_score": 100}))

        original = sqlite_cache.CACHE_SCHEMA_VERSION
        try:
            sqlite_cache.CACHE_SCHEMA_VERSION = "v-next"
            assert asyncio.run(cache.get("analysis:node:22")) is None
        finally:
            sqlite_cache.CACHE_SCHEMA_VERSION = original

        assert asyncio.run(cache.get("analysis:node:22")) is not None


class TestPolicyKeyCoversScoreAffectingInputs:
    """As regras de ignore e o threat intel são aplicados *antes* de avaliar,
    então precisam entrar na chave da *avaliação*. Sem isso o cache guardava
    uma supressão de CVE já revogada e a servia por até 24h. A camada do scan
    bruto não os conhece de propósito: mudá-los não pode custar um scan."""

    def _uc(self, **kwargs):
        return _use_case(_Cache(), **kwargs)[0]

    def test_changing_the_ignore_set_changes_the_key(self, tmp_path):
        ignore = tmp_path / ".dockerls-ignore.yaml"
        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n")
        with_rule = self._uc(ignore_path=ignore)

        ignore.write_text("ignores: []\n")
        without_rule = self._uc(ignore_path=ignore)

        assert with_rule._analysis_fingerprint != without_rule._analysis_fingerprint  # noqa: SLF001

    def test_an_expired_rule_does_not_reuse_the_suppressed_entry(self, tmp_path):
        ignore = tmp_path / ".dockerls-ignore.yaml"
        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n    expires: 2999-01-01\n")
        active = self._uc(ignore_path=ignore)

        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n    expires: 2000-01-01\n")
        expired = self._uc(ignore_path=ignore)

        assert active._analysis_fingerprint != expired._analysis_fingerprint  # noqa: SLF001

    def test_toggling_threat_intel_changes_the_key(self):
        from unittest.mock import MagicMock

        assert (
            self._uc()._analysis_fingerprint  # noqa: SLF001
            != self._uc(threat_intel=MagicMock())._analysis_fingerprint  # noqa: SLF001
        )

    def test_the_same_inputs_give_a_stable_key(self):
        assert self._uc()._analysis_fingerprint == self._uc()._analysis_fingerprint  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_changing_the_ignore_rules_recomputes_without_a_new_scan(self, tmp_path):
        ignore = tmp_path / ".dockerls-ignore.yaml"
        ignore.write_text("ignores: []\n")
        cache = _Cache()
        first, scanner = _use_case(cache, ignore_path=ignore)
        await first.execute("node")

        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n")
        second, _ = _use_case(cache, scanner=scanner, ignore_path=ignore)
        await second.execute("node")

        assert scanner.scans == 1, "a policy change must reuse the raw scan"
        assert len([k for k in cache.store if k.startswith(EVAL)]) == 2


class _BrokenCache(CacheStoreInterface):
    """A cache whose storage is unavailable -- a locked SQLite file, a full
    disk, a read-only home directory."""

    def __init__(self, fail_on: set[str]):
        self.fail_on = fail_on

    async def get(self, key):
        if "get" in self.fail_on:
            raise OSError("database is locked")
        return None

    async def set(self, key, value, ttl_seconds=86400):
        if "set" in self.fail_on:
            raise OSError("database is locked")

    async def delete(self, key):
        if "delete" in self.fail_on:
            raise OSError("database is locked")

    async def clear(self):
        raise OSError("database is locked")


class TestStorageFailuresNeverDiscardAScan:
    """The cache is an optimisation, never a source of truth."""

    @pytest.mark.parametrize("failing", ["set", "get", "delete"])
    @pytest.mark.asyncio
    async def test_image_is_still_recommended(self, failing):
        use_case, scanner = _use_case(_BrokenCache({failing}))

        result = await use_case.execute("node")

        assert scanner.scans == 1
        assert result.recommendations, f"a failing cache.{failing}() dropped a verified scan"
        assert result.recommendations[0].scan.is_verified
        assert result.unverified == []


class TestCacheIsKeyedByDigestNotTag:
    """Tags são mutáveis: `node:22-alpine` de hoje não é a mesma imagem de
    ontem. Uma entrada chaveada por tag continuava servindo o resultado antigo
    por até 24h depois de um rebuild upstream."""

    @pytest.mark.asyncio
    async def test_same_tag_different_digest_is_a_different_entry(self):
        cache = await _primed()
        rebuilt = _resolver(linux_amd64=digest_of("9"))
        use_case, scanner = _use_case(cache, resolver=rebuilt)

        await use_case.execute("node")

        assert scanner.scans == 1, "a rebuilt tag reused the previous image's cached verdict"

    @pytest.mark.asyncio
    async def test_same_digest_under_different_tags_is_one_scan_and_one_entry(self):
        """São os mesmos bytes -- escaneá-los duas vezes é desperdício."""
        tags = [TAG.model_copy(), DockerImage(name="node", tag="22", is_official=True)]
        resolver = _resolver()
        resolver.publish("node", "22", digest_of("1"), linux_amd64=MANIFEST)
        cache = _Cache()
        use_case, scanner = _use_case(cache, resolver=resolver, repo=_Repo(tags))

        await use_case.execute("node")

        assert scanner.scans == 1
        assert len([k for k in cache.store if k.startswith(SCAN)]) == 1

    @pytest.mark.asyncio
    async def test_all_unconfirmed_images_are_ineligible_for_the_security_cache(self):
        cache = _Cache()
        resolver = FakeRegistryResolver()  # knows nothing: every tag is unconfirmed
        tags = [DockerImage(name="node", tag="22-alpine"), DockerImage(name="node", tag="20-alpine")]
        use_case, scanner = _use_case(cache, resolver=resolver, repo=_Repo(tags))

        await use_case.execute("node")

        assert scanner.scans == 2
        assert cache.store == {}


class TestFingerprintCoversTheToolItself:
    """A cached `ImageAnalysis` carries the score, the tier and the readiness
    verdict -- all decided by policy that lives in this package. Keying only
    on the scanner meant a release that changed a penalty weight or a
    blocking rule kept serving verdicts decided under the previous rules
    until the TTL expired."""

    def _use_case(self):
        return _use_case(_Cache())[0]

    def test_the_dockerls_version_is_part_of_the_key(self, monkeypatch):
        from dockerls.application.use_cases import recommend_images as module

        use_case = self._use_case()
        before = use_case._compute_analysis_fingerprint()  # noqa: SLF001
        monkeypatch.setattr(module, "__version__", "999.999.999")
        after = use_case._compute_analysis_fingerprint()  # noqa: SLF001
        assert before != after, (
            "an upgrade that changes scoring policy must not reuse the previous "
            "release's cached verdicts"
        )

    def test_the_scanner_identity_is_still_part_of_the_key(self):
        use_case = self._use_case()
        before = use_case._compute_analysis_fingerprint()  # noqa: SLF001
        use_case._scanner_identity = "grype 0.90.0"  # noqa: SLF001
        assert use_case._compute_analysis_fingerprint() != before  # noqa: SLF001
