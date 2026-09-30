"""Behavioural tests for identity-pinned, shared, bounded measurement.

Each test names a way a result could end up describing the wrong bytes, the
wrong platform, a stale database or someone else's work -- and proves it does
not.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

from dockerls.application.services.measurement import MeasurementService
from dockerls.application.services.measurement_store import (
    UNKNOWN_REVISION_TTL_SECONDS,
    MeasurementStore,
    MissReason,
    ScannerFingerprint,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanStatus
from dockerls.domain.value_objects.platform import Platform
from dockerls.utils.deadline import Deadline
from tests.unit.application.measurement_fakes import (
    FakeRegistryResolver,
    FakeScanner,
    InMemoryCache,
    digest_of,
)

INDEX = digest_of("1")
AMD64 = digest_of("a")
ARM64 = digest_of("b")
NEW_AMD64 = digest_of("c")


def _world(cache: InMemoryCache | None = None, **scanner_kwargs):
    cache = cache if cache is not None else InMemoryCache()
    resolver = FakeRegistryResolver()
    resolver.publish("node", "22", INDEX, linux_amd64=AMD64, linux_arm64=ARM64)
    scanner = FakeScanner(**scanner_kwargs)
    scanner.findings = {AMD64: 3, ARM64: 5, NEW_AMD64: 9}
    scanner.live_tags = {"node:22": AMD64}
    return cache, resolver, scanner


def _service(scanner, resolver, cache, *, platform="linux/amd64", now=None, **kwargs):
    store = MeasurementStore(cache, **({"clock": now} if now else {}))
    return MeasurementService(
        scanner, resolver=resolver, store=store, platform=Platform.parse(platform), **kwargs
    )


def _image(tag="22", name="node") -> DockerImage:
    return DockerImage(name=name, tag=tag)


class TestImmutableIdentity:
    async def test_the_scanner_is_handed_the_platform_manifest_digest_not_the_tag(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, cache)

        result = await service.measure(_image())

        assert scanner.calls == [(f"node@{AMD64}", "linux/amd64")]
        assert result.refs.requested == "node:22"
        assert result.refs.resolved == f"node@{AMD64}"
        assert result.refs.measured == f"node@{AMD64}"
        # the index digest is recorded, and is not what was scanned
        assert result.provenance.index_digest == INDEX
        assert result.provenance.manifest_digest == AMD64

    async def test_a_tag_that_moves_between_resolution_and_scan_cannot_change_what_is_measured(
        self,
    ):
        cache, resolver, scanner = _world()
        # The moment the scanner starts, the tag is repointed at other bytes --
        # exactly the race the old `scan(name:tag)` lost.
        scanner.on_scan = lambda ref: scanner.live_tags.update({"node:22": NEW_AMD64})
        service = _service(scanner, resolver, cache)

        result = await service.measure(_image())

        assert result.scan.image_reference == f"node@{AMD64}"
        assert len(result.scan.vulnerabilities) == 3  # AMD64's findings, not NEW_AMD64's 9
        assert result.provenance.manifest_digest == AMD64
        assert all(NEW_AMD64 not in key for key in cache.rows)

    async def test_the_image_records_the_confirmed_digest_and_keeps_its_tag(self):
        cache, resolver, scanner = _world()
        image = _image()
        await _service(scanner, resolver, cache).measure(image)

        assert image.digest == AMD64
        assert image.index_digest == INDEX
        assert image.tag == "22" and image.full_reference == "node:22"
        assert image.identity_confirmed
        assert image.platform == "linux/amd64"
        assert image.requested_reference == "node:22"
        assert image.measured_reference == f"node@{AMD64}"

    async def test_a_platform_without_a_manifest_is_never_measured(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, cache, platform="linux/s390x")

        result = await service.measure(_image())

        assert scanner.calls == []
        assert not result.scan.is_verified
        assert result.scan.error_kind is ScanErrorKind.PLATFORM_UNAVAILABLE
        assert "linux/s390x" in result.scan.error_message

    async def test_different_platforms_never_share_a_result(self):
        cache, resolver, scanner = _world()

        amd64 = await _service(scanner, resolver, cache, platform="linux/amd64").measure(_image())
        arm64 = await _service(scanner, resolver, cache, platform="linux/arm64").measure(_image())

        assert (len(amd64.scan.vulnerabilities), len(arm64.scan.vulnerabilities)) == (3, 5)
        assert not arm64.from_cache
        assert [c[1] for c in scanner.calls] == ["linux/amd64", "linux/arm64"]
        assert len([k for k in cache.rows if k.startswith("m:scan:")]) == 2

    async def test_an_unconfirmed_identity_is_measured_but_never_filed_as_evidence(self):
        cache, resolver, scanner = _world()
        resolver.unreachable = True
        service = _service(scanner, resolver, cache)

        first = await service.measure(_image())
        second = await _service(scanner, resolver, cache).measure(_image())

        assert first.scan.is_verified
        assert first.provenance.identity_status == "UNRESOLVED"
        assert first.provenance.limitation
        assert first.refs.resolved == ""
        assert not first.stored_as_evidence
        assert [k for k in cache.rows if k.startswith("m:scan:")] == []
        assert not second.from_cache, "an unpinned result must never be reused as pinned"
        assert len(scanner.calls) == 2

    async def test_a_user_supplied_digest_is_scanned_as_named_even_without_a_registry(self):
        cache, resolver, scanner = _world()
        resolver.unreachable = True
        scanner.findings[AMD64] = 1
        image = DockerImage(name="node", tag="latest", full_reference=f"node@{AMD64}")

        result = await _service(scanner, resolver, cache).measure(image)

        assert scanner.calls[0][0] == f"node@{AMD64}"
        assert result.provenance.identity_status == "DIGEST_ONLY"
        assert not result.stored_as_evidence

    async def test_a_scanner_that_cannot_take_a_platform_refuses_rather_than_guess(self):
        cache, resolver, _ = _world()
        resolver.unreachable = True

        class Legacy(FakeScanner):
            async def scan(self, image_reference):  # no platform parameter
                return await super().scan(image_reference)

        legacy = Legacy()
        result = await _service(legacy, resolver, cache, platform="linux/arm64").measure(_image())

        assert legacy.calls == []
        assert result.scan.error_kind is ScanErrorKind.PLATFORM_UNAVAILABLE


class TestSharedCacheAcrossCommands:
    async def test_a_second_command_reuses_the_first_ones_scan(self):
        cache, resolver, scanner = _world()
        analyze_like = _service(scanner, resolver, cache)
        advisor_like = _service(scanner, resolver, cache)

        first = await analyze_like.measure(_image())
        second = await advisor_like.measure(_image())

        assert len(scanner.calls) == 1
        assert not first.from_cache and second.from_cache
        assert second.provenance.origin == "cache"
        assert second.provenance.measured_at == first.provenance.measured_at
        assert second.scan.vulnerabilities == first.scan.vulnerabilities

    async def test_two_tags_of_one_manifest_are_one_scan(self):
        cache, resolver, scanner = _world()
        resolver.publish("node", "lts", INDEX, linux_amd64=AMD64)
        scanner.live_tags["node:lts"] = AMD64
        service = _service(scanner, resolver, cache)

        results = await service.measure_many([_image("22"), _image("lts")])

        assert len(scanner.calls) == 1
        assert {r.scan.image_reference for r in results} == {f"node@{AMD64}"}
        assert service.stats.duplicates_avoided == 1

    async def test_no_cache_means_no_reads_and_no_writes_but_still_one_scan_per_run(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, None)  # --no-cache

        await service.measure(_image())
        await service.measure(_image("22"))  # the same identity again, same run

        assert cache.rows == {}
        assert len(scanner.calls) == 1, "the in-run memo is not the persistent cache"
        again = await _service(scanner, resolver, None).measure(_image())
        assert not again.from_cache
        assert len(scanner.calls) == 2


class TestInvalidation:
    async def test_a_database_update_invalidates_the_reusable_measurement(self):
        cache, resolver, scanner = _world(db_revision="2026-09-01T00:00:00+00:00")
        await _service(scanner, resolver, cache).measure(_image())

        refreshed = FakeScanner(db_revision="2026-09-02T00:00:00+00:00")
        refreshed.findings = dict(scanner.findings)
        result = await _service(refreshed, resolver, cache).measure(_image())

        assert not result.from_cache
        assert len(refreshed.calls) == 1
        assert result.provenance.cache_note.startswith(MissReason.DB_REVISION_CHANGED.value)
        assert result.provenance.db_revision == "2026-09-02T00:00:00+00:00"

    async def test_a_scanner_upgrade_invalidates_it_too(self):
        cache, resolver, scanner = _world(version="trivy 0.60.0")
        await _service(scanner, resolver, cache).measure(_image())
        upgraded = FakeScanner(version="trivy 0.61.0")
        upgraded.findings = dict(scanner.findings)

        result = await _service(upgraded, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.SCANNER_CHANGED.value)

    async def test_changed_scan_options_invalidate_it(self):
        cache, resolver, scanner = _world(options="opts-v1")
        await _service(scanner, resolver, cache).measure(_image())
        other = FakeScanner(options="opts-v2")
        other.findings = dict(scanner.findings)

        result = await _service(other, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.OPTIONS_CHANGED.value)

    async def test_an_unknown_database_revision_gets_the_conservative_policy(self):
        clock = [1_000_000.0]
        cache, resolver, scanner = _world(db_revision="")

        def now() -> float:
            return clock[0]

        service = _service(scanner, resolver, cache, now=now)
        await service.measure(_image())

        # within the short window, another run that also cannot tell reuses it
        clock[0] += 60
        same = await _service(scanner, resolver, cache, now=now).measure(_image())
        assert same.from_cache

        # after it, the row is not trusted -- unknown is never "unchanged"
        clock[0] += UNKNOWN_REVISION_TTL_SECONDS + 1
        later = await _service(scanner, resolver, cache, now=now).measure(_image())
        assert not later.from_cache
        assert later.provenance.cache_note.startswith(MissReason.DB_REVISION_UNKNOWN.value)

    async def test_a_row_written_without_a_revision_is_not_served_to_a_run_that_knows_it(self):
        cache, resolver, unknown = _world(db_revision="")
        await _service(unknown, resolver, cache).measure(_image())
        known = FakeScanner(db_revision="2026-09-01T00:00:00+00:00")
        known.findings = dict(unknown.findings)

        result = await _service(known, resolver, cache).measure(_image())

        assert not result.from_cache

    async def test_an_expired_row_is_a_miss(self):
        clock = [1_000_000.0]
        cache, resolver, scanner = _world()

        def now() -> float:
            return clock[0]

        await _service(scanner, resolver, cache, now=now).measure(_image())
        clock[0] += 3 * 24 * 3600
        result = await _service(scanner, resolver, cache, now=now).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.EXPIRED.value)


class TestUntrustedCacheRows:
    def _only_scan_key(self, cache):
        (key,) = [k for k in cache.rows if k.startswith("m:scan:")]
        return key

    async def test_a_corrupt_row_is_a_miss_that_is_evicted(self):
        cache, resolver, scanner = _world()
        await _service(scanner, resolver, cache).measure(_image())
        key = self._only_scan_key(cache)
        cache.rows[key] = {"schema_version": 1, "layer": "scan", "digest": 12345}

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.CORRUPT.value)
        assert key in cache.deleted, "a corrupt row is evicted so it is not re-read forever"

    async def test_a_row_that_is_not_even_an_object_is_a_miss(self):
        cache, resolver, scanner = _world()
        await _service(scanner, resolver, cache).measure(_image())
        cache.rows[self._only_scan_key(cache)] = ["not", "a", "record"]

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.from_cache

    async def test_an_incompatible_schema_is_a_miss(self):
        cache, resolver, scanner = _world()
        await _service(scanner, resolver, cache).measure(_image())
        cache.rows[self._only_scan_key(cache)]["schema_version"] = 999

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.SCHEMA_MISMATCH.value)

    async def test_a_row_of_another_identity_is_never_served_under_this_key(self):
        cache, resolver, scanner = _world()
        await _service(scanner, resolver, cache).measure(_image())
        key = self._only_scan_key(cache)
        # a tampered/misfiled row: ARM64's findings stored under AMD64's key
        arm = cache.rows[key]
        arm["digest"] = ARM64
        arm["scan"]["image_reference"] = f"node@{ARM64}"

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.IDENTITY_MISMATCH.value)
        assert len(result.scan.vulnerabilities) == 3

    async def test_an_incomplete_scan_in_the_cache_is_not_a_complete_analysis(self):
        cache, resolver, scanner = _world()
        await _service(scanner, resolver, cache).measure(_image())
        key = self._only_scan_key(cache)
        cache.rows[key]["scan"]["status"] = "PARTIAL"

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.from_cache
        assert result.provenance.cache_note.startswith(MissReason.INCOMPLETE_SCAN.value)

    async def test_an_unreadable_cache_is_a_miss_and_never_an_error(self):
        cache, resolver, scanner = _world()
        cache.fail_reads = True

        result = await _service(scanner, resolver, cache).measure(_image())

        assert result.scan.is_verified and not result.from_cache

    async def test_a_failing_cache_write_does_not_invalidate_a_finished_scan(self):
        cache, resolver, scanner = _world()
        cache.fail_writes = True
        service = _service(scanner, resolver, cache)

        result = await service.measure(_image())

        assert result.scan.is_verified
        assert len(result.scan.vulnerabilities) == 3
        assert service.store.writes_failed >= 1
        assert service.store.diagnostics

    @pytest.mark.parametrize("status", [ScanStatus.PARTIAL, ScanStatus.ERROR, ScanStatus.TIMEOUT])
    async def test_incomplete_or_failed_scans_are_never_stored(self, status):
        cache, resolver, scanner = _world()
        scanner.status_for[f"node@{AMD64}"] = status

        result = await _service(scanner, resolver, cache).measure(_image())

        assert not result.scan.is_verified
        assert [k for k in cache.rows if k.startswith("m:scan:")] == []


class TestPolicyIsSeparateFromTheScan:
    async def test_a_policy_change_misses_the_evaluation_but_not_the_scan(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, cache)
        measured = await service.measure(_image())
        strict = measured.identity.identity
        fingerprint = await service.fingerprint()
        store = service.store
        await store.put_evaluation(
            strict,
            fingerprint,
            "policy-A",
            {"security_score": 90.0},
            scan_measured_at=measured.provenance.measured_at,
            intel_at=None,
        )
        # measured_at on the record is the store's stamp; re-read the scan row
        record = (await store.get_scan(strict, fingerprint)).value
        await store.put_evaluation(
            strict,
            fingerprint,
            "policy-A",
            {"security_score": 90.0},
            scan_measured_at=record.measured_at,
            intel_at=None,
        )

        same_policy = await store.get_evaluation(strict, fingerprint, "policy-A")
        other_policy = await store.get_evaluation(strict, fingerprint, "policy-B")
        raw_scan = await store.get_scan(strict, fingerprint)

        assert same_policy.hit and same_policy.value == {"security_score": 90.0}
        assert other_policy.reason is MissReason.POLICY_CHANGED
        assert raw_scan.hit, "changing policy must not cost a new raw scan"
        assert len(scanner.calls) == 1

    async def test_an_evaluation_dies_with_the_scan_it_was_derived_from(self):
        cache, resolver, scanner = _world(db_revision="r1")
        service = _service(scanner, resolver, cache)
        measured = await service.measure(_image())
        strict = measured.identity.identity
        fingerprint = await service.fingerprint()
        record = (await service.store.get_scan(strict, fingerprint)).value
        await service.store.put_evaluation(
            strict, fingerprint, "p", {"x": 1}, scan_measured_at=record.measured_at, intel_at=None
        )

        new_db = ScannerFingerprint(
            name=fingerprint.name,
            version=fingerprint.version,
            db_revision="r2",
            options=fingerprint.options,
        )
        lookup = await service.store.get_evaluation(strict, new_db, "p")

        assert lookup.reason is MissReason.DB_REVISION_CHANGED

    async def test_stale_enrichment_makes_only_the_evaluation_stale(self):
        clock = [1_000_000.0]
        cache, resolver, scanner = _world()

        def now() -> float:
            return clock[0]

        service = _service(scanner, resolver, cache, now=now)
        measured = await service.measure(_image())
        strict = measured.identity.identity
        fingerprint = await service.fingerprint()
        record = (await service.store.get_scan(strict, fingerprint)).value
        await service.store.put_evaluation(
            strict,
            fingerprint,
            "p",
            {"x": 1},
            scan_measured_at=record.measured_at,
            intel_at=clock[0],
        )
        clock[0] += 7 * 3600

        evaluation = await service.store.get_evaluation(strict, fingerprint, "p")
        scan = await service.store.get_scan(strict, fingerprint)

        assert evaluation.reason is MissReason.ENRICHMENT_STALE
        assert scan.hit


class TestBoundedSharedWork:
    async def test_concurrent_requests_for_one_identity_are_one_scan(self):
        cache, resolver, scanner = _world(latency=0.05)
        service = _service(scanner, resolver, cache, max_concurrency=4)

        results = await asyncio.gather(*(service.measure(_image()) for _ in range(10)))

        assert len(scanner.calls) == 1
        assert service.stats.scans_performed == 1
        assert service.stats.duplicates_avoided == 9
        assert sum(1 for r in results if r.shared) == 9

    async def test_a_compare_of_many_images_respects_the_concurrency_limit_and_order(self):
        cache, resolver, scanner = _world(latency=0.03)
        images = []
        for i in range(9):
            tag = f"t{i}"
            digest = digest_of(str(i + 2))
            resolver.publish("app", tag, digest_of("f"), linux_amd64=digest)
            scanner.findings[digest] = i
            images.append(DockerImage(name="app", tag=tag))
        service = _service(scanner, resolver, cache, max_concurrency=3)

        results = await service.measure_many(images)

        assert scanner.max_in_flight == 3, "limited, and actually concurrent"
        assert [len(r.scan.vulnerabilities) for r in results] == list(range(9))

    async def test_one_failing_image_does_not_spoil_the_others(self):
        cache, resolver, scanner = _world()
        good, bad = digest_of("7"), digest_of("8")
        resolver.publish("app", "good", digest_of("f"), linux_amd64=good)
        resolver.publish("app", "bad", digest_of("f"), linux_amd64=bad)
        scanner.findings[good] = 2
        scanner.raise_for = {f"app@{bad}"}
        service = _service(scanner, resolver, cache, max_concurrency=2)

        results = await service.measure_many(
            [DockerImage(name="app", tag="bad"), DockerImage(name="app", tag="good")]
        )

        assert not results[0].scan.is_verified
        assert "crashed" in results[0].scan.error_message
        assert results[1].scan.is_verified and len(results[1].scan.vulnerabilities) == 2

    async def test_the_database_is_prepared_once_however_many_callers_ask(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, cache)

        await asyncio.gather(*(service.prepare() for _ in range(5)))

        assert scanner.refreshes == 1


class TestDeadline:
    async def test_the_budget_cancels_a_running_scan_and_its_subprocess(self, tmp_path):
        """A real child process, so "cancelled" is observable and not assumed."""
        from dockerls.domain.entities.scan_result import ScanResult
        from dockerls.domain.interfaces.scanner import ScannerInterface
        from dockerls.utils.subprocess_runner import run_capture

        pid_file = tmp_path / "child.pid"

        class SubprocessScanner(ScannerInterface):
            async def is_available(self) -> bool:
                return True

            async def scan(self, image_reference: str, platform: str | None = None) -> ScanResult:
                code = (
                    f"import os,time;open({str(pid_file)!r},'w').write(str(os.getpid()));"
                    "time.sleep(60)"
                )
                await run_capture([sys.executable, "-c", code], timeout=120)
                raise AssertionError("the subprocess should have been killed")

        cache, resolver, _ = _world()
        service = MeasurementService(
            SubprocessScanner(),
            resolver=resolver,
            store=MeasurementStore(cache),
            deadline=Deadline(1.0),
            min_scan_seconds=0.1,
        )

        result = await service.measure(_image())

        assert result.scan.error_kind is ScanErrorKind.DEADLINE_EXCEEDED
        assert result.scan.status is ScanStatus.TIMEOUT
        pid = int(pid_file.read_text())
        with pytest.raises(ProcessLookupError):
            for _ in range(50):  # the kernel may need a moment to reap it
                os.kill(pid, 0)
                await asyncio.sleep(0.05)
        assert [k for k in cache.rows if k.startswith("m:scan:")] == []

    async def test_a_scan_is_not_started_when_the_rest_of_the_budget_cannot_hold_it(self):
        cache, resolver, scanner = _world()
        service = _service(scanner, resolver, cache, deadline=Deadline(2.0), min_scan_seconds=30.0)

        result = await service.measure(_image())

        assert scanner.calls == []
        assert result.scan.error_kind is ScanErrorKind.DEADLINE_EXCEEDED
        assert "not started" in result.scan.error_message
        assert service.stats.not_started_deadline == 1

    async def test_measurements_finished_before_the_deadline_survive_it(self):
        cache, resolver, scanner = _world(latency=0.4)
        fast = digest_of("5")
        resolver.publish("app", "fast", digest_of("f"), linux_amd64=fast)
        scanner.findings[fast] = 1
        service = _service(
            scanner,
            resolver,
            cache,
            deadline=Deadline(0.3),
            min_scan_seconds=0.05,
            max_concurrency=2,
        )
        scanner.latency = 0.0
        first = await service.measure(DockerImage(name="app", tag="fast"))
        scanner.latency = 5.0
        second = await service.measure(_image())

        assert first.scan.is_verified
        assert second.scan.error_kind is ScanErrorKind.DEADLINE_EXCEEDED
