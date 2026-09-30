"""`compare` at the use-case level: bounded, ordered, isolated, cancellable.

The analyse use case is a fake that records how many analyses are in flight
at once, so the limit is measured rather than assumed.
"""

from __future__ import annotations

import asyncio

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus


def _analysis(reference: str, score: float, *, verified: bool = True) -> ImageAnalysis:
    name, _, tag = reference.partition(":")
    image = DockerImage(name=name, tag=tag)
    scan = (
        ScanResult(image_reference=reference, scan_timestamp="2026-01-01T00:00:00Z")
        if verified
        else ScanResult(
            image_reference=reference,
            status=ScanStatus.ERROR,
            error_kind=ScanErrorKind.TIMEOUT,
            error_message="scanner timed out",
        )
    )
    return ImageAnalysis(
        image=image, scan=scan, security_score=score, tier="A", remediation_score=100
    )


class _FakeAnalyze:
    def __init__(self, concurrency, delays=None, scores=None, crash=()):
        self.concurrency = concurrency
        self.delays = delays or {}
        self.scores = scores or {}
        self.crash = set(crash)
        self.in_flight = 0
        self.peak = 0
        self.started: list[str] = []
        self.closed = 0

    async def execute(self, reference: str) -> ImageAnalysis:
        self.started.append(reference)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(self.delays.get(reference, 0.01))
            if reference in self.crash:
                raise RuntimeError(f"registry refused {reference}")
            return _analysis(reference, self.scores.get(reference, 90.0))
        finally:
            self.in_flight -= 1

    async def close(self):
        self.closed += 1


@pytest.mark.asyncio
class TestCompareConcurrency:
    async def test_two_images_are_analysed_together(self):
        fake = _FakeAnalyze(concurrency=4)
        result = await CompareImagesUseCase(fake).execute(["a:1", "b:1"])
        assert fake.peak == 2
        assert [i.image.full_reference for i in result.images] == ["a:1", "b:1"]

    async def test_many_images_never_exceed_the_limit(self):
        refs = [f"img:{n}" for n in range(12)]
        fake = _FakeAnalyze(concurrency=3)
        result = await CompareImagesUseCase(fake).execute(refs)
        assert fake.peak == 3
        assert len(result.images) == 12

    async def test_unknown_limit_runs_one_at_a_time(self):
        fake = _FakeAnalyze(concurrency=None)
        await CompareImagesUseCase(fake).execute(["a:1", "b:1", "c:1"])
        assert fake.peak == 1

    async def test_result_order_is_the_order_asked_not_the_order_finished(self):
        refs = ["slow:1", "mid:1", "fast:1"]
        fake = _FakeAnalyze(concurrency=3, delays={"slow:1": 0.12, "mid:1": 0.06, "fast:1": 0.0})
        result = await CompareImagesUseCase(fake).execute(refs)
        assert [i.image.full_reference for i in result.images] == refs

    async def test_one_crash_is_that_images_row_not_the_end_of_the_others(self):
        fake = _FakeAnalyze(concurrency=3, crash={"bad:1"}, scores={"good:1": 80.0, "ok:1": 95.0})
        result = await CompareImagesUseCase(fake).execute(["good:1", "bad:1", "ok:1"])
        assert [i.image.full_reference for i in result.images] == ["good:1", "ok:1"]
        assert [u.image_reference for u in result.unverified] == ["bad:1"]
        assert "registry refused" in result.unverified[0].reason
        assert result.winner == "ok:1"

    async def test_all_failing_yields_no_winner(self):
        fake = _FakeAnalyze(concurrency=2, crash={"a:1", "b:1"})
        result = await CompareImagesUseCase(fake).execute(["a:1", "b:1"])
        assert result.images == [] and result.winner == ""
        assert len(result.unverified) == 2

    async def test_resources_are_released_once_even_when_everything_fails(self):
        fake = _FakeAnalyze(concurrency=2, crash={"a:1"})
        await CompareImagesUseCase(fake).execute(["a:1"])
        assert fake.closed == 1

    async def test_cancellation_stops_the_analyses_and_still_releases(self):
        fake = _FakeAnalyze(concurrency=2, delays={"a:1": 5, "b:1": 5})
        task = asyncio.create_task(CompareImagesUseCase(fake).execute(["a:1", "b:1"]))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fake.in_flight == 0
        assert fake.closed == 1
