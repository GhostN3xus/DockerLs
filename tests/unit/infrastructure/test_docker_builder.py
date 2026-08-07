"""The `docker` CLI wrapper, with the subprocess replaced.

The behaviour under test is what happens when the engine misbehaves: a
non-zero exit, a timeout, no daemon, unparseable inspect output. Every one
of those must produce a `BuildResult` the report can render, never an
exception that loses the validation findings alongside it.
"""

import asyncio
import json

import pytest

from dockerls.application.dto.build import BuildOptions, BuildSecret
from dockerls.infrastructure.docker.build_metadata import collect_build_metadata
from dockerls.infrastructure.docker.docker_builder import DockerCliBuilder

INSPECT_OUTPUT = json.dumps(
    [
        {
            "Id": "sha256:" + "a" * 64,
            "Size": 148897792,
            "RootFS": {"Layers": ["sha256:l1", "sha256:l2"]},
            "History": [
                {"created_by": "FROM alpine"},
                {"created_by": "COPY app", "empty_layer": False},
                {"created_by": "ENV X=1", "empty_layer": True},
            ],
        }
    ]
)


class FakeProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b"", hang=False):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(3600)
        return self._stdout, self._stderr


@pytest.fixture
def spawn(monkeypatch):
    """Replace subprocess creation and record every argv that was run."""
    calls: list[list[str]] = []
    responses: dict[str, FakeProcess] = {}

    async def fake_exec(*cmd, **kwargs):
        calls.append(list(cmd))
        for key, proc in responses.items():
            if key in " ".join(cmd):
                return proc
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return calls, responses


def _options(tmp_path, **kwargs):
    kwargs.setdefault("dockerfile_path", str(tmp_path / "Dockerfile"))
    kwargs.setdefault("context_path", str(tmp_path))
    kwargs.setdefault("tag", "app:1.0")
    return BuildOptions(**kwargs)


class TestAvailability:
    async def test_available_when_the_server_answers(self, spawn):
        calls, responses = spawn
        responses["version"] = FakeProcess(0, b"27.0.1\n")
        assert await DockerCliBuilder().is_available()

    async def test_unavailable_when_the_daemon_is_down(self, spawn):
        """`docker` on PATH says nothing about whether a build can run."""
        calls, responses = spawn
        responses["version"] = FakeProcess(1, b"", b"cannot connect")
        assert not await DockerCliBuilder().is_available()

    async def test_server_version_is_read_back(self, spawn):
        calls, responses = spawn
        responses["version"] = FakeProcess(0, b"27.0.1\n")
        assert await DockerCliBuilder().server_version() == "27.0.1"

    async def test_a_missing_docker_binary_is_not_a_crash(self, monkeypatch):
        async def boom(*cmd, **kwargs):
            raise FileNotFoundError("docker")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
        assert not await DockerCliBuilder().is_available()


class TestBuild:
    async def test_a_successful_build_reads_back_the_image(self, spawn, tmp_path):
        calls, responses = spawn
        responses["image inspect"] = FakeProcess(0, INSPECT_OUTPUT.encode())
        result = await DockerCliBuilder().build(_options(tmp_path))

        assert result.success
        assert result.image_id.startswith("sha256:")
        assert result.size_bytes == 148897792
        assert result.layer_count == 2
        assert result.size_human == "142.0 MB"

    async def test_a_failing_build_is_a_result_not_an_exception(self, spawn, tmp_path):
        calls, responses = spawn
        responses["docker build"] = FakeProcess(1, b"step 3/8 failed\nno such file\n")
        result = await DockerCliBuilder().build(_options(tmp_path))

        assert not result.success
        assert "exited with code 1" in result.error
        assert "no such file" in result.log_tail

    async def test_a_timeout_is_reported_with_its_limit(self, spawn, tmp_path):
        calls, responses = spawn
        responses["docker build"] = FakeProcess(hang=True)
        result = await DockerCliBuilder(timeout=0).build(_options(tmp_path))

        assert not result.success
        assert "timeout" in result.error

    async def test_an_invalid_tag_never_reaches_the_daemon(self, spawn, tmp_path):
        calls, responses = spawn
        result = await DockerCliBuilder().build(_options(tmp_path, tag="--rm"))

        assert not result.success
        assert calls == [], "a rejected argument must not spawn docker at all"

    async def test_unparseable_inspect_output_does_not_lose_the_build(self, spawn, tmp_path):
        """The image exists and may already be scanned; refusing it over a
        missing layer breakdown would throw away a passing build."""
        calls, responses = spawn
        responses["image inspect"] = FakeProcess(0, b"not json")
        result = await DockerCliBuilder().build(_options(tmp_path))

        assert result.success
        assert result.layers == []

    async def test_a_failed_inspect_does_not_lose_the_build(self, spawn, tmp_path):
        calls, responses = spawn
        responses["image inspect"] = FakeProcess(1, b"", b"no such image")
        assert (await DockerCliBuilder().build(_options(tmp_path))).success

    async def test_the_secret_value_never_appears_in_argv(self, spawn, tmp_path, monkeypatch):
        monkeypatch.setenv("NPM_TOKEN", "s3cr3t")
        calls, responses = spawn
        responses["image inspect"] = FakeProcess(0, INSPECT_OUTPUT.encode())
        options = _options(tmp_path, secrets=[BuildSecret(secret_id="npm", env="NPM_TOKEN")])
        await DockerCliBuilder().build(options)

        argv = " ".join(calls[0])
        assert "id=npm,env=NPM_TOKEN" in argv
        assert "s3cr3t" not in argv, "the material must stay in the environment, not in argv"


class TestPush:
    async def test_a_successful_push(self, spawn):
        calls, responses = spawn
        responses["docker push"] = FakeProcess(0, b"pushed\n")
        ok, message = await DockerCliBuilder().push("ghcr.io/org/app:1.0")
        assert ok
        assert "pushed" in message

    async def test_a_rejected_push_reports_the_reason(self, spawn):
        calls, responses = spawn
        responses["docker push"] = FakeProcess(1, b"", b"denied: requires authentication")
        ok, message = await DockerCliBuilder().push("ghcr.io/org/app:1.0")
        assert not ok
        assert "denied" in message

    async def test_an_invalid_tag_is_refused_before_spawning(self, spawn):
        calls, responses = spawn
        ok, message = await DockerCliBuilder().push("--all-tags")
        assert not ok
        assert calls == []


class TestBuildMetadata:
    async def test_records_provenance_when_git_answers(self, spawn, tmp_path):
        calls, responses = spawn
        responses["rev-parse HEAD"] = FakeProcess(0, b"a1b2c3d4\n")
        responses["--abbrev-ref"] = FakeProcess(0, b"main\n")
        metadata = await collect_build_metadata(str(tmp_path), docker_version="27.0.1")

        assert metadata.git_sha == "a1b2c3d4"
        assert metadata.git_branch == "main"
        assert metadata.docker_version == "27.0.1"
        assert "@" in metadata.built_by
        assert metadata.timestamp

    async def test_outside_a_git_checkout_it_says_unknown_rather_than_inventing(
        self, spawn, tmp_path
    ):
        calls, responses = spawn
        responses["rev-parse"] = FakeProcess(128, b"", b"not a git repository")
        metadata = await collect_build_metadata(str(tmp_path))
        assert metadata.git_sha == ""

    async def test_a_missing_git_binary_is_not_fatal(self, monkeypatch, tmp_path):
        async def boom(*cmd, **kwargs):
            raise FileNotFoundError("git")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
        metadata = await collect_build_metadata(str(tmp_path))
        assert metadata.git_sha == ""
        assert metadata.dockerls_version
