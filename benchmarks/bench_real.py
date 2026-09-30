"""REAL end-to-end timings: the installed `dockerls` CLI, a real Trivy, real registries.

    python benchmarks/bench_real.py --repeat 3 --json benchmarks/results/real.json

Nothing is simulated. Every number is wall-clock time of a subprocess on *this*
machine and *this* network, so it is only comparable to another run on the same
setup, and it varies with registry load. The environment block records the
tool versions that were actually used.

Three cache states are separated, because "cold" means different things:

* `cold everything`   -- fresh DockerLs store, fresh Trivy directory: the DB is
                         downloaded again. Slow and only run with `--full-cold`.
* `store cold`        -- fresh DockerLs store, Trivy's DB (and its layer cache)
                         already on disk: the first measurement of an image on a
                         machine that has run Trivy before.
* `store warm`        -- the same store again: the measurement is reused.

The default target is a small public image on a mirror that is not
rate-limited for anonymous pulls. `--include-hub` adds a `recommend` run
against Docker Hub, which throttles anonymous manifest requests: when it does,
the run is reported as it ended (identity unconfirmed), not retried until it
looks good.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks._common import Row, Sample, emit, environment, summarize


def _tool_version(*cmd: str) -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(cmd), capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "not installed"
    return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else ""


class Sandbox:
    """Private cache/state directories so a run never touches the real ones."""

    def __init__(self, trivy_dir: Path | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="dockerls-bench-"))
        self.trivy_dir = trivy_dir or self.root / "trivy"

    def env(self, engine: str) -> dict[str, str]:
        env = dict(os.environ)
        env["XDG_CACHE_HOME"] = str(self.root / "cache")
        env["XDG_STATE_HOME"] = str(self.root / "state")
        env["TRIVY_CACHE_DIR"] = str(self.trivy_dir)
        env["NO_COLOR"] = "1"
        if engine == "python":
            # A path that is not an executable file: the locator logs it and
            # answers "no engine", so the pure-Python path is what runs.
            env["DOCKERLS_ENGINE_PATH"] = str(self.root / "no-engine")
        return env

    def fresh_store(self) -> None:
        for name in ("cache", "state"):
            shutil.rmtree(self.root / name, ignore_errors=True)

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def run_cli(args: list[str], env: dict[str, str], timeout: float) -> tuple[float, int, str, str]:
    started = time.perf_counter()
    try:
        done = subprocess.run(  # noqa: S603 - argv built from constants and CLI options
            [shutil.which("dockerls") or "dockerls", *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return time.perf_counter() - started, -9, "", "timeout"
    return time.perf_counter() - started, done.returncode, done.stdout, done.stderr


def origin_of(stdout: str) -> str:
    """`scan` / `cache` / `shared` from a `--format summary` document, if present."""
    try:
        doc = json.loads(stdout)
    except ValueError:
        return ""
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("origin"), str):
                return node["origin"]
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return ""


def measure(
    label: str,
    args: list[str],
    *,
    sandbox: Sandbox,
    engine: str,
    repeat: int,
    warm: bool,
    timeout: float,
    notes: list[str],
) -> Row:
    samples: list[Sample] = []
    origins: list[str] = []
    codes: list[int] = []
    for i in range(repeat):
        if not warm:
            sandbox.fresh_store()
        elif i == 0:
            sandbox.fresh_store()
            run_cli(args, sandbox.env(engine), timeout)  # populate, not timed
        seconds, code, out, _ = run_cli(args, sandbox.env(engine), timeout)
        codes.append(code)
        origins.append(origin_of(out))
        samples.append(Sample(seconds, {"exit": float(code)}))
    note = f"exit codes {sorted(set(codes))}; origin {sorted({o for o in origins if o}) or 'n/a'}"
    notes.append(f"{label}: {note}")
    return summarize(label, "real", samples, note)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--image", default="mirror.gcr.io/library/alpine:3.20")
    p.add_argument("--second-image", default="mirror.gcr.io/library/alpine:3.19")
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument("--full-cold", action="store_true", help="also time a run that downloads the DB")
    p.add_argument("--include-hub", action="store_true", help="also time `recommend` on Docker Hub")
    p.add_argument("--engine", choices=["python", "go", "both"], default="python")
    p.add_argument("--json", default=None)
    args = p.parse_args()

    if shutil.which("dockerls") is None or shutil.which("trivy") is None:
        sys.exit("bench_real needs `dockerls` and `trivy` on PATH")

    engines = ["python", "go"] if args.engine == "both" else [args.engine]
    env_extra = {
        "trivy": _tool_version("trivy", "--version"),
        "grype": _tool_version("grype", "version"),
        "image": args.image,
        "network": "real, unthrottled by this script",
    }
    rows: list[Row] = []
    notes: list[str] = []
    sandbox = Sandbox()
    try:
        print("Preparing the Trivy DB (not timed)...", file=sys.stderr)
        run_cli(["analyze", args.image, "--format", "summary"], sandbox.env("python"), args.timeout)
        analyze = ["analyze", args.image, "--platform", "linux/amd64", "--format", "summary"]
        arm = ["analyze", args.image, "--platform", "linux/arm64", "--format", "summary"]
        compare = ["compare", args.image, args.second_image, "--platform", "linux/amd64"]
        for engine in engines:
            common = {"sandbox": sandbox, "engine": engine, "timeout": args.timeout, "notes": notes}
            tag = f"[{engine}] "
            if args.full_cold:
                cold = Sandbox()
                try:
                    rows.append(
                        measure(
                            tag + "analyze, cold everything",
                            analyze,
                            **{**common, "sandbox": cold},
                            repeat=1,
                            warm=False,
                        )
                    )
                finally:
                    cold.close()
            rows.append(
                measure(
                    tag + "analyze amd64, store cold",
                    analyze,
                    repeat=args.repeat,
                    warm=False,
                    **common,
                )
            )
            rows.append(
                measure(
                    tag + "analyze amd64, store warm",
                    analyze,
                    repeat=args.repeat,
                    warm=True,
                    **common,
                )
            )
            rows.append(
                measure(
                    tag + "analyze arm64, store cold", arm, repeat=args.repeat, warm=False, **common
                )
            )
            rows.append(
                measure(
                    tag + "compare 2 images, store cold",
                    compare,
                    repeat=args.repeat,
                    warm=False,
                    **common,
                )
            )
            rows.append(
                measure(
                    tag + "compare 2 images, store warm",
                    compare,
                    repeat=args.repeat,
                    warm=True,
                    **common,
                )
            )
            if args.include_hub:
                rec = [
                    "recommend",
                    "alpine",
                    "--limit",
                    "20",
                    "--format",
                    "summary",
                    "--no-progress",
                ]
                rows.append(
                    measure(
                        tag + "recommend alpine (Docker Hub)",
                        rec,
                        repeat=max(1, args.repeat - 1),
                        warm=False,
                        **common,
                    )
                )
    finally:
        sandbox.close()

    emit(
        "DockerLs end-to-end timings (REAL CLI, real Trivy, real registries)",
        environment(**env_extra),
        {"repeat": args.repeat, "engine": args.engine},
        rows,
        args.json,
    )


if __name__ == "__main__":
    main()
