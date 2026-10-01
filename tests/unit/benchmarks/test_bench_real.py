from __future__ import annotations

import json

from benchmarks.bench_real import origin_of, timing_counters


def test_timing_counters_group_instrumented_stages() -> None:
    stdout = json.dumps(
        {
            "recommendations": [
                {
                    "metrics": {
                        "timings": {
                            "stages": {
                                "startup": {"seconds": 0.2, "calls": 1},
                                "discovery": {"seconds": 0.5, "calls": 1},
                                "identity_resolution": {"seconds": 0.3, "calls": 2},
                                "database_preparation": {"seconds": 1.0, "calls": 1},
                                "scan_primary": {"seconds": 2.0, "calls": 1},
                                "cache": {"seconds": 0.1, "calls": 1},
                            }
                        }
                    }
                }
            ]
        }
    )

    assert timing_counters(stdout) == {
        "startup_s": 0.2,
        "network_s": 0.8,
        "scanner_s": 3.0,
        "api_s": 0.8,
        "cache_s": 0.1,
    }


def test_machine_output_parsers_fail_closed_on_invalid_json() -> None:
    assert timing_counters("not-json") == {}
    assert origin_of("not-json") == ""
