#!/usr/bin/env python3
"""Offline parse checks for iperf3 JSON helper."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
import ops  # noqa: E402


def main() -> int:
    sample = {
        "end": {
            "sum_sent": {"bits_per_second": 94_500_000, "seconds": 8.0},
            "sum_received": {"bits_per_second": 91_200_000, "seconds": 8.0},
        }
    }
    parsed = ops._iperf3_parse(json.dumps(sample))
    assert parsed["ok"]
    assert parsed["send_mbps"] == 94.5
    assert parsed["recv_mbps"] == 91.2
    bad = ops._iperf3_parse("not-json")
    assert not bad["ok"]
    print("ok iperf3 parse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
