#!/usr/bin/env python3
"""Offline checks for RAM-sized network perf sysctl body."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
import ops  # noqa: E402


def main() -> int:
    low = ops.perf_sysctl_body(mem_mb=1024, reserved={11080})
    mid = ops.perf_sysctl_body(mem_mb=2048, reserved={11080, 8000})
    hi = ops.perf_sysctl_body(mem_mb=4096, reserved=set())
    assert "16777216" in low and "67108864" not in low
    assert "33554432" in mid
    assert "67108864" in hi
    for body in (low, mid, hi):
        for needle in (
            "tcp_congestion_control = bbr",
            "netdev_max_backlog = 16384",
            "somaxconn = 65535",
            "tcp_notsent_lowat = 16384",
            "rmem_default = 1048576",
            "-net.netfilter.nf_conntrack_max",
            "ip_local_port_range = 10240 65535",
        ):
            assert needle in body, needle
    assert "ip_local_reserved_ports = 11080" in low
    print("ok", "low/mid/hi buffer tiers + reserved ports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
