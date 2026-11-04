"""Host metrics from /proc + minute-resolution history for dashboard charts."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_last_cpu: tuple[int, int] | None = None
_last_net: tuple[float, int, int] | None = None
HISTORY_POINTS = 1440


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def _cpu_times() -> tuple[int, int]:
    line = _read("/proc/stat").splitlines()[0] if _read("/proc/stat") else "cpu 0 0 0 0"
    vals = [int(x) for x in line.split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return idle, sum(vals)


def cpu_percent() -> float:
    global _last_cpu
    with _lock:
        idle, total = _cpu_times()
        if _last_cpu is None:
            time.sleep(0.2)
            _last_cpu = (idle, total)
            idle, total = _cpu_times()
        d_idle, d_total = idle - _last_cpu[0], total - _last_cpu[1]
        _last_cpu = (idle, total)
    return round(100.0 * (1 - d_idle / d_total), 1) if d_total > 0 else 0.0


def meminfo() -> dict:
    info: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        try:
            info[k] = int(v.split()[0]) * 1024
        except (IndexError, ValueError):
            pass
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    st, sf = info.get("SwapTotal", 0), info.get("SwapFree", 0)
    return {"total": total, "used": total - avail, "swap_total": st, "swap_used": st - sf}


def disk(path: str = "/") -> dict:
    try:
        s = os.statvfs(path)
    except OSError:
        return {"total": 0, "used": 0}
    total = s.f_blocks * s.f_frsize
    return {"total": total, "used": total - s.f_bfree * s.f_frsize}


def main_iface() -> str:
    for line in _read("/proc/net/route").splitlines()[1:]:
        parts = line.split()
        if len(parts) > 1 and parts[1] == "00000000":
            return parts[0]
    return ""


def net_totals(iface: str | None = None) -> tuple[int, int]:
    iface = iface or main_iface()
    for line in _read("/proc/net/dev").splitlines()[2:]:
        name, _, data = line.partition(":")
        if name.strip() == iface:
            vals = data.split()
            return int(vals[0]), int(vals[8])
    return 0, 0


def net_speed() -> tuple[float, float]:
    global _last_net
    now = time.time()
    rx, tx = net_totals()
    with _lock:
        if _last_net is None:
            _last_net = (now, rx, tx)
            return 0.0, 0.0
        dt = max(now - _last_net[0], 0.001)
        speed = ((rx - _last_net[1]) / dt, (tx - _last_net[2]) / dt)
        _last_net = (now, rx, tx)
    return max(speed[0], 0.0), max(speed[1], 0.0)


def conn_counts() -> dict:
    def count(path: str) -> int:
        return max(len(_read(path).splitlines()) - 1, 0)
    return {"tcp": count("/proc/net/tcp") + count("/proc/net/tcp6"), "udp": count("/proc/net/udp") + count("/proc/net/udp6")}


def snapshot() -> dict:
    load = (_read("/proc/loadavg").split() + ["0", "0", "0"])[:3]
    uptime = float((_read("/proc/uptime").split() or ["0"])[0])
    rx, tx = net_totals()
    rx_s, tx_s = net_speed()
    return {
        "cpu": cpu_percent(),
        "cores": os.cpu_count() or 1,
        "load": [float(x) for x in load],
        "mem": meminfo(),
        "disk": disk("/"),
        "uptime": int(uptime),
        "net": {"iface": main_iface(), "rx": rx, "tx": tx, "rx_s": rx_s, "tx_s": tx_s},
        "conns": conn_counts(),
    }


class History:
    def __init__(self, path: Path):
        self.path = path
        self.points: list[dict] = []
        try:
            self.points = json.loads(path.read_text())[-HISTORY_POINTS:]
        except (OSError, ValueError):
            self.points = []
        self._last_rx_tx: tuple[float, int, int] | None = None

    def sample(self, online: int = 0) -> dict:
        now = time.time()
        rx, tx = net_totals()
        rx_s = tx_s = 0.0
        if self._last_rx_tx:
            dt = max(now - self._last_rx_tx[0], 1)
            rx_s = max((rx - self._last_rx_tx[1]) / dt, 0)
            tx_s = max((tx - self._last_rx_tx[2]) / dt, 0)
        self._last_rx_tx = (now, rx, tx)
        mem = meminfo()
        point = {
            "t": int(now),
            "cpu": cpu_percent(),
            "mem": round(100 * mem["used"] / mem["total"], 1) if mem["total"] else 0,
            "rx": int(rx_s),
            "tx": int(tx_s),
            "online": online,
        }
        self.points.append(point)
        self.points = self.points[-HISTORY_POINTS:]
        try:
            self.path.write_text(json.dumps(self.points))
        except OSError:
            pass
        return point


class OutboundStats:
    """Per-outbound speeds derived from accumulated byte counters {tag: (up, down)}.

    up = bytes sent by the server to the destination (client upload),
    down = bytes received from the destination (client download).
    """

    def __init__(self, path: Path, points: int = HISTORY_POINTS):
        self.path = path
        self.max = points
        self.points: list[dict] = []
        try:
            self.points = json.loads(path.read_text())[-points:]
        except (OSError, ValueError):
            self.points = []
        self.rates: dict[str, dict[str, int]] = {}
        self._fast: tuple[float, dict] | None = None
        self._slow: tuple[float, dict] | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _delta(prev: dict, cur: dict, dt: float) -> dict[str, tuple[float, float]]:
        out = {}
        for tag, (u, d) in cur.items():
            pu, pd = prev.get(tag, (u, d))
            out[tag] = (max(u - pu, 0) / dt, max(d - pd, 0) / dt)
        return out

    def update(self, totals: dict[str, tuple[int, int]]) -> None:
        """Instant speed between two consecutive calls (watchdog cycle)."""
        now = time.time()
        with self._lock:
            if self._fast and now - self._fast[0] > 0:
                r = self._delta(self._fast[1], totals, now - self._fast[0])
                self.rates = {t: {"up": int(u), "down": int(d)} for t, (u, d) in r.items()}
            self._fast = (now, dict(totals))

    def sample(self, totals: dict[str, tuple[int, int]]) -> None:
        """Minute point: average speed per tag since the previous sample."""
        now = time.time()
        with self._lock:
            if self._slow:
                r = self._delta(self._slow[1], totals, max(now - self._slow[0], 1))
                self.points.append({"t": int(now), "d": {t: [int(u), int(d)] for t, (u, d) in r.items() if u or d}})
                self.points = self.points[-self.max:]
                try:
                    self.path.write_text(json.dumps(self.points, separators=(",", ":")))
                except OSError:
                    pass
            self._slow = (now, dict(totals))

    def summary(self, minutes: int = 60) -> dict[str, dict[str, float]]:
        pts = self.points[-minutes:]
        n = max(len(pts), 1)
        out: dict[str, dict[str, float]] = {}
        for p in pts:
            for tag, (u, d) in p["d"].items():
                s = out.setdefault(tag, {"avg_up": 0.0, "avg_down": 0.0, "peak_up": 0, "peak_down": 0})
                s["avg_up"] += u / n
                s["avg_down"] += d / n
                s["peak_up"] = max(s["peak_up"], u)
                s["peak_down"] = max(s["peak_down"], d)
        return out

    def series(self, tag: str | None, n: int) -> list[dict]:
        """tag=None → sum over all outbounds."""
        out = []
        for p in self.points[-n:]:
            if tag:
                u, d = p["d"].get(tag) or (0, 0)
            else:
                u = sum(v[0] for v in p["d"].values())
                d = sum(v[1] for v in p["d"].values())
            out.append({"t": p["t"], "up": u, "down": d})
        return out
