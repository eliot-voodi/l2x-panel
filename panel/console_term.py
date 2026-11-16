"""Interactive shell console: local PTY + agent→master WebSocket bridge (no SSH)."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import select
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("l2x.console")

IDLE_SEC = 30 * 60
SESSION_TTL_SEC = 15 * 60
SHELL = os.environ.get("L2XPANEL_CONSOLE_SHELL", "/bin/bash")


@dataclass
class ConsoleSession:
    sid: str
    target: str  # "master" or node id
    created: float = field(default_factory=time.time)
    expires: float = 0.0
    browser_ws: Any = None  # starlette WebSocket
    agent_ws: Any = None
    pty_fd: int | None = None
    pty_pid: int | None = None
    reader_stop: threading.Event = field(default_factory=threading.Event)
    last_activity: float = field(default_factory=time.time)
    status: str = "pending"  # pending|ready|closed
    node_id: str = ""
    error: str = ""

    def touch(self) -> None:
        self.last_activity = time.time()

    def expired(self) -> bool:
        now = time.time()
        if self.expires and now > self.expires:
            return True
        return (now - self.last_activity) > IDLE_SEC


_LOCK = threading.RLock()
_SESSIONS: dict[str, ConsoleSession] = {}


def new_session_id() -> str:
    return uuid.uuid4().hex


def get_session(sid: str) -> ConsoleSession | None:
    with _LOCK:
        return _SESSIONS.get(sid)


def register_session(sess: ConsoleSession) -> ConsoleSession:
    with _LOCK:
        _SESSIONS[sess.sid] = sess
    return sess


def drop_session(sid: str) -> None:
    with _LOCK:
        sess = _SESSIONS.pop(sid, None)
    if sess:
        _cleanup_session(sess)


def _cleanup_session(sess: ConsoleSession) -> None:
    sess.status = "closed"
    sess.reader_stop.set()
    if sess.pty_fd is not None:
        try:
            os.close(sess.pty_fd)
        except OSError:
            pass
        sess.pty_fd = None
    if sess.pty_pid:
        try:
            import signal
            os.kill(sess.pty_pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            os.waitpid(sess.pty_pid, os.WNOHANG)
        except OSError:
            pass
        sess.pty_pid = None


def sweep_expired() -> None:
    with _LOCK:
        dead = [s.sid for s in _SESSIONS.values() if s.expired()]
    for sid in dead:
        drop_session(sid)


def encode_data(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return base64.b64encode(raw).decode("ascii")


def decode_data(b64: str) -> bytes:
    try:
        return base64.b64decode(b64.encode("ascii"), validate=False)
    except Exception:
        return b""


def msg_data(raw: bytes | str) -> str:
    return json.dumps({"type": "data", "data": encode_data(raw)}, ensure_ascii=False)


def msg_status(text: str) -> str:
    return json.dumps({"type": "status", "msg": text}, ensure_ascii=False)


def msg_error(text: str) -> str:
    return json.dumps({"type": "error", "msg": text}, ensure_ascii=False)


def msg_ready() -> str:
    return json.dumps({"type": "ready"}, ensure_ascii=False)


def spawn_pty(*, cols: int = 120, rows: int = 32, cwd: str = "/root") -> tuple[int, int]:
    """Fork a login shell attached to a PTY. Returns (pid, master_fd)."""
    import pty
    import fcntl
    import termios

    if not Path(SHELL).exists():
        shell = "/bin/sh"
    else:
        shell = SHELL
    work = cwd if Path(cwd).is_dir() else "/"
    pid, master = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ.setdefault("LANG", "C.UTF-8")
        os.environ.setdefault("HOME", "/root")
        try:
            os.chdir(work)
        except OSError:
            pass
        argv = [shell, "-l"] if "bash" in shell else [shell]
        os.execvp(argv[0], argv)
        os._exit(127)
    # parent
    try:
        _pty_resize(master, cols, rows)
    except OSError:
        pass
    # non-blocking reads
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    return pid, master


def _pty_resize(fd: int, cols: int, rows: int) -> None:
    import fcntl
    import termios

    cols = max(20, min(500, int(cols or 80)))
    rows = max(5, min(200, int(rows or 24)))
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def pty_write(fd: int, data: bytes) -> None:
    if fd is None or not data:
        return
    try:
        os.write(fd, data)
    except OSError:
        pass


def pty_resize(sess: ConsoleSession, cols: int, rows: int) -> None:
    if sess.pty_fd is not None:
        try:
            _pty_resize(sess.pty_fd, cols, rows)
        except OSError:
            pass


def start_local_pty(sess: ConsoleSession, *, cols: int = 120, rows: int = 32) -> None:
    pid, master = spawn_pty(cols=cols, rows=rows)
    sess.pty_pid = pid
    sess.pty_fd = master
    sess.status = "ready"


def start_pty_reader(sess: ConsoleSession, loop: asyncio.AbstractEventLoop, send_cb: Callable[[str], Any]) -> None:
    """Background thread: read PTY → schedule send_cb(json) on the asyncio loop."""

    def _run() -> None:
        fd = sess.pty_fd
        if fd is None:
            return
        while not sess.reader_stop.is_set():
            try:
                r, _, _ = select.select([fd], [], [], 0.2)
            except (OSError, ValueError):
                break
            if not r:
                continue
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                break
            if not chunk:
                break
            sess.touch()
            payload = msg_data(chunk)
            try:
                fut = asyncio.run_coroutine_threadsafe(send_cb(payload), loop)
                fut.result(timeout=10)
            except Exception:
                break
        sess.reader_stop.set()

    threading.Thread(target=_run, name=f"console-pty-{sess.sid[:8]}", daemon=True).start()


async def ws_send_safe(ws: Any, text: str) -> bool:
    if ws is None:
        return False
    try:
        await ws.send_text(text)
        return True
    except Exception:
        return False


async def relay_browser_to_local(sess: ConsoleSession, raw_msg: str) -> None:
    """Handle a JSON control/data message from the browser for a local PTY session."""
    try:
        obj = json.loads(raw_msg)
    except json.JSONDecodeError:
        pty_write(sess.pty_fd or -1, raw_msg.encode("utf-8", "replace"))
        return
    typ = str(obj.get("type") or "")
    sess.touch()
    if typ == "data":
        pty_write(sess.pty_fd or -1, decode_data(str(obj.get("data") or "")))
    elif typ == "resize":
        pty_resize(sess, int(obj.get("cols") or 80), int(obj.get("rows") or 24))
    elif typ == "ping":
        pass


async def relay_peer_text(dst_ws: Any, raw_msg: str) -> bool:
    """Forward a JSON text frame to the other WebSocket peer."""
    return await ws_send_safe(dst_ws, raw_msg)


def console_ws_url(master_base: str, *, session_id: str, token: str = "") -> str:
    """Build wss?/ws? URL for agent dial to master's /agent/console."""
    base = (master_base or "").rstrip("/")
    if base.startswith("https://"):
        ws = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        ws = "ws://" + base[len("http://"):]
    elif base.startswith("wss://") or base.startswith("ws://"):
        ws = base
    else:
        ws = "wss://" + base.lstrip("/")
    q = f"session_id={session_id}"
    if token:
        q += f"&token={token}"
    return f"{ws}/agent/console?{q}"


def agent_dial_and_serve(
    *,
    ws_url: str,
    token: str,
    cols: int = 120,
    rows: int = 32,
    on_status: Callable[[str], None] | None = None,
) -> dict:
    """Agent side: connect to master console WS, spawn local PTY, bridge until closed.

    Blocking; run in a daemon thread from manage/pull handlers.
    """
    try:
        import websockets
        from websockets.sync.client import connect as ws_connect
    except Exception as exc:
        return {"ok": False, "error": f"websockets unavailable: {exc}"}

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with ws_connect(ws_url, additional_headers=headers, open_timeout=20, close_timeout=5) as ws:
            if on_status:
                on_status("connected")
            pid, master = spawn_pty(cols=cols, rows=rows)
            stop = threading.Event()

            def _reader() -> None:
                while not stop.is_set():
                    try:
                        r, _, _ = select.select([master], [], [], 0.2)
                    except (OSError, ValueError):
                        break
                    if not r:
                        continue
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    try:
                        ws.send(msg_data(chunk))
                    except Exception:
                        break
                stop.set()

            threading.Thread(target=_reader, name="agent-console-pty", daemon=True).start()
            try:
                ws.send(msg_ready())
            except Exception as exc:
                stop.set()
                try:
                    os.close(master)
                except OSError:
                    pass
                return {"ok": False, "error": str(exc)}
            try:
                for message in ws:
                    if stop.is_set():
                        break
                    if isinstance(message, bytes):
                        pty_write(master, message)
                        continue
                    try:
                        obj = json.loads(message)
                    except json.JSONDecodeError:
                        pty_write(master, str(message).encode("utf-8", "replace"))
                        continue
                    typ = str(obj.get("type") or "")
                    if typ == "data":
                        pty_write(master, decode_data(str(obj.get("data") or "")))
                    elif typ == "resize":
                        try:
                            _pty_resize(master, int(obj.get("cols") or 80), int(obj.get("rows") or 24))
                        except OSError:
                            pass
                    elif typ == "ping":
                        try:
                            ws.send(json.dumps({"type": "pong"}))
                        except Exception:
                            break
            finally:
                stop.set()
                try:
                    os.close(master)
                except OSError:
                    pass
                try:
                    import signal
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            return {"ok": True, "error": ""}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:400]}


# Track in-flight agent dials so pull/manage do not spawn duplicates
_AGENT_DIALS: set[str] = set()
_AGENT_DIALS_LOCK = threading.Lock()


def start_agent_console_dial(*, ws_url: str, token: str, session_id: str, cols: int = 120, rows: int = 32) -> bool:
    """Fire-and-forget agent dial thread. Returns False if already dialing this session."""
    with _AGENT_DIALS_LOCK:
        if session_id in _AGENT_DIALS:
            return False
        _AGENT_DIALS.add(session_id)

    def _job() -> None:
        try:
            log.info("console dial start sid=%s", session_id[:8])
            agent_dial_and_serve(ws_url=ws_url, token=token, cols=cols, rows=rows)
        finally:
            with _AGENT_DIALS_LOCK:
                _AGENT_DIALS.discard(session_id)
            log.info("console dial end sid=%s", session_id[:8])

    threading.Thread(target=_job, name=f"console-dial-{session_id[:8]}", daemon=True).start()
    return True
