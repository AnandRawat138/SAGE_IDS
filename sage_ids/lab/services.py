"""Isolated laboratory services bound to loopback only.

* LoginService  -- dummy HTTP login endpoint with a deliberately weak lab account.
* TestApp       -- local HTTP test application with an optional per-source rate limit.
* DecoyListeners -- TCP listeners that accept and close (stand-ins for exposed services).

Every service reports connection/request metadata to a `LabSensor` (application-instrumented
sensor). This is NOT packet capture: connections that never reach a listener (e.g. probes to
closed ports) are invisible to it. Zeek/Suricata adapters cover packet-level telemetry.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

LAB_HOST = "127.0.0.1"
# Dummy, lab-only credentials. They protect nothing and exist so that the password-guessing
# scenario has an observable security effect inside the laboratory.
LAB_TARGET_USER = "labuser"
LAB_TARGET_PASSWORD = "Winter2024!"
BENIGN_PASSWORD = "correct-horse-lab"


class LabSensor:
    """Thread-safe collector of canonical flow events."""

    def __init__(self):
        self._events: list[dict] = []
        self._lock = threading.Lock()

    def emit(self, **ev: Any) -> None:
        ev.setdefault("ts", time.time())
        ev.setdefault("proto", "tcp")
        ev.setdefault("sensor", "lab_sensor")
        ev.setdefault("data_origin", "live_lab")
        with self._lock:
            self._events.append(ev)

    def drain(self) -> list[dict]:
        with self._lock:
            out, self._events = self._events, []
        return out


@dataclass
class LabConfigState:
    login_lockout_threshold: int | None = None
    login_lockout_seconds: int = 60
    app_rate_limit_rps: int | None = None

    def apply(self, cfg: dict) -> None:
        for k in ("login_lockout_threshold", "login_lockout_seconds", "app_rate_limit_rps"):
            if k in cfg:
                setattr(self, k, cfg[k])

    def as_dict(self) -> dict:
        return {"login_lockout_threshold": self.login_lockout_threshold,
                "login_lockout_seconds": self.login_lockout_seconds,
                "app_rate_limit_rps": self.app_rate_limit_rps}


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, request, client_address):  # clients may reset; never spam stderr
        pass


def _make_handler(lab: "LabEnvironment", service: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):  # silence stderr
            pass

        def _reply(self, code: int, body: dict, t0: float, n_in: int) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            src_ip, src_port = self.client_address[:2]
            lab.sensor.emit(ts=t0, src_ip=src_ip, src_port=src_port, dst_ip=lab.bind_host,
                            dst_port=self.server.server_address[1], service=service,
                            status=str(code), bytes_in=n_in, bytes_out=len(data),
                            duration=time.time() - t0)

        def do_GET(self):  # noqa: N802
            t0 = time.time()
            if self.path.startswith("/health"):
                return self._reply(200, {"ok": True}, t0, 0)
            if service == "test_app" and self.path.startswith("/item"):
                if not lab.allow_request(self.client_address[0]):
                    return self._reply(429, {"error": "rate limited"}, t0, 0)
                return self._reply(200, {"item": self.path.split("=")[-1], "payload": "x" * 256}, t0, 0)
            return self._reply(404, {"error": "not found"}, t0, 0)

        def do_POST(self):  # noqa: N802
            t0 = time.time()
            n = min(int(self.headers.get("Content-Length", 0) or 0), 4096)
            raw = self.rfile.read(n) if n else b""
            if service != "login" or not self.path.startswith("/login"):
                return self._reply(404, {"error": "not found"}, t0, n)
            try:
                body = json.loads(raw or b"{}")
                user, pw = str(body.get("username", "")), str(body.get("password", ""))
            except (ValueError, AttributeError):
                return self._reply(400, {"error": "bad request"}, t0, n)
            code = lab.check_login(user, pw)
            return self._reply(code, {"result": {200: "ok", 401: "invalid", 423: "locked"}[code]}, t0, n)

    return Handler


@dataclass
class LabEnvironment:
    login_port: int
    app_port: int
    decoy_ports: list[int]
    sensor: LabSensor = field(default_factory=LabSensor)
    config: LabConfigState = field(default_factory=LabConfigState)
    bind_host: str = LAB_HOST

    def __post_init__(self):
        self._servers: list[Any] = []
        self._threads: list[threading.Thread] = []
        self._decoy_socks: list[socket.socket] = []
        self._stop = threading.Event()
        self._fail: dict[str, deque] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._rate: dict[str, deque] = defaultdict(deque)
        self._state_lock = threading.Lock()
        self.accounts = {LAB_TARGET_USER: LAB_TARGET_PASSWORD}
        self.accounts.update({f"user{i:02d}": BENIGN_PASSWORD for i in range(1, 33)})

    # -------------------------------------------------------------- service logic
    def check_login(self, user: str, pw: str) -> int:
        now = time.time()
        with self._state_lock:
            thr = self.config.login_lockout_threshold
            if thr is not None and self._locked_until.get(user, 0) > now:
                return 423
            if self.accounts.get(user) == pw:
                self._fail[user].clear()
                return 200
            if thr is not None:
                q = self._fail[user]
                q.append(now)
                while q and q[0] < now - self.config.login_lockout_seconds:
                    q.popleft()
                if len(q) >= thr:
                    self._locked_until[user] = now + self.config.login_lockout_seconds
            return 401

    def allow_request(self, src_ip: str) -> bool:
        rps = self.config.app_rate_limit_rps
        if rps is None:
            return True
        now = time.time()
        with self._state_lock:
            q = self._rate[src_ip]
            while q and q[0] < now - 1.0:
                q.popleft()
            if len(q) >= rps:
                return False
            q.append(now)
            return True

    def reset_state(self) -> None:
        """Cleanup between trials: clear lockouts, failure counters and rate windows."""
        with self._state_lock:
            self._fail.clear()
            self._locked_until.clear()
            self._rate.clear()

    # -------------------------------------------------------------- lifecycle
    def start(self) -> "LabEnvironment":
        for port, svc in ((self.login_port, "login"), (self.app_port, "test_app")):
            srv = _QuietServer((self.bind_host, port), _make_handler(self, svc))
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
            t.start()
            self._servers.append(srv)
            self._threads.append(t)
        for port in self.decoy_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.bind_host, port))
            s.listen(64)
            s.settimeout(0.2)
            self._decoy_socks.append(s)
            t = threading.Thread(target=self._decoy_loop, args=(s, port), daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def _decoy_loop(self, s: socket.socket, port: int) -> None:
        while not self._stop.is_set():
            try:
                c, addr = s.accept()
            except (socket.timeout, OSError):
                continue
            t0 = time.time()
            c.close()
            self.sensor.emit(ts=t0, src_ip=addr[0], src_port=addr[1], dst_ip=self.bind_host, dst_port=port,
                             service="decoy", status="conn", bytes_in=0, bytes_out=0, duration=0.0)

    def stop(self) -> None:
        self._stop.set()
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        for s in self._decoy_socks:
            s.close()

    def health(self) -> dict[str, bool]:
        out = {}
        for name, port in (("login", self.login_port), ("test_app", self.app_port)):
            try:
                with socket.create_connection((self.bind_host if self.bind_host != "0.0.0.0" else LAB_HOST, port),
                                              timeout=1.0) as s:
                    s.sendall(b"GET /health HTTP/1.0\r\nHost: lab\r\n\r\n")
                    buf = b""
                    while chunk := s.recv(1024):
                        buf += chunk
                    out[name] = buf.startswith(b"HTTP/1.0 200")
            except OSError:
                out[name] = False
        return out


def http_request(connect: Callable[[], socket.socket], method: str, path: str,
                 body: dict | None = None, timeout: float = 2.0) -> int:
    """Minimal HTTP/1.0 client over an already-validated socket factory. Returns status code."""
    s = connect()
    try:
        s.settimeout(timeout)
        data = json.dumps(body).encode() if body is not None else b""
        req = (f"{method} {path} HTTP/1.0\r\nHost: lab\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(data)}\r\n\r\n").encode() + data
        s.sendall(req)
        buf = b""
        while b"\r\n" not in buf:
            chunk = s.recv(256)
            if not chunk:
                break
            buf += chunk
        while s.recv(4096):
            pass
        return int(buf.split(b" ", 2)[1]) if buf.startswith(b"HTTP/") else 0
    finally:
        s.close()
