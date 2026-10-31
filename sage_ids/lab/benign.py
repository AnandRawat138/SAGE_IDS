"""Synthetic benign traffic generator for the laboratory (clearly labelled synthetic).

Simulated users with distinct loopback source addresses log in (with occasional typos), browse
the test application at human-like or "power user" rates, and occasionally call the application's
health endpoint. Decoy listeners receive no benign traffic (deception-lab convention). Its realism
is limited and documented.
"""
from __future__ import annotations

import random
import threading
import time
from functools import partial

from ..security.allowlist import Allowlist
from .services import BENIGN_PASSWORD, LAB_HOST, http_request


def _user_session(user_idx: int, src_ip: str, allow: Allowlist, ports: dict, rng: random.Random,
                  power_user: bool, stats: dict, lock: threading.Lock) -> None:
    login = partial(allow.guarded_connect, LAB_HOST, ports["login"], src_ip, 1.0)
    app = partial(allow.guarded_connect, LAB_HOST, ports["test_app"], src_ip, 1.0)
    codes = []
    user = f"user{user_idx:02d}"
    time.sleep(rng.uniform(0, 0.4))
    # login, possibly with typos (realistic source of benign authentication failures)
    n_typos = 0 if rng.random() > 0.2 else (1 if rng.random() < 0.8 else 2)
    for _ in range(n_typos):
        codes.append(http_request(login, "POST", "/login", {"username": user, "password": "wrong-" + str(rng.random())}))
        time.sleep(rng.uniform(0.2, 0.6))
    codes.append(http_request(login, "POST", "/login", {"username": user, "password": BENIGN_PASSWORD}))
    n_pages = rng.randint(12, 30) if power_user else rng.randint(2, 10)
    for _ in range(n_pages):
        codes.append(http_request(app, "GET", f"/item?id={rng.randint(1, 500)}"))
        time.sleep(rng.uniform(0.02, 0.08) if power_user else rng.uniform(0.1, 0.4))
    if rng.random() < 0.15:  # client-side health check of the application (decoys get no legitimate traffic)
        codes.append(http_request(app, "GET", "/health"))
    with lock:
        stats["requests"] += len(codes)
        stats["denied"] += sum(c in (423, 429) for c in codes)
        stats["errors"] += sum(c == 0 for c in codes)


def run_benign_round(allow: Allowlist, ports: dict, n_users: int, seed: int,
                     source_prefix: str = "127.0.1.") -> dict:
    """One round = every simulated user runs one short session concurrently."""
    rng = random.Random(seed)
    stats = {"requests": 0, "denied": 0, "errors": 0}
    lock = threading.Lock()
    threads = []
    t0 = time.time()
    sources = []
    for i in range(1, n_users + 1):
        src = f"{source_prefix}{10 + i}"
        sources.append(src)
        threads.append(threading.Thread(target=_user_session, args=(
            i, src, allow, ports, random.Random(rng.random()), i <= max(1, n_users // 4), stats, lock)))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return {"started_at": t0, "ended_at": time.time(), "sources": sources, **stats}
