"""Approved scenario catalogue and bounded executors.

Executors are fixed functions selected by the `executor` field of a reviewed catalogue entry.
All network activity goes through `Allowlist.guarded_connect`, which validates the resolved
target and port on every connection. Parameters are clamped to the catalogue bounds.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from functools import partial

from ..config import load_yaml
from ..schemas import ScenarioSpec, TrialOutcome
from ..security.allowlist import ActiveLabDisabled, Allowlist, TargetNotAllowed
from .services import LAB_HOST, LAB_TARGET_PASSWORD, LAB_TARGET_USER, http_request

# Fixed, built-in lab wordlist (no external wordlists are ever loaded).
LAB_WORDLIST = [f"{w}{n}" for n in ("", "1", "123", "2023", "2024!") for w in
                ("password", "welcome", "letmein", "admin", "qwerty", "summer", "autumn", "dragon",
                 "monkey", "secret")]


def load_catalogue() -> dict[str, ScenarioSpec]:
    return {d["id"]: ScenarioSpec.model_validate(d) for d in load_yaml("scenarios.yaml")}


def clamp_params(spec: ScenarioSpec, requested: dict | None = None) -> dict:
    requested = requested or {}
    out = {}
    for p in spec.params:
        v = float(requested.get(p.name, p.default))
        v = min(max(v, p.min), p.max)
        out[p.name] = int(round(v)) if p.type == "int" else v
    return out


def sample_params(spec: ScenarioSpec, rng: random.Random) -> dict:
    """Randomise parameters uniformly within reviewed bounds (trial-to-trial variability)."""
    return clamp_params(spec, {p.name: (rng.randint(int(p.min), int(p.max)) if p.type == "int"
                                        else rng.uniform(p.min, p.max)) for p in spec.params})


@dataclass
class ExecContext:
    allowlist: Allowlist
    active_enabled: bool
    target_host: str
    ports: dict[str, int | list[int]]
    connect_timeout: float = 0.5
    source_cidr: str = "127.0.2.0/24"
    cancel: threading.Event = field(default_factory=threading.Event)


def _guard(ctx: ExecContext, spec: ScenarioSpec, port: int) -> None:
    if not ctx.active_enabled:
        raise ActiveLabDisabled("active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1)")
    ctx.allowlist.check_target(ctx.target_host, port)


def _recon(spec: ScenarioSpec, params: dict, src_ip: str, ctx: ExecContext, rng: random.Random,
           out: TrialOutcome) -> None:
    service_ports = {int(ctx.ports["login"]), int(ctx.ports["test_app"])}
    candidates = sorted(p for p in ctx.allowlist.ports if p not in service_ports)
    rng.shuffle(candidates)
    ports = candidates[: min(params["n_ports"], int(spec.limits["max_connections"]))]
    deadline = out.started_at + spec.limits["max_seconds"]
    open_ports = []
    for p in ports:
        if ctx.cancel.is_set():
            out.stop_reason = "cancellation requested"
            break
        if time.time() > deadline:
            out.stop_reason = "time limit reached"
            break
        try:
            s = ctx.allowlist.guarded_connect(ctx.target_host, p, src_ip, timeout=0.25)
            s.close()
            open_ports.append(p)
        except TargetNotAllowed:
            raise
        except OSError:
            pass
        out.requests_sent += 1
        time.sleep(params["inter_probe_ms"] / 1000)
    out.stop_reason = out.stop_reason or "connection budget reached"
    out.effect_occurred = len(open_ports) >= 3
    out.effect_evidence = {"ports_probed": len(ports), "open_ports_found": sorted(open_ports),
                           "criterion": spec.effect_criterion}


def _auth(spec: ScenarioSpec, params: dict, src_ip: str, ctx: ExecContext, rng: random.Random,
          out: TrialOutcome) -> None:
    n = min(params["n_attempts"], int(spec.limits["max_requests"]))
    words = rng.sample(LAB_WORDLIST, k=min(n - 1, len(LAB_WORDLIST)))
    pos = rng.randint(1, n)                     # position of the lab password in the sequence
    guesses = words[: pos - 1] + [LAB_TARGET_PASSWORD]
    port = int(ctx.ports["login"])
    connect = partial(ctx.allowlist.guarded_connect, ctx.target_host, port, src_ip, ctx.connect_timeout)
    deadline = out.started_at + spec.limits["max_seconds"]
    codes: list[int] = []
    for pw in guesses:
        if ctx.cancel.is_set():
            out.stop_reason = "cancellation requested"
            break
        if time.time() > deadline:
            out.stop_reason = "time limit reached"
            break
        codes.append(http_request(connect, "POST", "/login", {"username": LAB_TARGET_USER, "password": pw}))
        out.requests_sent += 1
        if codes[-1] == 200:
            out.stop_reason = "credential found"
            break
        time.sleep(params["delay_ms"] / 1000)
    out.stop_reason = out.stop_reason or "request budget reached"
    out.effect_occurred = 200 in codes
    out.effect_evidence = {"attempts": len(codes), "password_position": pos,
                           "status_counts": {str(c): codes.count(c) for c in sorted(set(codes))},
                           "criterion": spec.effect_criterion}


def _auth_distributed(spec: ScenarioSpec, params: dict, src_ip: str, ctx: ExecContext, rng: random.Random,
                      out: TrialOutcome) -> None:
    """Evasive variant: each guess comes from a different allowlisted source address, so no single
    source crosses a per-source failure threshold. Sources are drawn from the attacker CIDR only."""
    import ipaddress

    n = min(params["n_attempts"], int(spec.limits["max_requests"]))
    words = rng.sample(LAB_WORDLIST, k=min(n - 1, len(LAB_WORDLIST)))
    pos = rng.randint(1, n)
    guesses = words[: pos - 1] + [LAB_TARGET_PASSWORD]
    port = int(ctx.ports["login"])
    net = ipaddress.ip_network(ctx.source_cidr)
    hosts = [str(h) for h in net.hosts()][20:20 + max(n, 2)]
    deadline = out.started_at + spec.limits["max_seconds"]
    codes: list[int] = []
    used_sources: set[str] = set()
    for i, pw in enumerate(guesses):
        if ctx.cancel.is_set() or time.time() > deadline:
            out.stop_reason = "cancellation requested" if ctx.cancel.is_set() else "time limit reached"
            break
        src = hosts[i % len(hosts)]
        used_sources.add(src)
        connect = partial(ctx.allowlist.guarded_connect, ctx.target_host, port, src, ctx.connect_timeout)
        codes.append(http_request(connect, "POST", "/login", {"username": LAB_TARGET_USER, "password": pw}))
        out.requests_sent += 1
        if codes[-1] == 200:
            out.stop_reason = "credential found"
            break
        time.sleep(params["delay_ms"] / 1000)
    out.stop_reason = out.stop_reason or "request budget reached"
    out.effect_occurred = 200 in codes
    out.effect_evidence = {"attempts": len(codes), "password_position": pos, "distinct_sources": len(used_sources),
                           "status_counts": {str(c): codes.count(c) for c in sorted(set(codes))},
                           "criterion": spec.effect_criterion}


def _flood(spec: ScenarioSpec, params: dict, src_ip: str, ctx: ExecContext, rng: random.Random,
           out: TrialOutcome) -> None:
    n = min(params["n_requests"], int(spec.limits["max_requests"]))
    port = int(ctx.ports["test_app"])
    connect = partial(ctx.allowlist.guarded_connect, ctx.target_host, port, src_ip, ctx.connect_timeout)
    deadline = out.started_at + spec.limits["max_seconds"]
    lock = threading.Lock()
    codes: list[int] = []
    budget = iter(range(n))

    def worker():
        while not ctx.cancel.is_set() and time.time() < deadline:
            with lock:
                i = next(budget, None)
            if i is None:
                return
            try:
                c = http_request(connect, "GET", f"/item?id={i}")
            except OSError:
                c = 0
            with lock:
                codes.append(c)

    threads = [threading.Thread(target=worker) for _ in range(params["workers"])]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=spec.limits["max_seconds"] + 2)
    elapsed = max(time.time() - out.started_at, 1e-6)
    out.requests_sent = len(codes)
    out.stop_reason = ("cancellation requested" if ctx.cancel.is_set() else
                       "time limit reached" if len(codes) < n else "request budget reached")
    ok = codes.count(200)
    rate = len(codes) / elapsed
    out.effect_occurred = bool(codes) and ok / len(codes) >= 0.9 and rate >= 50
    out.effect_evidence = {"requests": len(codes), "served_200": ok, "throttled_429": codes.count(429),
                           "errors": codes.count(0), "rate_rps": round(rate, 1),
                           "criterion": spec.effect_criterion}


EXECUTORS = {"recon_probe": _recon, "auth_guessing": _auth, "request_flood": _flood,
             "auth_distributed": _auth_distributed}
EXECUTOR_PORT = {"recon_probe": "decoy", "auth_guessing": "login", "request_flood": "test_app",
                 "auth_distributed": "login"}


def execute_trial(spec: ScenarioSpec, params: dict, src_ip: str, ctx: ExecContext, seed: int,
                  trial_index: int = 0) -> TrialOutcome:
    """Run one bounded trial. Execution success, security effect and detection are separate:
    this function determines only the first two. Detection is evaluated by the monitoring agent."""
    rng = random.Random(seed)
    params = clamp_params(spec, params)
    out = TrialOutcome(scenario_id=spec.id, trial_index=trial_index, seed=seed, src_ip=src_ip,
                       started_at=time.time(), ended_at=0.0, executed=False)
    port_key = EXECUTOR_PORT[spec.executor]
    port = int(ctx.ports[port_key])
    _guard(ctx, spec, port)          # raises before any packet is sent
    ctx.allowlist.check_source(src_ip)
    try:
        EXECUTORS[spec.executor](spec, params, src_ip, ctx, rng, out)
        out.executed = out.requests_sent > 0
        if not out.executed:
            out.execution_error = "no traffic could be generated"
    except (TargetNotAllowed, ActiveLabDisabled):
        raise
    except Exception as e:  # executor failure is recorded, never treated as "asset secure"
        out.executed = False
        out.execution_error = f"{type(e).__name__}: {e}"
        out.effect_occurred = None
    out.ended_at = time.time()
    out.effect_evidence["params"] = params
    return out


def default_context(settings, cancel: threading.Event | None = None) -> ExecContext:  # noqa: ANN001
    lab = settings.lab
    return ExecContext(allowlist=Allowlist.from_settings(lab), active_enabled=lab.active_scenarios_enabled,
                       target_host=LAB_HOST, ports={"login": lab.login_service_port, "test_app": lab.test_app_port,
                                                    "decoy": lab.decoy_ports[0]},
                       connect_timeout=lab.connect_timeout_s, source_cidr=lab.attacker_source_cidr,
                       cancel=cancel or threading.Event())
