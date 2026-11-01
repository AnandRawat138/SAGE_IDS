"""Real packet-capture sensor for the loopback laboratory (scapy + Npcap).

Unlike the application-level LabSensor, this observes actual TCP packets on the loopback adapter, so
it sees connections that never reach a listener (probes to closed ports -> SYN then RST) and derives
bidirectional flow statistics from packet headers and timing. It requires Npcap with loopback support
(installed here) and runs without administrator rights.

It assembles flows keyed by (src_ip, src_port, dst_ip, dst_port) and emits a `flow-v1` feature record
per flow. `flow-v1` is a deliberately CICIDS2017-compatible subset: the feature names that can be
derived from packet headers alone match the benchmark schema, so a flow-based detector can be compared
against, and share a feature space with, the CICIDS2017 model (see detection/flow_features.py).

The sensor is read-only: it never injects packets.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

LOOPBACK_IFACE = r"\Device\NPF_Loopback"
FLOW_TIMEOUT_S = 5.0          # idle gap that closes a flow
FLOW_SCHEMA = "flow-v1"


@dataclass
class _Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_ts: float
    last_ts: float
    fwd_key: tuple
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_times: list = field(default_factory=list)
    bwd_times: list = field(default_factory=list)
    fwd_lens: list = field(default_factory=list)
    bwd_lens: list = field(default_factory=list)
    flags: dict = field(default_factory=lambda: defaultdict(int))
    syn_only_no_data: bool = True       # stays True if the flow is just SYN(/RST): a probe signature


class PacketFlowSensor:
    """Captures loopback TCP packets and emits completed flows as canonical events with flow-v1 features.

    emit callback receives a dict with the lab-v1 canonical fields (so the same monitoring path works)
    PLUS a nested ``flow_features`` dict with the flow-v1 schema.
    """

    def __init__(self, ports: set[int], emit: Callable[[dict], None], iface: str = LOOPBACK_IFACE,
                 flow_timeout: float = FLOW_TIMEOUT_S):
        self.ports = set(ports)
        self.emit = emit
        self.iface = iface
        self.flow_timeout = flow_timeout
        self._flows: dict[tuple, _Flow] = {}
        self._lock = threading.Lock()
        self._sniffer = None
        self._reaper = None
        self._stop = threading.Event()
        self._service_of: Callable[[int], str] | None = None

    def set_service_map(self, fn: Callable[[int], str]) -> None:
        self._service_of = fn

    # ------------------------------------------------------------------ capture
    def start(self):
        from scapy.all import AsyncSniffer

        portfilter = " or ".join(f"port {p}" for p in sorted(self.ports)) or "tcp"
        self._sniffer = AsyncSniffer(iface=self.iface, filter=f"tcp and ({portfilter})",
                                     prn=self._on_packet, store=False)
        self._sniffer.start()
        self._reaper = threading.Thread(target=self._reap_loop, daemon=True)
        self._reaper.start()
        return self

    def _on_packet(self, pkt) -> None:
        if not pkt.haslayer("TCP") or not pkt.haslayer("IP"):
            return
        ip, tcp = pkt["IP"], pkt["TCP"]
        sport, dport = int(tcp.sport), int(tcp.dport)
        if dport not in self.ports and sport not in self.ports:
            return
        ts = float(pkt.time)
        payload = len(tcp.payload)
        # canonical direction: the side that opened to a lab service port is "forward"
        if dport in self.ports:
            key = (ip.src, sport, ip.dst, dport)
            fwd = True
        else:
            key = (ip.dst, dport, ip.src, sport)
            fwd = False
        flags = int(tcp.flags)
        with self._lock:
            fl = self._flows.get(key)
            if fl is None:
                fl = _Flow(src_ip=key[0], src_port=key[1], dst_ip=key[2], dst_port=key[3],
                           first_ts=ts, last_ts=ts, fwd_key=key)
                self._flows[key] = fl
            fl.last_ts = ts
            if fwd:
                fl.fwd_pkts += 1
                fl.fwd_bytes += payload
                fl.fwd_times.append(ts)
                fl.fwd_lens.append(payload)
            else:
                fl.bwd_pkts += 1
                fl.bwd_bytes += payload
                fl.bwd_times.append(ts)
                fl.bwd_lens.append(payload)
            for name, bit in (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
                              ("ACK", 0x10), ("URG", 0x20)):
                if flags & bit:
                    fl.flags[name] += 1
            if payload > 0:
                fl.syn_only_no_data = False
            closed = bool(flags & 0x01) or bool(flags & 0x04)   # FIN or RST
        if closed:
            # let a final ACK arrive, then flush
            pass

    # ------------------------------------------------------------------ flow completion
    def _reap_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(0.5)
            now = time.time()
            due = []
            with self._lock:
                for key, fl in list(self._flows.items()):
                    if now - fl.last_ts >= self.flow_timeout or fl.flags.get("RST") or \
                            (fl.flags.get("FIN", 0) >= 1 and now - fl.last_ts >= 0.5):
                        due.append(fl)
                        del self._flows[key]
            for fl in due:
                self._emit_flow(fl)

    def flush(self) -> None:
        with self._lock:
            due = list(self._flows.values())
            self._flows.clear()
        for fl in due:
            self._emit_flow(fl)

    def _emit_flow(self, fl: _Flow) -> None:
        feats = flow_features(fl)
        service = self._service_of(fl.dst_port) if self._service_of else ""
        # status mirrors the app sensor vocabulary so both sensors share the lab-v1 path:
        #   'conn' for a probe/refused flow (no payload), else the number of forward data packets.
        status = "conn" if fl.syn_only_no_data else "flow"
        self.emit({
            "ts": fl.first_ts, "src_ip": fl.src_ip, "src_port": fl.src_port, "dst_ip": fl.dst_ip,
            "dst_port": fl.dst_port, "proto": "tcp", "service": service, "status": status,
            "bytes_in": fl.fwd_bytes, "bytes_out": fl.bwd_bytes, "duration": fl.last_ts - fl.first_ts,
            "sensor": "packet", "data_origin": "live_lab", "flow_features": feats,
        })

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self.flush()


def _stats(xs: list[float]) -> tuple[float, float, float, float]:
    if not xs:
        return 0.0, 0.0, 0.0, 0.0
    n = len(xs)
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n if n > 1 else 0.0
    return mean, var ** 0.5, max(xs), min(xs)


def _iat(times: list[float]) -> list[float]:
    t = sorted(times)
    return [t[i + 1] - t[i] for i in range(len(t) - 1)]


def flow_features(fl: _Flow) -> dict:
    """CICIDS2017-compatible flow features derivable from packet headers/timing.
    Field names match the CICIDS2017 column names so the two schemas overlap."""
    dur = max(fl.last_ts - fl.first_ts, 0.0)
    tot_pkts = fl.fwd_pkts + fl.bwd_pkts
    all_iat = _iat(fl.fwd_times + fl.bwd_times)
    f_iat = _iat(fl.fwd_times)
    b_iat = _iat(fl.bwd_times)
    fl_mean, fl_std, fl_max, fl_min = _stats(fl.fwd_lens)
    bl_mean, bl_std, bl_max, bl_min = _stats(fl.bwd_lens)
    iat_mean, iat_std, iat_max, iat_min = _stats(all_iat)
    fiat_mean, fiat_std, fiat_max, fiat_min = _stats(f_iat)
    all_lens = fl.fwd_lens + fl.bwd_lens
    pl_mean, pl_std, pl_max, pl_min = _stats(all_lens)
    dur_s = dur if dur > 0 else 1e-6
    return {
        "Destination Port": fl.dst_port,
        "Flow Duration": dur * 1e6,                       # CICIDS uses microseconds
        "Total Fwd Packets": fl.fwd_pkts,
        "Total Backward Packets": fl.bwd_pkts,
        "Total Length of Fwd Packets": fl.fwd_bytes,
        "Total Length of Bwd Packets": fl.bwd_bytes,
        "Fwd Packet Length Max": fl_max, "Fwd Packet Length Min": fl_min,
        "Fwd Packet Length Mean": fl_mean, "Fwd Packet Length Std": fl_std,
        "Bwd Packet Length Max": bl_max, "Bwd Packet Length Min": bl_min,
        "Bwd Packet Length Mean": bl_mean, "Bwd Packet Length Std": bl_std,
        "Flow Bytes/s": (fl.fwd_bytes + fl.bwd_bytes) / dur_s,
        "Flow Packets/s": tot_pkts / dur_s,
        "Flow IAT Mean": iat_mean * 1e6, "Flow IAT Std": iat_std * 1e6,
        "Flow IAT Max": iat_max * 1e6, "Flow IAT Min": iat_min * 1e6,
        "Fwd IAT Mean": fiat_mean * 1e6, "Fwd IAT Std": fiat_std * 1e6,
        "Fwd IAT Max": fiat_max * 1e6, "Fwd IAT Min": fiat_min * 1e6,
        "Min Packet Length": pl_min, "Max Packet Length": pl_max,
        "Packet Length Mean": pl_mean, "Packet Length Std": pl_std,
        "FIN Flag Count": fl.flags.get("FIN", 0), "SYN Flag Count": fl.flags.get("SYN", 0),
        "RST Flag Count": fl.flags.get("RST", 0), "PSH Flag Count": fl.flags.get("PSH", 0),
        "ACK Flag Count": fl.flags.get("ACK", 0), "URG Flag Count": fl.flags.get("URG", 0),
        "Down/Up Ratio": (fl.bwd_pkts / fl.fwd_pkts) if fl.fwd_pkts else 0.0,
        "Average Packet Size": pl_mean,
        "schema": FLOW_SCHEMA,
    }
