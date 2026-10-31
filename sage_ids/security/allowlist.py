"""Target allowlist enforcement for active laboratory scenarios.

Enforced in code at two layers, independent of any LLM output:
  1. `check_target` validates a scenario's declared target before execution.
  2. `guarded_connect` re-validates the *resolved* address of every socket connection a
     scenario executor opens (defence against DNS tricks / executor bugs).
Hostnames are resolved and every resolved address must be inside an allowed CIDR.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field


class TargetNotAllowed(PermissionError):
    pass


class ActiveLabDisabled(PermissionError):
    pass


@dataclass(frozen=True)
class Allowlist:
    cidrs: tuple[str, ...]
    ports: frozenset[int] = field(default_factory=frozenset)
    source_cidrs: tuple[str, ...] = ()

    @classmethod
    def from_settings(cls, lab) -> "Allowlist":  # noqa: ANN001
        return cls(tuple(lab.allowed_target_cidrs), frozenset(lab.allowed_target_ports),
                   (lab.attacker_source_cidr, lab.benign_source_cidr))

    def _networks(self):
        return [ipaddress.ip_network(c, strict=False) for c in self.cidrs]

    def ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._networks())

    def resolve(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise TargetNotAllowed(f"cannot resolve target {host!r}: {e}") from e
        return sorted({i[4][0] for i in infos})

    def check_target(self, host: str, port: int | None = None) -> str:
        """Return the validated IP or raise TargetNotAllowed."""
        if not host or any(c in host for c in "/\\ ;|&$`"):
            raise TargetNotAllowed(f"malformed target {host!r}")
        ips = self.resolve(host)
        bad = [ip for ip in ips if not self.ip_allowed(ip)]
        if not ips or bad:
            raise TargetNotAllowed(f"target {host!r} resolves to non-allowlisted address(es) {bad or ips}")
        if port is not None and self.ports and int(port) not in self.ports:
            raise TargetNotAllowed(f"port {port} not in laboratory port allowlist")
        return ips[0]

    def check_source(self, src_ip: str) -> None:
        addr = ipaddress.ip_address(src_ip)
        if self.source_cidrs and not any(addr in ipaddress.ip_network(c) for c in self.source_cidrs):
            raise TargetNotAllowed(f"source address {src_ip} outside laboratory source ranges")

    def guarded_connect(self, host: str, port: int, src_ip: str | None = None,
                        timeout: float = 0.5) -> socket.socket:
        ip = self.check_target(host, port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if src_ip:
                self.check_source(src_ip)
                s.bind((src_ip, 0))
            s.connect((ip, int(port)))
            peer = s.getpeername()[0]
            if not self.ip_allowed(peer):  # paranoia: peer must still be allowlisted
                raise TargetNotAllowed(f"connected peer {peer} not allowlisted")
            return s
        except Exception:
            s.close()
            raise
