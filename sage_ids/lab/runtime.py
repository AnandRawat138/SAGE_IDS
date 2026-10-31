"""Process-wide laboratory runtime (starts loopback lab services once, applies versioned lab config)."""
from __future__ import annotations

import threading

from ..config import Settings
from .services import LabEnvironment

_lab: LabEnvironment | None = None
_lock = threading.Lock()


def get_lab(settings: Settings) -> LabEnvironment:
    global _lab
    with _lock:
        if _lab is None:
            _lab = LabEnvironment(login_port=settings.lab.login_service_port, app_port=settings.lab.test_app_port,
                                  decoy_ports=list(settings.lab.decoy_ports)).start()
        return _lab


def stop_lab() -> None:
    global _lab
    with _lock:
        if _lab is not None:
            _lab.stop()
            _lab = None
