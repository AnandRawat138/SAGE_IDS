"""Run the laboratory services standalone (e.g. as the `lab-targets` container of the Docker lab).

    SAGE_LAB_BIND=0.0.0.0 python -m sage_ids.lab.serve

Binding beyond loopback is only appropriate on an isolated network with no route to other systems
(see docker/docker-compose.yml, network `labnet` with `internal: true`).
"""
from __future__ import annotations

import os
import time

from ..config import load_settings
from .services import LabEnvironment


def main() -> None:
    s = load_settings()
    lab = LabEnvironment(login_port=s.lab.login_service_port, app_port=s.lab.test_app_port,
                         decoy_ports=list(s.lab.decoy_ports), bind_host=os.environ.get("SAGE_LAB_BIND", "127.0.0.1"))
    lab.start()
    print(f"lab services on {lab.bind_host}: login={lab.login_port} app={lab.app_port} decoys={lab.decoy_ports}",
          flush=True)
    try:
        while True:
            time.sleep(3600)
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
