"""Packet-capture sensor tests. Skipped automatically if scapy/Npcap loopback capture is unavailable."""
import time

import pytest

pytestmark = pytest.mark.packet

scapy = pytest.importorskip("scapy")


def _loopback_ok() -> bool:
    try:
        from scapy.all import AsyncSniffer
        s = AsyncSniffer(iface=r"\Device\NPF_Loopback", filter="tcp", store=False)
        s.start(); time.sleep(0.2); s.stop()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _loopback_ok(), reason="Npcap loopback capture not available")
def test_packet_sensor_captures_flows_and_probe_signature():
    from sage_ids.lab.services import LAB_HOST, LabEnvironment
    from sage_ids.lab.scenarios import ExecContext, execute_trial, load_catalogue
    from sage_ids.security.allowlist import Allowlist
    from sage_ids.telemetry.packet_sensor import PacketFlowSensor

    lab = LabEnvironment(login_port=19181, app_port=19182,
                         decoy_ports=[19200, 19201, 19202, 19203, 19204, 19205]).start()
    ports = {19181, 19182} | set(range(19200, 19206))
    flows = []
    sensor = PacketFlowSensor(ports, flows.append)
    sensor.set_service_map(lambda p: "login" if p == 19181 else "test_app" if p == 19182 else "decoy")
    sensor.start()
    time.sleep(1.0)
    allow = Allowlist(("127.0.0.1/32",), frozenset(ports), ("127.0.2.0/24", "127.0.1.0/24"))
    cat = load_catalogue()
    ctx = ExecContext(allowlist=allow, active_enabled=True, target_host=LAB_HOST,
                      ports={"login": 19181, "test_app": 19182, "decoy": 19200})
    try:
        execute_trial(cat["recon-tcp-probe"], {}, "127.0.2.60", ctx, seed=1)
        execute_trial(cat["auth-password-guessing"], {}, "127.0.2.61", ctx, seed=1)
        time.sleep(6.5)
        sensor.stop()
    finally:
        lab.stop()
    assert len(flows) > 5
    probe = [f for f in flows if f["status"] == "conn"]
    assert len(probe) >= 3                                   # SYN-only probes to closed/decoy ports
    login = [f for f in flows if f["service"] == "login"]
    assert login and login[0]["flow_features"]["SYN Flag Count"] >= 1
    assert login[0]["flow_features"]["schema"] == "flow-v1"
    assert all("Flow Duration" in f["flow_features"] for f in flows)
