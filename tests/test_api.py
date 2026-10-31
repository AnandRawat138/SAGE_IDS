import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAGE_DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    monkeypatch.setenv("SAGE_ENABLE_ACTIVE_LAB", "0")
    monkeypatch.delenv("SAGE_VIEWER_KEY", raising=False)
    monkeypatch.setenv("SAGE_OPERATOR_KEY", "test-operator-key")
    import sage_ids.api.main as m
    m = importlib.reload(m)
    with TestClient(m.app) as c:
        yield c


def test_read_only_endpoints(client):
    assert client.get("/about").json()["id"] == "28_CS_4E_04"
    h = client.get("/health").json()
    assert h["audit_chain"]["valid"] and h["lab"]["active_scenarios_enabled"] is False
    assert len(client.get("/scenarios").json()) == 3


def test_privileged_actions_require_operator_key_and_identity(client):
    assert client.post("/research", json={"mode": "fixture"}).status_code == 401
    assert client.post("/research", json={"mode": "fixture"},
                       headers={"X-API-Key": "test-operator-key"}).status_code == 400
    r = client.post("/research", json={"mode": "fixture"},
                    headers={"X-API-Key": "test-operator-key", "X-Operator": "alice"})
    assert r.status_code == 200 and r.json()["by"] == "operator:alice"
    cases = client.get("/cases", params={"state": "scenario_pending_review"}).json()
    assert cases
    hdr = {"X-API-Key": "test-operator-key", "X-Operator": "alice"}
    assert client.post(f"/cases/{cases[0]['id']}/approve", headers=hdr).status_code == 200
    # active lab disabled -> refused, state unchanged
    assert client.post(f"/cases/{cases[0]['id']}/baseline", headers=hdr).status_code == 403
    assert client.get(f"/cases/{cases[0]['id']}").json()["case"]["state"] == "scenario_approved"
    # invalid transition -> 409
    assert client.post(f"/cases/{cases[0]['id']}/accept", headers=hdr).status_code == 409
    rep = client.get(f"/cases/{cases[0]['id']}/report").json()
    assert rep["generated_by"] == "deterministic" and "[OBS]" in rep["content_md"]
