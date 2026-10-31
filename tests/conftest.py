from __future__ import annotations

import pytest

from sage_ids.config import load_settings
from sage_ids.db import Database

TEST_BASE = 28000   # separate port range from the default lab so tests never collide with a running lab


def make_settings(tmp_path, active: bool = False):
    s = load_settings()
    s.database_url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    s.artifacts_dir = str(tmp_path / "artifacts")
    s.cache_dir = str(tmp_path / "cache")
    s.reports_dir = str(tmp_path / "reports")
    s.llm.provider = "none"
    s.lab.active_scenarios_enabled = active
    s.lab.login_service_port, s.lab.test_app_port = TEST_BASE + 81, TEST_BASE + 82
    s.lab.decoy_ports = [TEST_BASE + 100 + i for i in range(6)]
    s.lab.allowed_target_ports = [TEST_BASE + 81, TEST_BASE + 82] + [TEST_BASE + 100 + i for i in range(16)]
    return s


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def db(settings):
    return Database(settings.database_url)
