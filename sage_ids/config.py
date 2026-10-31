"""Configuration loading. YAML file for non-secret settings, environment for secrets/overrides."""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "configs"


class ApiCfg(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000


class LabCfg(BaseModel):
    active_scenarios_enabled: bool = False
    allowed_target_cidrs: list[str] = ["127.0.0.1/32"]
    attacker_source_cidr: str = "127.0.2.0/24"
    benign_source_cidr: str = "127.0.1.0/24"
    allowed_target_ports: list[int] = []
    login_service_port: int = 18081
    test_app_port: int = 18082
    decoy_ports: list[int] = []
    probe_ports_max: int = 16
    max_requests_per_trial: int = 400
    max_trial_seconds: float = 10.0
    connect_timeout_s: float = 0.5


class MonitoringCfg(BaseModel):
    window_seconds: float = 5.0
    feature_schema_version: str = "lab-v1"


class CoordinatorCfg(BaseModel):
    max_retries: int = 2
    max_adaptation_cycles: int = 3
    running_timeout_s: int = 900


class ExperimentCfg(BaseModel):
    baseline_trials: int = 20
    retest_trials: int = 20
    benign_windows_per_phase: int = 6
    benign_users: int = 8
    base_seed: int = 20261030


class LlmCfg(BaseModel):
    provider: str = "none"
    model: str = ""
    timeout_s: int = 30


class ThreatCfg(BaseModel):
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    attack_stix_url: str = ""
    http_timeout_s: int = 20
    cache_ttl_s: int = 86400
    min_interval_s: float = 6.5
    newly_published_days: int = 30
    max_results_per_query: int = 20


class Settings(BaseModel):
    database_url: str = "sqlite:///data/sage_ids.db"
    artifacts_dir: str = "artifacts"
    reports_dir: str = "reports"
    cache_dir: str = "data/cache"
    api: ApiCfg = Field(default_factory=ApiCfg)
    lab: LabCfg = Field(default_factory=LabCfg)
    monitoring: MonitoringCfg = Field(default_factory=MonitoringCfg)
    coordinator: CoordinatorCfg = Field(default_factory=CoordinatorCfg)
    experiment: ExperimentCfg = Field(default_factory=ExperimentCfg)
    llm: LlmCfg = Field(default_factory=LlmCfg)
    threat_research: ThreatCfg = Field(default_factory=ThreatCfg)

    def path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else PROJECT_ROOT / p

    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()


def _env_bool(name: str) -> bool | None:
    v = os.environ.get(name)
    if v is None:
        return None
    return v.strip().lower() in {"1", "true", "yes", "on"}


def load_settings(path: str | Path | None = None) -> Settings:
    path = Path(path or os.environ.get("SAGE_CONFIG", CONFIG_DIR / "sage.yaml"))
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    s = Settings.model_validate(data)
    if os.environ.get("SAGE_DATABASE_URL"):
        s.database_url = os.environ["SAGE_DATABASE_URL"]
    active = _env_bool("SAGE_ENABLE_ACTIVE_LAB")
    if active is not None:
        s.lab.active_scenarios_enabled = active
    if os.environ.get("SAGE_LLM_PROVIDER"):
        s.llm.provider = os.environ["SAGE_LLM_PROVIDER"]
    if os.environ.get("SAGE_LLM_MODEL"):
        s.llm.model = os.environ["SAGE_LLM_MODEL"]
    return s


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


def load_yaml(name: str) -> Any:
    return yaml.safe_load((CONFIG_DIR / name).read_text(encoding="utf-8"))
