"""Validated data and agent message schemas (Pydantic v2)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

DataOrigin = Literal["live_lab", "replay", "synthetic_fixture", "live_internet", "benchmark_dataset"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- lab assets
class ServiceSpec(Strict):
    name: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "http"] = "tcp"


class AssetSpec(Strict):
    id: str = Field(pattern=r"^[a-z0-9_\-]{2,64}$")
    name: str
    host: str
    environment: Literal["lab"] = "lab"
    services: list[ServiceSpec]
    products: list[str] = []        # lower-case product keywords / CPE vendor:product strings
    cwe_exposure: list[str] = []    # weakness classes the asset is designed to exhibit
    techniques: list[str] = []      # ATT&CK technique IDs applicable to the asset


# --------------------------------------------------------------------------- scenarios
class ParamSpec(Strict):
    name: str
    type: Literal["int", "float"]
    default: float
    min: float
    max: float


class ScenarioSpec(Strict):
    id: str = Field(pattern=r"^[a-z0-9_\-]{2,64}$")
    name: str
    technique: str
    target_asset: str
    executor: Literal["recon_probe", "auth_guessing", "request_flood"]
    description: str
    preconditions: list[str]
    params: list[ParamSpec] = []
    limits: dict[str, float]
    expected_observations: list[str]
    effect_criterion: str
    cleanup: list[str]
    stop_conditions: list[str]
    reviewed_by: str
    reviewed_on: str


class TrialOutcome(Strict):
    """Three outcomes are recorded separately -- never conflated."""
    scenario_id: str
    trial_index: int
    seed: int
    src_ip: str
    started_at: float
    ended_at: float
    executed: bool
    execution_error: str = ""
    effect_occurred: bool | None = None
    effect_evidence: dict[str, Any] = {}
    stop_reason: str = ""
    requests_sent: int = 0


# --------------------------------------------------------------------------- detection rules
RULE_FEATURES = Literal["n_events", "n_distinct_dst_ports", "n_auth_fail", "n_http", "req_rate",
                        "n_http_429", "frac_auth_fail", "n_conn_refused_like"]


class RuleSpec(Strict):
    id: str = Field(pattern=r"^[A-Z0-9_\-]{3,48}$")
    template: Literal["threshold"] = "threshold"
    feature: RULE_FEATURES
    op: Literal[">=", ">"] = ">="
    threshold: float = Field(ge=0)
    severity: Literal["low", "medium", "high"] = "medium"
    label: str
    description: str = ""


# --------------------------------------------------------------------------- remediation
LAB_CONFIG_BOUNDS: dict[str, tuple[int, int]] = {
    "login_lockout_threshold": (3, 50),
    "login_lockout_seconds": (5, 3600),
    "app_rate_limit_rps": (5, 1000),
}


class ChangeRule(Strict):
    kind: Literal["rule"] = "rule"
    action: Literal["add", "replace", "remove"]
    rule: RuleSpec


class ChangeLabConfig(Strict):
    kind: Literal["lab_config"] = "lab_config"
    key: Literal["login_lockout_threshold", "login_lockout_seconds", "app_rate_limit_rps"]
    value: int | None

    @field_validator("value")
    @classmethod
    def _bounds(cls, v, info):  # noqa: ANN001
        if v is None:
            return v
        lo, hi = LAB_CONFIG_BOUNDS[info.data["key"]]
        if not lo <= v <= hi:
            raise ValueError(f"{info.data['key']} must be within [{lo}, {hi}]")
        return v


class ChangeRetrain(Strict):
    kind: Literal["retrain"] = "retrain"
    label_policy: Literal["verified_only"] = "verified_only"
    add_run_ids: list[int]


class ProposalSpec(Strict):
    title: str
    changes: list[ChangeRule | ChangeLabConfig | ChangeRetrain] = Field(min_length=1)
    rationale: str
    affected_artifacts: list[str]
    expected_effect: str
    validation_steps: list[str]
    rollback: str


# --------------------------------------------------------------------------- agent messages
class AgentMessage(Strict):
    sender: Literal["monitoring", "threat_research", "adversarial", "remediation", "explanation",
                    "coordinator", "operator"]
    kind: str
    case_id: int | None = None
    payload: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)


class LlmScenarioChoice(Strict):
    """The only structured output an LLM may return for scenario mapping: IDs from a closed set."""
    scenario_ids: list[str]
    justification: str = Field(max_length=600)


class AcceptanceCriteria(Strict):
    """Frozen after the baseline measurement; hash-committed before any candidate is evaluated.
    `objective` follows the confirmed weakness: "detection" (detection gap) or "prevention"
    (security effect achieved although detection was adequate)."""
    objective: Literal["detection", "prevention"]
    prevention_min_effect_reduction: float
    prevention_fisher_alpha: float
    trigger_min_detection_gain: float
    trigger_mcnemar_alpha: float
    trigger_min_detection_rate_lcb: float
    regression_noninferiority_margin: float
    benign_fpr_max: float
    benign_denied_rate_max: float
    effect_tolerance: float
    effect_must_not_increase: bool
    require_service_health: bool
    max_execution_failure_rate: float
    derived_from: dict[str, Any]
