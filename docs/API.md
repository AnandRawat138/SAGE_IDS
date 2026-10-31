# REST API

The server binds to `127.0.0.1:8000` by default. Interactive OpenAPI docs are served at `/docs` once it is running.

| Header | Meaning |
|---|---|
| `X-API-Key` | `SAGE_VIEWER_KEY` for read endpoints (open on loopback if unset). `SAGE_OPERATOR_KEY` for privileged endpoints. If `SAGE_OPERATOR_KEY` is unset, privileged endpoints return **403**. |
| `X-Operator` | Required on privileged endpoints: a simple operator name, recorded as `operator:<name>` in transitions and the audit log. |

## Read-only (viewer)

| Method & path | Returns |
|---|---|
| `GET /health` | active version, lab status, LLM provider, audit-chain verification, record counts, case states, recent jobs |
| `GET /about` | project details |
| `GET /states` | all coordinator states |
| `GET /findings` | threat findings with provenance, relevance, `newly_published` / `newly_retrieved` |
| `GET /assets` | laboratory asset inventory |
| `GET /scenarios` | approved scenario catalogue |
| `GET /cases?state=` | cases |
| `GET /cases/{id}` | case, transitions (with evidence), proposals, evaluations |
| `GET /cases/{id}/report?regenerate=` | deterministic evidence report (Markdown) |
| `GET /runs?case_id=&phase=&limit=` | experiment runs with per-version detection outcomes |
| `GET /alerts?data_origin=&limit=` | alerting predictions (rule / rf / iforest / suricata) with evidence |
| `GET /events?limit=` / `GET /windows?limit=` | telemetry events / lab-v1 feature windows |
| `GET /versions` | detector versions (candidate / accepted / rejected / retired / ablation) |
| `GET /audit?limit=` / `GET /audit/verify` | audit ledger / hash-chain verification |
| `GET /jobs/{id}` | background job status |

## Privileged (operator)

| Method & path | Body | Effect |
|---|---|---|
| `POST /research` | `{"mode": "fixture" \| "live"}` | retrieve findings, create cases |
| `POST /bootstrap` | – | calibration + v1 (needs active lab) — background job |
| `POST /cases/{id}/approve` | – | `scenario_pending_review → scenario_approved` |
| `POST /cases/{id}/deny` | `{"reason"}` | `→ rejected` |
| `POST /cases/{id}/baseline` | – | background baseline test (403 if active lab disabled) |
| `POST /cases/{id}/prepare` | `{"proposal_id"}` | create candidate version |
| `POST /cases/{id}/retest` | – | background retest + frozen-criteria evaluation |
| `POST /cases/{id}/accept` | – | activate candidate (409 unless `acceptance_pending` and evaluation passed) |
| `POST /cases/{id}/reject` | `{"reason"}` | reject |
| `POST /cases/{id}/cancel` | – | cancel (running phases stop between trials) |
| `POST /versions/rollback` | `{"to_version_id": null \| int}` | re-activate a previously accepted version |

Errors: `401` bad key, `400` missing operator identity, `403` disabled capability, `404` unknown, `409` invalid state transition or version operation.
