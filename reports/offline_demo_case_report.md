# SAGE-IDS case report — case 1

*Generated 2026-10-31T15:12:50Z by the deterministic Explanation Agent. Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*

**Final/current state:** `scenario_approved`

## 1. Source finding
- [OBS] Source `nvd` record `SYNTH-2026-0001` — SYNTH-2026-0001 (data origin: **synthetic_fixture**).
- [OBS] Published: 2026-10-21 04:45:00; first retrieved: 2026-10-31 15:12:50.602144; newly published (≤30 d): True; newly retrieved: True.
- [OBS] Weakness classes: CWE-307; techniques: T1110, T1110.001; CVSS: 7.5.
- [OBS] Provenance: `fixture://nvd_fixture.json` sha256 `d0899b0b3d09569c…`; retrieved content was handled as untrusted data and never executed.

## 2. Applicable laboratory asset
- [INF] Asset `lab-login-service` matched by cwe_class=CWE-307; attack_technique=T1110,T1110.001; candidate scenarios: auth-password-guessing.
- [UNC] lab assets are analogues; a CWE/technique match is not a product vulnerability match.

## 3. Scenario and approval
- [OBS] Scenario `auth-password-guessing` on asset `lab-login-service`.
- [OBS] Approved by `operator:offline-demo` at 2026-10-31 15:12:50.724873 (transition:16).

## 8. Outcome
- [OBS] Last transition: `scenario_pending_review` → `scenario_approved` by `operator:offline-demo` — operator approved reviewed scenario (transition:16, audit hash `3606586d4f964a39…`).

## 9. Uncertainty and limitations
- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately recorded security-effect outcome.
- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; results do not transfer to production networks without re-validation.
- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or behaviours outside the reviewed scenario parameters.
