"""Explanation Agent: evidence-grounded case reports.

The deterministic report is always produced and is authoritative. Statements are tagged
[OBS] observation (directly recorded), [INF] inference (derived by a stated rule) or
[UNC] uncertainty/limitation, and cite record IDs (run:, transition:, evaluation:, audit:).
An optional LLM summary is appended only when a provider is configured, and is labelled.
"""
from __future__ import annotations

import statistics

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import (Case, DetectorVersion, Evaluation, RemediationProposal, Report, ThreatFinding, Transition,
                  utcnow)
from ..evaluation.stats import fmt_rate, wilson
from ..llm.provider import DeterministicProvider, get_provider, wrap_untrusted


def _lat(xs: list) -> str:
    xs = [x for x in xs if x is not None]
    if not xs:
        return "n/a (no detections)"
    return f"median {statistics.median(xs):.2f} s (min {min(xs):.2f}, max {max(xs):.2f}, n={len(xs)})"


class ExplanationAgent:
    def __init__(self, settings: Settings):
        self.settings = settings

    def case_report(self, s: Session, case_id: int) -> Report:
        case = s.get(Case, case_id)
        f = s.get(ThreatFinding, case.finding_id) if case.finding_id else None
        trs = s.execute(select(Transition).where(Transition.case_id == case_id).order_by(Transition.id)).scalars().all()
        props = s.execute(select(RemediationProposal).where(RemediationProposal.case_id == case_id)
                          .order_by(RemediationProposal.id)).scalars().all()
        evals = s.execute(select(Evaluation).where(Evaluation.case_id == case_id).order_by(Evaluation.id)).scalars().all()
        refs: list[str] = [f"transition:{t.id}" for t in trs]
        L: list[str] = [f"# SAGE-IDS case report — case {case.id}", "",
                        f"*Generated {utcnow().isoformat(timespec='seconds')}Z by the deterministic Explanation Agent. "
                        "Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*", "",
                        f"**Final/current state:** `{case.state}`", ""]
        # 1 finding
        L.append("## 1. Source finding")
        if f:
            L += [f"- [OBS] Source `{f.source}` record `{f.source_id}` — {f.title} (data origin: **{f.data_origin}**).",
                  f"- [OBS] Published: {f.published_at or 'unknown'}; first retrieved: {f.first_retrieved_at}; "
                  f"newly published (≤{self.settings.threat_research.newly_published_days} d): {f.newly_published}; "
                  f"newly retrieved: {f.newly_retrieved}.",
                  f"- [OBS] Weakness classes: {', '.join(f.cwe_ids) or '—'}; techniques: {', '.join(f.techniques) or '—'}; "
                  f"CVSS: {f.cvss if f.cvss is not None else '—'}.",
                  f"- [OBS] Provenance: `{f.provenance.get('url')}` sha256 `{str(f.provenance.get('sha256'))[:16]}…`; "
                  f"retrieved content was handled as untrusted data and never executed.",
                  ]
            if f.provenance.get("suspicious_instruction_text"):
                L.append("- [OBS] The retrieved text contains instruction-like content; it was flagged and ignored. "
                         "It had no effect on scenarios, targets or permissions.")
        L.append("")
        # 2 relevance
        L.append("## 2. Applicable laboratory asset")
        rel = (f.relevance if f else {}) or {}
        for m in rel.get("matches", []):
            why = "; ".join(f"{r['type']}={','.join(r['values'])}" for r in m["reasons"])
            L.append(f"- [INF] Asset `{m['asset_id']}` matched by {why}; candidate scenarios: {', '.join(m['scenarios']) or '—'}.")
        if rel.get("caveat"):
            L.append(f"- [UNC] {rel['caveat']}.")
        if not rel.get("matches"):
            L.append("- [INF] No asset in the laboratory inventory matched this finding.")
        L.append("")
        # 3 scenario
        L.append("## 3. Scenario and approval")
        appr = next((t for t in trs if t.to_state in ("scenario_approved",) ), None)
        L.append(f"- [OBS] Scenario `{case.scenario_id}` on asset `{case.asset_id}`.")
        if appr:
            L.append(f"- [OBS] Approved by `{appr.actor}` at {appr.ts} (transition:{appr.id}).")
        L.append("")
        # 4 baseline
        b = case.baseline_summary
        if b:
            vid = str(case.baseline_version_id)
            t = b["trigger"]
            det = t["detected"].get(vid, [])
            refs += [f"run:{r}" for r in t["run_ids"]]
            L += ["## 4. Baseline test (accepted version v%s)" % vid,
                  f"- [OBS] Trials: {t['n_trials']}; executed: {t['n_executed']} (runs {t['run_ids'][0]}–{t['run_ids'][-1]})."
                  if t["run_ids"] else "- [OBS] No trials recorded.",
                  f"- [OBS] Security effect achieved: {fmt_rate(t['n_effect'], t['n_executed'])}.",
                  f"- [OBS] IDS detection: {fmt_rate(sum(det), len(det))}; latency {_lat(t['latency_s'].get(vid, []))}.",
                  f"- [OBS] Benign windows: {b['benign']['n_windows']}, alerting: {b['benign']['alert_windows'].get(vid, 0)}; "
                  f"benign requests denied: {b['benign']['denied']}/{b['benign']['requests']}.",
                  f"- [OBS] Previously passed scenarios (regression set): {', '.join(b.get('regression_set', [])) or 'none'}.",
                  f"- [OBS] Service health after phase: {b['health']}.", ""]
            wk = next((tr for tr in trs if tr.from_state == "baseline_test_completed"), None)
            if wk:
                L.append(f"- [INF] Decision `{wk.to_state}`: {wk.reason} — evidence {wk.evidence} (transition:{wk.id}).")
                if wk.to_state == "weakness_not_confirmed":
                    L.append("- [UNC] Failure to reproduce an effect under bounded lab conditions is not evidence that the asset is secure.")
            L.append("")
        # 5 criteria
        if case.criteria:
            c = case.criteria
            L += ["## 5. Frozen acceptance criteria",
                  f"- [OBS] Derived from the measured baseline and hash-committed before any candidate was evaluated: "
                  f"`{case.criteria_hash}`.",
                  f"- [OBS] trigger gain ≥ {c['trigger_min_detection_gain']}, McNemar p < {c['trigger_mcnemar_alpha']}, "
                  f"detection Wilson LCB ≥ {c['trigger_min_detection_rate_lcb']}; regression margin "
                  f"{c['regression_noninferiority_margin']}; benign FPR ≤ {c['benign_fpr_max']:.4f}; benign denied ≤ "
                  f"{c['benign_denied_rate_max']:.4f}; effect may not increase (+{c['effect_tolerance']}); service health required.",
                  ""]
        # 6 proposals
        if props:
            L.append("## 6. Remediation proposals")
            for p in props:
                L.append(f"- [OBS] Proposal {p.id} — **{p.title}** — status `{p.status}`"
                         + (f", candidate version {p.candidate_version_id}" if p.candidate_version_id else "") + ".")
                L.append(f"  - Rationale [INF]: {p.rationale}")
                L.append(f"  - Rollback: {p.rollback}")
            L.append("")
        # 7 retests
        for e in evals:
            refs.append(f"evaluation:{e.id}")
            r = e.results
            rs = r.get("retest_summary", {})
            cv = str(e.candidate_version_id)
            bv = str(e.baseline_version_id)
            t = rs.get("trigger", {})
            L += [f"## 7.{e.id} Retest of candidate v{cv} (evaluation:{e.id}) — "
                  + ("**INCONCLUSIVE**" if e.inconclusive else "**PASSED**" if e.passed else "**FAILED**"),
                  f"- [OBS] Fresh-seed trials: {t.get('n_trials')}, executed {t.get('n_executed')}; effect "
                  f"{fmt_rate(t.get('n_effect', 0), t.get('n_executed', 0))}.",
                  f"- [OBS] Detection on identical retest telemetry — baseline v{bv}: "
                  f"{fmt_rate(sum(t.get('detected', {}).get(bv, [])), len(t.get('detected', {}).get(bv, [])))}; "
                  f"candidate v{cv}: {fmt_rate(sum(t.get('detected', {}).get(cv, [])), len(t.get('detected', {}).get(cv, [])))}; "
                  f"candidate latency {_lat(t.get('latency_s', {}).get(cv, []))}.", "",
                  "| criterion | measured | required | result |", "|---|---|---|---|"]
            for ch in r["checks"]:
                val = ch["value"]
                val = f"{val:.4f}" if isinstance(val, float) else str(val)
                L.append(f"| {ch['name']} | {val} | {ch['required']} | {'pass' if ch['passed'] else 'FAIL'} |")
            L.append("")
        # 8 outcome
        L.append("## 8. Outcome")
        last = trs[-1] if trs else None
        if last:
            L.append(f"- [OBS] Last transition: `{last.from_state}` → `{last.to_state}` by `{last.actor}` — {last.reason} "
                     f"(transition:{last.id}, audit hash `{last.audit_hash[:16]}…`).")
        if case.state == "accepted":
            v = s.get(DetectorVersion, case.candidate_version_id)
            L.append(f"- [OBS] Version v{v.id} (`{v.bundle_hash[:16]}…`) activated by `{v.accepted_by}`; the previous "
                     f"accepted version remains available for rollback.")
            L.append("- [INF] The accepted change improved detection of the triggering scenario under the tested lab "
                     "conditions without violating the frozen regression, benign-traffic and health criteria.")
        L += ["", "## 9. Uncertainty and limitations",
              "- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately "
              "recorded security-effect outcome.",
              "- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; "
              "results do not transfer to production networks without re-validation.",
              "- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or "
              "behaviours outside the reviewed scenario parameters.", ""]
        content = "\n".join(L)
        generated_by = "deterministic"
        provider = get_provider(self.settings)
        if not isinstance(provider, DeterministicProvider):
            try:
                summary = provider.complete("Summarise this evidence report in 5 sentences for a security operator. "
                                            "Do not add facts.\n" + wrap_untrusted(content, 12000), max_tokens=500)
                content += ("\n\n## Appendix: LLM-generated summary (provider: %s)\n> Generated text; the deterministic "
                            "report above is authoritative.\n\n%s\n" % (provider.name, summary.strip()))
                generated_by = f"deterministic+{provider.name}"
            except Exception as e:  # noqa: BLE001
                content += f"\n\n*(LLM summary unavailable: {type(e).__name__}; deterministic report only.)*\n"
        rep = Report(case_id=case_id, kind="case", content_md=content, generated_by=generated_by, evidence_refs=refs)
        s.add(rep)
        s.flush()
        return rep
