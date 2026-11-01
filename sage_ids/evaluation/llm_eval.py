"""Measure the configured LLM against the deterministic scenario mapper.

The deterministic CWE/technique -> scenario mapping is treated as ground truth (it is reviewed and
auditable). For every retrieved finding that the deterministic mapper found relevant, we ask the LLM
to pick scenario IDs from the closed allowed set and record agreement, validity and latency. This
quantifies what the optional LLM adds (or risks) without ever letting it widen the action space.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from ..agents.threat_research import ThreatResearchAgent
from ..config import Settings
from ..db import Database, ThreatFinding
from ..llm.provider import DeterministicProvider, choose_scenarios, get_provider


def run_llm_eval(settings: Settings, out_dir: Path, mode: str = "fixture", max_findings: int = 40) -> dict:
    db = Database(settings.database_url)
    agent = ThreatResearchAgent(settings)
    provider = get_provider(settings)
    with db.session() as s:
        agent.sync_assets(s)
        agent.retrieve(s, mode)
        findings = s.execute(select(ThreatFinding)).scalars().all()
        rows = []
        for f in findings:
            rel = agent.assess_relevance(s, f)
            allowed = sorted({sc for m in rel["matches"] for sc in m["scenarios"]})
            if not allowed:
                continue
            det = sorted(allowed)                       # deterministic reference (all mapped scenarios)
            det_primary = det[0]
            t0 = time.time()
            llm = choose_scenarios(provider, f"{f.title}\n{f.description}", allowed)
            dt = time.time() - t0
            valid = llm is not None
            subset = valid and all(x in allowed for x in llm)   # guaranteed by construction; recorded anyway
            agree = valid and det_primary in (llm or [])
            rows.append({"finding": f.source_id, "cwe": f.cwe_ids, "techniques": f.techniques,
                         "allowed": allowed, "deterministic": det, "llm": llm, "valid_json": valid,
                         "within_closed_set": subset, "selected_reference_scenario": agree,
                         "latency_s": round(dt, 2), "data_origin": f.data_origin})
            if len(rows) >= max_findings:
                break
    n = len(rows)
    valid = sum(r["valid_json"] for r in rows)
    agree = sum(r["selected_reference_scenario"] for r in rows)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "provider": provider.name,
           "model": settings.llm.model, "mode": mode, "n_findings_evaluated": n,
           "llm_available": not isinstance(provider, DeterministicProvider),
           "valid_structured_output": valid, "valid_rate": (valid / n) if n else None,
           "selected_reference_scenario": agree, "agreement_rate": (agree / n) if n else None,
           "mean_latency_s": round(sum(r["latency_s"] for r in rows) / n, 2) if n else None,
           "never_exceeded_closed_set": all(r["within_closed_set"] or not r["valid_json"] for r in rows),
           "rows": rows}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"llm_eval_{provider.name}_{mode}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    _md(out, out_dir / f"llm_eval_{provider.name}_{mode}.md")
    return out


def _md(o: dict, path: Path) -> None:
    L = [f"# LLM evaluation: {o['provider']} ({o['model'] or 'n/a'}), mode={o['mode']}", "",
         f"Generated {o['generated_at']}. Deterministic CWE/technique->scenario mapping is the reference.", "",
         f"- Findings evaluated (relevant to a lab asset): **{o['n_findings_evaluated']}**",
         f"- LLM available: {o['llm_available']}",
         f"- Valid structured output: {o['valid_structured_output']}/{o['n_findings_evaluated']}"
         f" ({o['valid_rate']:.2f})" if o["valid_rate"] is not None else "- Valid structured output: n/a",
         f"- Selected the deterministic reference scenario: {o['selected_reference_scenario']}"
         f"/{o['n_findings_evaluated']} ({o['agreement_rate']:.2f})" if o["agreement_rate"] is not None else "",
         f"- Mean latency: {o['mean_latency_s']} s",
         f"- **LLM never selected a scenario outside the closed allowed set: {o['never_exceeded_closed_set']}** "
         "(enforced by schema validation + catalogue intersection, independent of the LLM).", "",
         "| finding | CWE/technique | allowed set | deterministic | LLM | valid | agree | lat (s) |",
         "|---|---|---|---|---|---|---|---|"]
    for r in o["rows"]:
        L.append(f"| {r['finding']} | {','.join(r['cwe'] or r['techniques'])} | {','.join(r['allowed'])} | "
                 f"{','.join(r['deterministic'])} | {','.join(r['llm']) if r['llm'] else '—'} | "
                 f"{'Y' if r['valid_json'] else 'N'} | {'Y' if r['selected_reference_scenario'] else 'N'} | "
                 f"{r['latency_s']} |")
    L += ["", "The agreement rate measures how often the LLM independently picks the reviewed mapping; "
          "it is not used to widen actions. Even at 0% agreement the system is safe, because only the "
          "deterministic mapping and the operator drive execution."]
    path.write_text("\n".join(L), encoding="utf-8")
