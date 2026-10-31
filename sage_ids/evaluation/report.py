"""Render the experiment report (Markdown) strictly from the recorded results dictionary."""
from __future__ import annotations

from pathlib import Path

from .stats import wilson


def _f(x, nd=3) -> str:
    if x is None:
        return "—"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def _rate(k: int, n: int) -> str:
    if not n:
        return "n/a"
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} = {p:.2f} [{lo:.2f}, {hi:.2f}]"


def _summary(r: dict) -> list[str]:
    """Computed summary (no hand-written numbers)."""
    ft = r["final_test"]
    active = next((v for v in r["versions"] if v["active"]), None)
    v1 = ft["v1_id"]
    L = ["## Summary (computed from the records below)", ""]
    for name, c in r["cases"].items():
        L.append(f"- {name}: `{c['final_state']}` after {len(c['tried'])} candidate(s)"
                 + (f"; accepted v{c['accepted_version']}" if c["accepted_version"] else ""))
    rejected = sum(1 for e in r["evaluations"] if not e["passed"])
    L.append(f"- Candidate evaluations: {len(r['evaluations'])} total, {rejected} rejected by the frozen criteria.")
    if active and str(active["id"]) in ft["versions"]:
        a, b = ft["versions"][str(active["id"])], ft["versions"][v1]
        L += ["", f"Held-out final test, initial v{v1} vs final active v{active['id']} (identical traffic):", "",
              "| metric | v%s | v%s |" % (v1, active["id"]), "|---|---|---|"]
        for k in ("precision", "recall", "f1", "fpr"):
            L.append(f"| window {k} | {_f(b['window_binary'][k])} | {_f(a['window_binary'][k])} |")
        for sid in sorted(a["per_scenario"]):
            pa, pb = a["per_scenario"][sid], b["per_scenario"][sid]
            L.append(f"| {sid} detection | {pb['detected']}/{pb['n']} | {pa['detected']}/{pa['n']} |")
    abl = {v["name"]: v for v in ft["versions"].values() if v["status"] == "ablation"}
    if "ABL-self-training" in abl and "ABL-verified-retrain-all" in abl:
        st, vr = abl["ABL-self-training"], abl["ABL-verified-retrain-all"]
        L += ["", "Label-provenance ablation (same base model, same observations):", "",
              "| scenario | self-training (pseudo-labels) | verified-label retraining |", "|---|---|---|"]
        for sid in sorted(st["per_scenario"]):
            L.append(f"| {sid} | {st['per_scenario'][sid]['detected']}/{st['per_scenario'][sid]['n']} | "
                     f"{vr['per_scenario'][sid]['detected']}/{vr['per_scenario'][sid]['n']} |")
    L.append("")
    return L


def write_report(r: dict, path: Path) -> None:
    L: list[str] = ["# SAGE-IDS — Experiment Report", "",
                    f"Generated {r['generated_at']} from actual execution recorded in `{Path(r['database']).name}`. "
                    "Every number below is read from that run's records; nothing is estimated or hand-entered.", ""]
    ti = r.get("timing_integrity")
    if ti is not None:
        L += ["**Timing integrity: clean** (no stalled runs or gaps suggesting a host suspend)." if ti["clean"] else
              f"**Timing integrity WARNING:** possible host suspend or stall — long runs {ti['long_runs']}, gaps "
              f"{ti['gaps']}. Measurements of the affected phases should not be relied on.", ""]
    L += _summary(r)
    L += ["## 1. Scope and environment", ""]
    for k, v in {**r["scope"], **r["environment"]}.items():
        L.append(f"- **{k}**: {v}")
    L += ["", "## 2. Execution log", ""] + [f"- {x}" for x in r["log"]]

    L += ["", "## 3. Closed-loop case outcomes", "", "| case | finding | scenario | final state | adaptation cycles |",
          "|---|---|---|---|---|"]
    for c in r["case_states"]:
        L.append(f"| {c['id']} | `{c['finding']}` | {c['scenario'] or '—'} | `{c['state']}` | {c['cycles']} |")
    L.append("")
    for name, c in r["cases"].items():
        L.append(f"**{name}** (case {c['case_id']}, {c['wall_s']} s): final `{c['final_state']}`"
                 + (f", accepted version v{c['accepted_version']}" if c["accepted_version"] else ""))
        for t in c["tried"]:
            L.append(f"  - proposal {t['proposal_id']} *{t['title']}* → `{t['result_state']}`")
    L += ["", "## 4. Baseline measurements (accepted version at the time; Wilson 95% CI)", "",
          "| case | scenario | executed | security effect | detected | benign windows alerting | regression set |",
          "|---|---|---|---|---|---|---|"]
    for cid, b in r["baselines"].items():
        t = b["trigger"]
        vid = next(iter(t["detected"]), None)
        det = t["detected"].get(vid, [])
        bw = b["benign"]
        L.append(f"| {cid} | {t['scenario_id']} | {t['n_executed']}/{t['n_trials']} | {_rate(t['n_effect'], t['n_executed'])} | "
                 f"{_rate(sum(det), len(det))} | {_rate(bw['alert_windows'].get(vid, 0), bw['n_windows'])} | "
                 f"{', '.join(b.get('regression_set', [])) or '—'} |")

    L += ["", "## 5. Candidate evaluations against frozen criteria (fresh-seed retests)", ""]
    for e in r["evaluations"]:
        verdict = "INCONCLUSIVE" if e["inconclusive"] else ("PASSED" if e["passed"] else "FAILED")
        L += [f"**evaluation {e['id']}** — case {e['case_id']}, candidate v{e['candidate']}: **{verdict}**", "",
              "| criterion | measured | required | result |", "|---|---|---|---|"]
        for ch in e["checks"]:
            L.append(f"| {ch['name']} | {_f(ch['value'], 4) if not isinstance(ch['value'], dict) else ch['value']} | "
                     f"{ch['required']} | {'pass' if ch['passed'] else '**FAIL**'} |")
        L.append("")

    L += ["## 6. Versions", "", "| id | name | status | active | rules | lab config | label counts |", "|---|---|---|---|---|---|---|"]
    for v in r["versions"]:
        L.append(f"| {v['id']} | {v['name']} | {v['status']} | {'yes' if v['active'] else ''} | {'; '.join(v['rules'])} | "
                 f"{ {k: x for k, x in v['lab_config'].items() if x is not None} } | {v['label_counts']} |")
    L += ["", f"Rollback demonstration: {r['rollback']}", ""]

    ft = r["final_test"]
    L += ["## 7. Held-out final test (fresh seeds; identical traffic for every version)", "",
          f"Events: {ft['n_events']}; labelled windows: {ft['n_windows_labelled']} {ft['label_counts']}. "
          "All versions are evaluated under the v1 lab configuration so that detectors see identical traffic; "
          "preventive effects of hardening are reported in Section 5.", "",
          "### 7.1 Window-level binary detection (attack vs benign)", "",
          "| version | precision | recall | F1 | FPR [95% CI] | TP/FP/TN/FN | ms/window |", "|---|---|---|---|---|---|---|"]
    for vid, v in ft["versions"].items():
        w = v["window_binary"]
        L.append(f"| v{vid} {v['name']} ({v['status']}) | {_f(w['precision'])} | {_f(w['recall'])} | {_f(w['f1'])} | "
                 f"{_f(w['fpr'], 4)} [{_f(w['fpr_ci95'][0], 3)}, {_f(w['fpr_ci95'][1], 3)}] | "
                 f"{'/'.join(map(str, w['tp_fp_tn_fn']))} | {_f(v['cost']['ms_per_window'], 2)} |")
    scen = sorted({s for v in ft["versions"].values() for s in v["per_scenario"]})
    L += ["", "### 7.2 Per-trial detection rate by scenario (Wilson 95% CI) and median detection latency", "",
          "| version | " + " | ".join(scen) + " |", "|---|" + "---|" * len(scen)]
    for vid, v in ft["versions"].items():
        cells = []
        for sid in scen:
            p = v["per_scenario"][sid]
            cells.append(f"{p['detected']}/{p['n']} = {_f(p['rate'], 2)} [{_f(p['ci95'][0], 2)}, {_f(p['ci95'][1], 2)}]; "
                         f"lat {_f(p['latency_median_s'], 2)} s")
        L.append(f"| v{vid} {v['name']} | " + " | ".join(cells) + " |")
    L += ["", "### 7.3 Paired exact McNemar tests vs v1 on identical final-test trials (two-sided)", "",
          "| scenario | version | candidate-only detections | v1-only detections | p-value |", "|---|---|---|---|---|"]
    for sid, d in ft["mcnemar_vs_v1"].items():
        for vid, m in d.items():
            L.append(f"| {sid} | v{vid} {ft['versions'][vid]['name']} | {m['b_candidate_only']} | {m['c_baseline_only']} | "
                     f"{m['p_value']:.2e} |")
    L += ["", "### 7.4 Per-class metrics and confusion matrices", ""]
    for vid, v in ft["versions"].items():
        if v["status"] not in ("accepted", "retired") and vid != ft["v1_id"]:
            continue
        L += [f"**v{vid} {v['name']}**", "", "| class | precision | recall | F1 | support |", "|---|---|---|---|---|"]
        for c, m in v["per_class"].items():
            L.append(f"| {c} | {_f(m['precision'])} | {_f(m['recall'])} | {_f(m['f1'])} | {m['support']} |")
        cm = v["confusion_matrix"]
        L += ["", "| true \\ predicted | " + " | ".join(cm["labels"]) + " |", "|---|" + "---|" * len(cm["labels"])]
        for lbl, row in zip(cm["labels"], cm["matrix"]):
            L.append(f"| {lbl} | " + " | ".join(map(str, row)) + " |")
        L.append("")

    L += ["## 8. Safety verification", "", "| attempted target | decision | detail |", "|---|---|---|"]
    for s in r["safety_checks"]:
        L.append(f"| `{s['target']}` | {s['decision']} | {s['detail'].replace('|', '/')} |")
    a, t = r["audit_chain"], r["audit_tamper_test"]
    L += ["", f"- Audit hash chain: valid={a['valid']}, entries checked={a['entries_checked']}.",
          f"- Tamper test on a copy: modified entry {t['modified_entry']} → valid={t['valid']}, broken at id "
          f"{t.get('broken_at_id')}.", "",
          "## 9. Resource use", ""]
    for k, v in r["resources"].items():
        L.append(f"- {k}: {_f(v, 1)}")
    L += [f"- RSS during final test: {_f(ft['rss_mb'], 1)} MB", "",
          "## 10. Threats to validity and limitations", "",
          "- **Laboratory realism.** Targets are loopback services; telemetry comes from an application-level sensor, "
          "not packet capture; benign traffic is synthetic. Absolute rates do not transfer to production networks.",
          "- **Scenario scope.** Three reviewed, bounded scenarios with parameters randomised inside reviewed bounds. "
          "No adaptive or evasive attacker is modelled; a candidate that passes here may fail against one.",
          "- **Sample size.** Trials per phase are finite; use the reported confidence intervals, not point estimates.",
          "- **Behaviourally undetectable trials.** Password guessing that succeeds within the first ~2 attempts is "
          "indistinguishable from benign typos; such trials cap achievable detection for that scenario.",
          "- **Single realisation.** One run with one base seed; repeat with other `base_seed` values for run-to-run variance.",
          "- **Scripted operator.** Approvals and the order in which candidates were tried were fixed in advance by the "
          "experiment script; they are not independent human judgements.",
          "- **Threat-intel fixtures.** Unless run with live intelligence, findings are synthetic fixtures (SYNTH- IDs) "
          "used to exercise the mapping logic; matches are weakness-class/technique matches, not product matches.",
          "- **Detection ≠ prevention.** Alerts show detection only; prevention is measured by the separately recorded "
          "security-effect outcome.",
          "- **Benchmark separation.** CICIDS2017 results (if run) come from a separate model and schema and are not "
          "comparable to laboratory numbers.", ""]
    path.write_text("\n".join(L), encoding="utf-8")
