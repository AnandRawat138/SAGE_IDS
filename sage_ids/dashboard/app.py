"""SAGE-IDS Streamlit dashboard. Talks to the API only (no direct DB writes).

Run:  streamlit run sage_ids/dashboard/app.py --server.address 127.0.0.1
Env:  SAGE_API_URL (default http://127.0.0.1:8000), SAGE_VIEWER_KEY / SAGE_OPERATOR_KEY, SAGE_OPERATOR_NAME
"""
from __future__ import annotations

import json
import os

import httpx
import pandas as pd
import streamlit as st

API = os.environ.get("SAGE_API_URL", "http://127.0.0.1:8000")
ORIGIN_BADGE = {"live_lab": "🟢 live lab", "replay": "🔵 replay", "synthetic_fixture": "🟠 synthetic fixture",
                "live_internet": "🟢 live internet", "benchmark_dataset": "🟣 benchmark dataset"}

st.set_page_config(page_title="SAGE-IDS", page_icon="🛡️", layout="wide")


def _headers(privileged: bool = False) -> dict:
    h = {}
    key = os.environ.get("SAGE_OPERATOR_KEY") if privileged else (os.environ.get("SAGE_VIEWER_KEY")
                                                                   or os.environ.get("SAGE_OPERATOR_KEY"))
    if key:
        h["X-API-Key"] = key
    if privileged:
        h["X-Operator"] = st.session_state.get("operator", os.environ.get("SAGE_OPERATOR_NAME", ""))
    return h


def get(path: str, **params):
    try:
        r = httpx.get(API + path, params=params, headers=_headers(), timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001
        st.error(f"API error on GET {path}: {e}")
        return None


def post(path: str, body: dict | None = None):
    try:
        r = httpx.post(API + path, json=body or {}, headers=_headers(True), timeout=60)
        if r.status_code >= 400:
            st.error(f"{r.status_code}: {r.json().get('detail', r.text)}")
            return None
        st.success(f"POST {path}: {r.json()}")
        return r.json()
    except Exception as e:  # noqa: BLE001
        st.error(f"API error on POST {path}: {e}")
        return None


def origin_col(df: pd.DataFrame) -> pd.DataFrame:
    if "data_origin" in df.columns:
        df.insert(0, "origin", df["data_origin"].map(lambda o: ORIGIN_BADGE.get(o, o)))
    return df


PAGES = ["Overview", "Network events & alerts", "Threat findings", "Lab assets", "Scenarios & approval queue",
         "Experiment runs & evidence", "Remediation proposals", "Baseline vs candidate", "Versions & rollback",
         "Reports & audit", "About"]
with st.sidebar:
    st.title("🛡️ SAGE-IDS")
    page = st.radio("Screen", PAGES)
    st.text_input("Operator name (for privileged actions)", key="operator",
                  value=os.environ.get("SAGE_OPERATOR_NAME", ""))
    st.caption(f"API: {API}")
    st.caption("Legend: " + " · ".join(ORIGIN_BADGE.values()))

if page == "Overview":
    h = get("/health")
    if h:
        c = st.columns(4)
        c[0].metric("Active version", f"v{h['active_version']}" if h["active_version"] else "none",
                    h.get("active_version_name") or "")
        c[1].metric("Audit chain", "valid" if h["audit_chain"]["valid"] else "BROKEN",
                    f"{h['audit_chain']['entries_checked']} entries")
        c[2].metric("Active lab scenarios", "enabled" if h["lab"]["active_scenarios_enabled"] else "disabled")
        c[3].metric("LLM provider", h["llm_provider"])
        st.subheader("Component health")
        st.json({"database": h["database"], "lab": h["lab"],
                 "privileged_actions_enabled": h["privileged_actions_enabled"]})
        st.subheader("Record counts")
        st.dataframe(pd.DataFrame([h["counts"]]), hide_index=True)
        st.subheader("Cases by state")
        if h["case_states"]:
            st.bar_chart(pd.Series(h["case_states"], name="cases"))
        if h["jobs"]:
            st.subheader("Background jobs (this API process)")
            st.dataframe(pd.DataFrame(h["jobs"]), hide_index=True)

elif page == "Network events & alerts":
    origin = st.selectbox("Data origin filter", ["(all)", *ORIGIN_BADGE])
    a = get("/alerts", limit=500, **({} if origin == "(all)" else {"data_origin": origin}))
    st.subheader("Alerts (alerting predictions; detector = rule / rf / iforest / suricata)")
    if a:
        df = origin_col(pd.DataFrame(a))
        st.dataframe(df[["origin", "id", "ts", "src_ip", "detector", "predicted_label", "confidence", "version_id",
                         "window_id"]], hide_index=True)
        sel = st.number_input("Show evidence for alert id", min_value=0, value=int(df["id"].iloc[0]))
        row = next((x for x in a if x["id"] == sel), None)
        if row:
            st.json(row["evidence"])
    else:
        st.info("No alerts recorded.")
    st.subheader("Recent telemetry events")
    e = get("/events", limit=300)
    if e:
        st.dataframe(origin_col(pd.DataFrame(e)), hide_index=True)

elif page == "Threat findings":
    f = get("/findings")
    if f:
        df = origin_col(pd.DataFrame(f))
        st.dataframe(df[["origin", "id", "source", "source_id", "title", "published_at", "first_retrieved_at",
                         "newly_published", "newly_retrieved", "cwe_ids", "techniques"]], hide_index=True)
        fid = st.selectbox("Details", df["id"].tolist())
        row = next(x for x in f if x["id"] == fid)
        st.markdown(f"**{row['source_id']}** — {row['title']}")
        st.caption("Retrieved text below is untrusted data. It is displayed but never executed.")
        st.code(row["description"], language=None)
        if row["provenance"].get("suspicious_instruction_text"):
            st.warning("Instruction-like content detected in retrieved text; it was flagged and ignored.")
        st.json({"relevance": row["relevance"], "provenance": row["provenance"]})
    if st.button("Retrieve fixture findings (privileged)"):
        post("/research", {"mode": "fixture"})

elif page == "Lab assets":
    a = get("/assets")
    if a:
        st.dataframe(pd.DataFrame(a), hide_index=True)
    st.caption("All assets are loopback laboratory analogues. Matches are by weakness class / technique.")

elif page == "Scenarios & approval queue":
    st.subheader("Approved scenario catalogue")
    sc = get("/scenarios")
    if sc:
        for s in sc:
            with st.expander(f"{s['id']} — {s['name']} ({s['technique']})"):
                st.json(s)
    st.subheader("Approval queue (scenario_pending_review)")
    q = get("/cases", state="scenario_pending_review") or []
    for c in q:
        cols = st.columns([4, 1, 1])
        cols[0].write(f"case {c['id']}: `{c['scenario_id']}` on `{c['asset_id']}` — {c['idempotency_key']}")
        if cols[1].button("Approve", key=f"a{c['id']}"):
            post(f"/cases/{c['id']}/approve")
        if cols[2].button("Deny", key=f"d{c['id']}"):
            post(f"/cases/{c['id']}/deny", {"reason": "denied in dashboard"})
    st.subheader("Approved — ready for baseline test")
    for c in get("/cases", state="scenario_approved") or []:
        cols = st.columns([5, 1])
        cols[0].write(f"case {c['id']}: `{c['scenario_id']}`")
        if cols[1].button("Run baseline", key=f"b{c['id']}"):
            post(f"/cases/{c['id']}/baseline")

elif page == "Experiment runs & evidence":
    cases = get("/cases") or []
    cid = st.selectbox("Case", [None] + [c["id"] for c in cases])
    runs = get("/runs", **({"case_id": cid} if cid else {}), limit=1000)
    if runs:
        df = pd.DataFrame(runs)
        df["detected_by"] = df["detections"].map(
            lambda d: ", ".join(f"v{x['version_id']}:{'yes' if x['detected'] else 'no'}" for x in d))
        df["effect"] = df["effect_occurred"]
        st.caption("Three outcomes are recorded separately: executed · security effect · detected (per version).")
        st.dataframe(origin_col(df)[["origin", "id", "case_id", "phase", "scenario_id", "trial_index", "seed", "src_ip",
                                     "executed", "effect", "detected_by", "stop_reason", "execution_error"]],
                     hide_index=True)
        rid = st.number_input("Run evidence", min_value=0, value=int(df["id"].iloc[0]))
        r = next((x for x in runs if x["id"] == rid), None)
        if r:
            st.json({"effect_evidence": r["effect_evidence"], "lab_config": r["lab_config"], "detections": r["detections"]})
    running = [c for c in cases if c["state"] in ("baseline_test_running", "retest_running")]
    for c in running:
        st.warning(f"case {c['id']} is {c['state']} (last heartbeat {c['heartbeat_at']})")
        if st.button(f"Cancel case {c['id']}"):
            post(f"/cases/{c['id']}/cancel")

elif page == "Remediation proposals":
    cases = [c for c in (get("/cases") or []) if c["state"] in ("remediation_proposed", "acceptance_pending",
                                                                "accepted", "rejected", "candidate_prepared")]
    if not cases:
        st.info("No cases with proposals yet.")
    for c in cases:
        d = get(f"/cases/{c['id']}")
        st.subheader(f"Case {c['id']} — {c['scenario_id']} — state `{c['state']}`")
        for p in d["proposals"]:
            with st.expander(f"[{p['status']}] proposal {p['id']}: {p['title']}"):
                st.write(p["rationale"])
                st.json({"changes": p["changes"], "affected": p["affected_artifacts"], "expected": p["expected_effect"],
                         "validation": p["validation_steps"], "rollback": p["rollback"]})
                if c["state"] == "remediation_proposed" and p["status"] == "proposed":
                    if st.button("Prepare candidate", key=f"p{p['id']}"):
                        post(f"/cases/{c['id']}/prepare", {"proposal_id": p["id"]})
        if c["state"] == "candidate_prepared" and st.button("Run retest", key=f"r{c['id']}"):
            post(f"/cases/{c['id']}/retest")

elif page == "Baseline vs candidate":
    cases = [c for c in (get("/cases") or []) if c.get("baseline_version_id")]
    if not cases:
        st.info("No baseline measurements yet.")
    else:
        cid = st.selectbox("Case", [c["id"] for c in cases])
        d = get(f"/cases/{cid}")
        b = d["case"]["baseline_summary"]
        vid = str(d["case"]["baseline_version_id"])
        t = b["trigger"]
        det = t["detected"].get(vid, [])
        st.markdown(f"**Baseline (v{vid})** — executed {t['n_executed']}/{t['n_trials']}, effect {t['n_effect']}, "
                    f"detected {sum(det)}/{len(det)}; benign alerting windows "
                    f"{b['benign']['alert_windows'].get(vid, 0)}/{b['benign']['n_windows']}")
        st.markdown(f"Frozen criteria hash: `{d['case']['criteria_hash']}`")
        st.json(d["case"]["criteria"])
        for e in d["evaluations"]:
            verdict = "INCONCLUSIVE" if e["inconclusive"] else ("PASSED" if e["passed"] else "FAILED")
            st.subheader(f"Evaluation {e['id']}: candidate v{e['candidate_version_id']} — {verdict}")
            chk = pd.DataFrame(e["results"]["checks"])
            chk["value"] = chk["value"].map(lambda v: json.dumps(v) if isinstance(v, dict) else
                                            (f"{v:.4f}" if isinstance(v, float) else str(v)))
            st.dataframe(chk[["name", "value", "required", "passed"]], hide_index=True)
            rt = e["results"]["retest_summary"]["trigger"]["detected"]
            st.bar_chart(pd.Series({f"v{k}": sum(v) / len(v) if v else 0 for k, v in rt.items()},
                                   name="detection rate on identical retest trials"))
        c = next(x for x in cases if x["id"] == cid)
        if c["state"] == "acceptance_pending":
            col = st.columns(2)
            if col[0].button("Accept candidate"):
                post(f"/cases/{cid}/accept")
            if col[1].button("Reject candidate"):
                post(f"/cases/{cid}/reject", {"reason": "rejected in dashboard"})

elif page == "Versions & rollback":
    v = get("/versions")
    if v:
        df = pd.DataFrame(v)
        st.dataframe(df[["id", "name", "status", "is_active", "parent_id", "bundle_hash", "accepted_by", "accepted_at",
                         "lab_config", "detector_policy", "notes"]], hide_index=True)
        acc = [x["id"] for x in v if x["status"] in ("accepted", "retired") and not x["is_active"]]
        if acc:
            tgt = st.selectbox("Roll back to version", acc)
            if st.button("Roll back (privileged)"):
                post("/versions/rollback", {"to_version_id": tgt})
        with st.expander("Rulesets"):
            for x in v:
                st.write(f"v{x['id']} {x['name']}")
                st.json(x["ruleset"])

elif page == "Reports & audit":
    cases = get("/cases") or []
    if cases:
        cid = st.selectbox("Case report", [c["id"] for c in cases])
        regen = st.checkbox("Regenerate")
        r = get(f"/cases/{cid}/report", regenerate=regen)
        if r:
            st.caption(f"generated_by: {r['generated_by']} · evidence refs: {len(r['evidence_refs'])}")
            st.markdown(r["content_md"])
    st.subheader("Audit log (hash-chained)")
    st.json(get("/audit/verify"))
    a = get("/audit", limit=300)
    if a:
        st.dataframe(pd.DataFrame(a)[["id", "ts", "actor", "action", "entity_type", "entity_id", "hash", "prev_hash"]],
                     hide_index=True)

elif page == "About":
    a = get("/about")
    if a:
        st.header(a["title"])
        st.markdown(f"**Project ID:** {a['id']}  \n**Department:** {a['department']}, Section {a['section']}  \n"
                    f"**Mentor:** {a['mentor']}  \n**Domains:** {', '.join(a['domains'])}")
        st.table(pd.DataFrame(a["team"]))
    st.markdown("Research prototype. Active scenarios run only against allowlisted loopback laboratory services, "
                "are opt-in, and every change requires operator acceptance after evidence-gated validation. "
                "Cryptography appears as a domain classification and in the SHA-256 hash-chained audit ledger and "
                "artifact integrity checks; no custom cryptographic algorithm is implemented.")
