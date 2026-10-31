"""Threat Research Agent: NVD + MITRE ATT&CK retrieval, provenance, dedup and asset relevance.

Retrieved content is UNTRUSTED DATA: it is sanitised, length-limited, stored, and matched with
deterministic rules. It is never executed and never alters instructions or permissions.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import PROJECT_ROOT, Settings, load_yaml
from ..db import Asset, ThreatFinding, utcnow
from ..lab.scenarios import load_catalogue
from ..llm.provider import choose_scenarios, get_provider
from ..schemas import AssetSpec

FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "threat_intel"
ALLOWED_SOURCE_HOSTS = {"services.nvd.nist.gov", "raw.githubusercontent.com"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INJECTION = re.compile(r"(ignore (all|previous) instructions|system prompt|you are now|run the following|"
                        r"curl\s+http|wget\s+http|powershell|/bin/sh|rm -rf)", re.I)


def sanitize(text: str, limit: int = 4000) -> tuple[str, bool]:
    t = _CTRL.sub(" ", str(text or ""))[:limit]
    return t, bool(_INJECTION.search(t))


class RateLimiter:
    def __init__(self, min_interval_s: float):
        self.min_interval = min_interval_s
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        with self._lock:
            delay = self._last.get(host, 0) + self.min_interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._last[host] = time.monotonic()


@dataclass
class Fetched:
    data: dict
    provenance: dict


class CachedFetcher:
    """HTTPS GET with host allowlist, timeout, rate limit and on-disk TTL cache."""

    def __init__(self, settings: Settings):
        self.cfg = settings.threat_research
        self.cache_dir = settings.path(settings.cache_dir) / "threat_intel"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.limiter = RateLimiter(self.cfg.min_interval_s)

    def get_json(self, url: str, headers: dict | None = None) -> Fetched:
        host = urlparse(url).hostname or ""
        if urlparse(url).scheme != "https" or host not in ALLOWED_SOURCE_HOSTS:
            raise PermissionError(f"source host {host!r} is not an approved threat-intel source")
        key = hashlib.sha256(url.encode()).hexdigest()
        path = self.cache_dir / f"{key}.json"
        if path.exists() and time.time() - path.stat().st_mtime < self.cfg.cache_ttl_s:
            raw = path.read_bytes()
            return Fetched(json.loads(raw), {"url": url, "from_cache": True, "sha256": hashlib.sha256(raw).hexdigest(),
                                             "fetched_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()})
        self.limiter.wait(host)
        r = httpx.get(url, timeout=self.cfg.http_timeout_s, headers=headers or {}, follow_redirects=False)
        r.raise_for_status()
        raw = r.content
        path.write_bytes(raw)
        return Fetched(r.json(), {"url": url, "from_cache": False, "sha256": hashlib.sha256(raw).hexdigest(),
                                  "fetched_at": datetime.now(timezone.utc).isoformat(), "http_status": r.status_code})


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)


def parse_nvd(payload: dict) -> list[dict]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                       if str(d.get("value", "")).startswith("CWE-")})
        cpes = sorted({m.get("criteria", "") for c in cve.get("configurations", []) for n in c.get("nodes", [])
                       for m in n.get("cpeMatch", [])})[:50]
        cvss = None
        for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if cve.get("metrics", {}).get(k):
                cvss = cve["metrics"][k][0].get("cvssData", {}).get("baseScore")
                break
        out.append({"source": "nvd", "source_id": cve.get("id", ""), "title": cve.get("id", ""),
                    "description": desc, "published_at": _parse_dt(cve.get("published")),
                    "last_modified_at": _parse_dt(cve.get("lastModified")), "cwe_ids": cwes, "cpes": cpes,
                    "techniques": [], "cvss": cvss,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"})
    return out


def parse_attack(bundle: dict, tracked: list[str]) -> list[dict]:
    out = []
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or ref.get("external_id") not in tracked:
            continue
        out.append({"source": "mitre_attack", "source_id": ref["external_id"], "title": o.get("name", ""),
                    "description": o.get("description", ""), "published_at": _parse_dt(o.get("created")),
                    "last_modified_at": _parse_dt(o.get("modified")), "cwe_ids": [], "cpes": [],
                    "techniques": [ref["external_id"]], "cvss": None, "url": ref.get("url", "")})
    return out


class ThreatResearchAgent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.maps = load_yaml("mappings.yaml")
        self.catalogue = load_catalogue()
        self.fetcher = CachedFetcher(settings)

    # ------------------------------------------------------------------ inventory
    def sync_assets(self, s: Session) -> list[Asset]:
        out = []
        for d in load_yaml("lab_assets.yaml"):
            spec = AssetSpec.model_validate(d)
            a = s.get(Asset, spec.id) or Asset(id=spec.id)
            a.name, a.host, a.environment = spec.name, spec.host, spec.environment
            a.services = [x.model_dump() for x in spec.services]
            a.products, a.cwe_exposure, a.techniques = spec.products, spec.cwe_exposure, spec.techniques
            s.add(a)
            out.append(a)
        s.flush()
        return out

    # ------------------------------------------------------------------ retrieval
    def retrieve(self, s: Session, mode: str = "fixture") -> list[ThreatFinding]:
        records: list[tuple[dict, dict, str]] = []
        if mode == "fixture":
            for name, parser in (("nvd_fixture.json", parse_nvd), ("attack_fixture.json", None)):
                raw = (FIXTURE_DIR / name).read_bytes()
                payload = json.loads(raw)
                prov = {"url": f"fixture://{name}", "from_cache": False, "sha256": hashlib.sha256(raw).hexdigest(),
                        "fetched_at": datetime.now(timezone.utc).isoformat(), "note": payload.get("_fixture_note", "")}
                recs = parser(payload) if parser else parse_attack(payload, self.maps["tracked_techniques"])
                records += [(r, prov, "synthetic_fixture") for r in recs]
        elif mode == "live":
            cfg = self.settings.threat_research
            for cwe in self.maps["nvd_cwe_queries"]:
                end = datetime.now(timezone.utc)
                start = end - timedelta(days=110)  # NVD limits date ranges to 120 days
                q = urlencode({"cweId": cwe, "resultsPerPage": cfg.max_results_per_query,
                               "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                               "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000")})
                f = self.fetcher.get_json(f"{cfg.nvd_api_url}?{q}")
                records += [(r, f.provenance, "live_internet") for r in parse_nvd(f.data)]
            f = self.fetcher.get_json(cfg.attack_stix_url)
            records += [(r, f.provenance, "live_internet") for r in parse_attack(f.data, self.maps["tracked_techniques"])]
        else:
            raise ValueError("mode must be 'fixture' or 'live'")
        return [self._upsert(s, r, prov, origin) for r, prov, origin in records]

    def _upsert(self, s: Session, r: dict, prov: dict, origin: str) -> ThreatFinding:
        desc, suspicious = sanitize(r["description"])
        title, _ = sanitize(r["title"], 256)
        chash = hashlib.sha256(json.dumps({"d": desc, "c": r["cwe_ids"], "m": str(r["last_modified_at"])},
                                          sort_keys=True).encode()).hexdigest()
        now = utcnow()
        f = s.execute(select(ThreatFinding).where(ThreatFinding.source == r["source"],
                                                  ThreatFinding.source_id == r["source_id"])).scalar_one_or_none()
        if f is None:
            f = ThreatFinding(source=r["source"], source_id=r["source_id"], first_retrieved_at=now,
                              newly_retrieved=True, content_hash=chash)
            s.add(f)
        else:
            f.newly_retrieved = False          # seen before: not "newly retrieved", even if updated
        changed = f.content_hash != chash
        f.content_hash = chash
        f.title, f.description, f.url = title, desc, r["url"][:512]
        f.published_at, f.last_modified_at, f.last_retrieved_at = r["published_at"], r["last_modified_at"], now
        f.cwe_ids, f.cpes, f.cvss = r["cwe_ids"], r["cpes"], r["cvss"]
        techs = set(r["techniques"])
        for c in r["cwe_ids"]:
            techs.update(self.maps["cwe_to_techniques"].get(c, []))
        f.techniques = sorted(techs)
        days = self.settings.threat_research.newly_published_days
        f.newly_published = bool(f.published_at and (now - f.published_at) <= timedelta(days=days))
        f.data_origin = origin
        f.provenance = {**prov, "suspicious_instruction_text": suspicious, "content_changed": changed,
                        "handling": "untrusted data; never executed"}
        s.flush()
        audit.append(s, "agent:threat_research", "finding_retrieved", "finding", f.id,
                     {"source": f.source, "source_id": f.source_id, "content_hash": chash, "origin": origin,
                      "newly_retrieved": f.newly_retrieved, "newly_published": f.newly_published})
        return f

    # ------------------------------------------------------------------ relevance
    def assess_relevance(self, s: Session, f: ThreatFinding) -> dict:
        """Deterministic match against the asset inventory -> candidate scenario requests."""
        matches = []
        for a in s.execute(select(Asset)).scalars():
            reasons = []
            cwe_hit = sorted(set(f.cwe_ids) & set(a.cwe_exposure))
            if cwe_hit:
                reasons.append({"type": "cwe_class", "values": cwe_hit})
            tech_hit = sorted(set(f.techniques) & set(a.techniques))
            if tech_hit:
                reasons.append({"type": "attack_technique", "values": tech_hit})
            prod_hit = [p for p in a.products if any(p in c for c in f.cpes)]
            if prod_hit:
                reasons.append({"type": "cpe_product", "values": prod_hit})
            if not reasons:
                continue
            scen = sorted({sid for t in f.techniques for sid in self.maps["technique_to_scenarios"].get(t, [])
                           if self.catalogue.get(sid) and self.catalogue[sid].target_asset == a.id})
            matches.append({"asset_id": a.id, "reasons": reasons, "scenarios": scen})
        llm_choice = None
        provider = get_provider(self.settings)
        allowed = sorted({sc for m in matches for sc in m["scenarios"]})
        if allowed:
            llm_choice = choose_scenarios(provider, f"{f.title}\n{f.description}", allowed)
        rel = {"relevant": any(m["scenarios"] for m in matches), "matches": matches,
               "method": "deterministic CWE/technique/CPE match against lab inventory",
               "llm_suggestion": llm_choice, "llm_provider": provider.name,
               "caveat": "lab assets are analogues; a CWE/technique match is not a product vulnerability match"}
        f.relevance = rel
        return rel
