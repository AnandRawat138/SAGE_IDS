# Fixtures

All files in this directory are **synthetic demo fixtures** created for this project. They are
labelled `synthetic_fixture` wherever they are ingested and are never presented as real data.

| path | content |
|---|---|
| `threat_intel/nvd_fixture.json` | NVD CVE API 2.0-shaped records with `SYNTH-` IDs (not real CVEs). One record contains instruction-like text to test untrusted-content handling. |
| `threat_intel/attack_fixture.json` | Minimal STIX bundle shaped like MITRE ATT&CK with short project-written paraphrases. |
| `zeek/conn.log`, `zeek/http.log` | Hand-generated Zeek TSV logs: 3 benign hosts, one password-guessing host, one port-sweeping host. |
| `suricata/eve.json` | Hand-generated Suricata EVE alerts (fixture SID 9000001) plus one non-alert event. |

Real data paths: `sage-ids research --mode live` (NVD + ATT&CK), Zeek/Suricata logs from the
Docker lab (`docker/`), and the CICIDS2017 / UNSW-NB15 downloads described in `docs/SETUP.md`.
