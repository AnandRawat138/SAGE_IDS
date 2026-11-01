# LLM evaluation: ollama (llama3), mode=fixture

Generated 2026-11-01T05:28:40.788717+00:00. Deterministic CWE/technique->scenario mapping is the reference.

- Findings evaluated (relevant to a lab asset): **7**
- LLM available: True
- Valid structured output: 6/7 (0.86)
- Selected the deterministic reference scenario: 6/7 (0.86)
- Mean latency: 2.48 s
- **LLM never selected a scenario outside the closed allowed set: True** (enforced by schema validation + catalogue intersection, independent of the LLM).

| finding | CWE/technique | allowed set | deterministic | LLM | valid | agree | lat (s) |
|---|---|---|---|---|---|---|---|
| SYNTH-2026-0001 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.39 |
| SYNTH-2026-0002 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 3.01 |
| SYNTH-2025-0107 | CWE-1391 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 1.65 |
| SYNTH-2026-0004 | CWE-307 | auth-password-guessing | auth-password-guessing | — | N | N | 1.55 |
| T1046 | T1046 | recon-tcp-probe | recon-tcp-probe | recon-tcp-probe | Y | Y | 3.12 |
| T1110.001 | T1110.001 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.1 |
| T1499.002 | T1499.002 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 3.54 |

The agreement rate measures how often the LLM independently picks the reviewed mapping; it is not used to widen actions. Even at 0% agreement the system is safe, because only the deterministic mapping and the operator drive execution.