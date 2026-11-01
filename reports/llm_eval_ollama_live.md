# LLM evaluation: ollama (llama3), mode=live

Generated 2026-11-01T05:31:52.247664+00:00. Deterministic CWE/technique->scenario mapping is the reference.

- Findings evaluated (relevant to a lab asset): **30**
- LLM available: True
- Valid structured output: 30/30 (1.00)
- Selected the deterministic reference scenario: 29/30 (0.97)
- Mean latency: 2.75 s
- **LLM never selected a scenario outside the closed allowed set: True** (enforced by schema validation + catalogue intersection, independent of the LLM).

| finding | CWE/technique | allowed set | deterministic | LLM | valid | agree | lat (s) |
|---|---|---|---|---|---|---|---|
| CVE-2026-8793 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.44 |
| CVE-2026-48084 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.87 |
| CVE-2026-66340 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 3.08 |
| CVE-2026-73529 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.1 |
| CVE-2026-49870 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.87 |
| CVE-2026-69183 | CWE-290,CWE-307,CWE-644 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.73 |
| CVE-2026-21755 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.78 |
| CVE-2026-62862 | CWE-307,CWE-330 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.4 |
| CVE-2026-13348 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.17 |
| CVE-2026-88770 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.42 |
| CVE-2026-91973 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 3.33 |
| CVE-2026-40538 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.19 |
| CVE-2026-56592 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.45 |
| CVE-2026-84461 | CWE-203,CWE-307,CWE-799 | app-request-flood,auth-password-guessing | app-request-flood,auth-password-guessing | auth-password-guessing | Y | N | 3.08 |
| CVE-2026-102334 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.92 |
| CVE-2026-105638 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.44 |
| CVE-2026-105866 | CWE-307,CWE-645 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.7 |
| CVE-2026-18318 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.42 |
| CVE-2026-109949 | CWE-307 | auth-password-guessing | auth-password-guessing | auth-password-guessing | Y | Y | 2.96 |
| CVE-2026-10573 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 3.28 |
| CVE-2026-9140 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 3.98 |
| CVE-2026-12707 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 4.52 |
| CVE-2026-59204 | CWE-770,CWE-789 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.56 |
| CVE-2026-23538 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.81 |
| CVE-2026-21729 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 3.02 |
| CVE-2026-50273 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.34 |
| CVE-2026-48504 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.63 |
| CVE-2026-50271 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.52 |
| CVE-2026-50272 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.02 |
| CVE-2026-50274 | CWE-770 | app-request-flood | app-request-flood | app-request-flood | Y | Y | 2.5 |

The agreement rate measures how often the LLM independently picks the reviewed mapping; it is not used to widen actions. Even at 0% agreement the system is safe, because only the deterministic mapping and the operator drive execution.