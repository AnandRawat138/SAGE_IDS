# Multi-seed experiment (3 realisations)

Generated 2026-11-01T06:44:11.692320+00:00. Seeds: [20261030, 20261101, 20261102]. Timing clean on all seeds: False.

## Case decision stability across seeds

| case | final states across seeds |
|---|---|
| A_password_guessing | accepted, accepted, accepted |
| B_request_flood | accepted, accepted, accepted |
| C_recon | rejected, rejected, rejected |

## Held-out detection rate by scenario across seeds (mean [95% bootstrap CI])

| scenario | initial v1 | accepted version |
|---|---|---|
| app-request-flood | 0.00 [0.00, 0.00] | 1.00 [1.00, 1.00] |
| auth-password-guessing | 0.00 [0.00, 0.00] | 0.90 [0.90, 0.90] |
| recon-tcp-probe | 1.00 [1.00, 1.00] | 1.00 [1.00, 1.00] |

Each seed is an independent run (attacker parameters, trial order, benign traffic and model seeds all vary). Stable decisions and tight intervals indicate the protocol's outcomes are not an artifact of one random draw.