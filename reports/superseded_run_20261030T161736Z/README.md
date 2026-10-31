# Superseded run (kept for transparency)

This is the first full measured run (`data/experiment_20261030T161736Z.db`), left unedited. It
exposed two protocol flaws, documented as rows 9–10 of `docs/DEVELOPMENT_NOTES.md`:

1. preventive weaknesses were evaluated against unsatisfiable detection-gain criteria;
2. candidates within a case were retested on different seeds.

The current report in `reports/` comes from a fresh run after those fixes.
