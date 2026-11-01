# SAGE-IDS paper — LaTeX source

Complete IEEE-format manuscript.

## Files
- `sage_ids.tex` — main manuscript (IEEEtran, journal mode).
- `refs.bib` — bibliography (21 entries, each verified against its primary source).
- `figures/` — result figures (`.pdf` vector, `.png` raster) and dashboard screenshots (`.jpg`).
- `make_figures.py` — regenerates every figure from the committed `reports/*.json` (no hand-entered numbers).
- `sage_ids_paper.md` — a plain-Markdown mirror of the manuscript (reference only).

## Build
Requires a TeX distribution with `IEEEtran` (standard in TeX Live / MiKTeX / Overleaf):

```bash
pdflatex sage_ids
bibtex   sage_ids
pdflatex sage_ids
pdflatex sage_ids
```

On Overleaf: upload this folder, set the main document to `sage_ids.tex`, compiler pdfLaTeX.

## Regenerating figures
From the repository root, with the result JSON present under `reports/`:

```bash
python paper/make_figures.py
```
