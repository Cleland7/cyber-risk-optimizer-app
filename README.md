# Budget-Constrained Cyber Risk Optimizer

> Most tools tell you what's wrong. This one tells you the cheapest way to make the most risk go away, and checks that it worked.

Wazuh telemetry becomes a quantified risk range, then the best set of fixes for a given budget, then a before/after attack check. Loop: **Measure, Quantify, Prioritize, Fix, Verify.**

## Run it in 5 minutes (replay mode, no lab needed)
```bash
python3 -m croptimizer --budget 50000            # command-line report
python3 -m croptimizer --budget 80000 --db snapshots.db   # also store before/after snapshots
pip install -r requirements.txt && streamlit run app.py   # budget slider UI
docker compose up                                # same UI in a container
python3 -m pytest -q tests
```
The sample data is fictional (Pinnacle Bank Ghana lab). Regenerate it with `python3 sample-data/make_sample.py`.

## What is inside
| Path | Purpose |
|---|---|
| `croptimizer/scoring.py` | Risk Prioritization Engine, CVSS-only comparison |
| `croptimizer/fair.py` | FAIR-lite PERT Monte Carlo (seeded) |
| `croptimizer/optimizer.py` | Overlap-aware exact optimizer + sensitivity check |
| `croptimizer/verify.py` | Expected-vs-observed attack verification |
| `croptimizer/store.py` | `risk_snapshots` with Measured/Declared source column |
| `app.py` | Streamlit budget slider |
| `docs/METHODOLOGY.md` | Formulas, assumptions, validation, limitations |
| `lab/README.md` | Live-mode lab and Atomic Red Team guidance |

## Honesty rules
- Every metric is labelled **Measured** (Wazuh/public feeds) or **Declared** (manual input).
- Dollar figures are ranges (90% interval), never single numbers.
- "Technical control coverage" only; this tool does not claim framework compliance.
- Loss sizes (SLE) are anchored to IBM 2026, Verizon 2026 DBIR, Sophos 2026 and FBI IC3 2025 where marked Cited; frequencies, fix costs and fix effectiveness are Declared. Secondary-sourced figures must be checked against the originals before publishing.

## Status
Replay mode complete and tested. Alert evidence now drives scenario frequency. Live Wazuh collector, NVD/EPSS enrichment cache, and the recorded demo are the next milestones (see `docs/METHODOLOGY.md` section 9). Lab-only warning: see `SECURITY.md`.

License: MIT.
