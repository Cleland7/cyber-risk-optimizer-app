# Methodology

Version 0.1 (assumptions version 2026.11-a). All sample figures are fictional placeholders for a lab called Pinnacle Bank Ghana.

## 1. Purpose and loop
Measure, quantify, prioritize, fix, verify. The system converts Wazuh telemetry into a dollar-denominated exposure range, recommends the best set of fixes for a budget, and checks the result against a re-run attack.

## 2. Measured vs Declared
| Measured (from Wazuh or public feeds) | Declared (manual input, versioned) |
|---|---|
| Alerts, rule levels, MITRE technique/tactic tags | Asset criticality (1-5) |
| Vulnerability findings | SLE and ARO ranges per scenario |
| CVSS (NVD), EPSS (FIRST), KEV (CISA) enrichment | Fix costs and fix-to-scenario effectiveness |
| Atomic Red Team outcomes (blocked/detected/missed) | Risk owners, treatment decisions |

Every stored metric has a `source` column constrained to `Measured` or `Declared`.

## 3. Risk Prioritization Engine
`priority = Criticality x CVSS x EPSS x ThreatMultiplier`, range 0 to 100.
ThreatMultiplier is 1.0 plus the number of high-severity (level >= 10) alerts on the host divided by 5, capped at 2.0.
Enterprise score = `100 x (1 - exp(-sum(priority) / K))`, K = 120. This is a weighted scoring model, not machine learning. K is a calibration constant chosen so a lab with several exploitable, alerting crown-jewel hosts lands in the HIGH band; it is not empirically derived and should be tuned and disclosed.
Headline score = `0.6 x vulnerability score + 0.4 x exposure component`, where exposure component = `100 x (1 - exp(-mean annual exposure / 1,500,000))`. The blend stops the score reading 0 when every known vulnerability is closed but dollar exposure from other scenarios (phishing, insider misuse, unknowns) remains. The 0.6/0.4 weights and the 1,500,000 reference are Declared calibration choices in `model.json`.
Bands: LOW below 33, MODERATE 33 to 65, HIGH 66 and above.

## 4. Financial exposure (FAIR-lite)
`ALE = SLE x ARO` per scenario. SLE and ARO are PERT distributions (minimum, most likely, maximum). Monte Carlo: 10,000 iterations, fixed seed (42), assumptions in `sample-data/model.json`. Scenario samples are paired by iteration so before/after totals are comparable. Output is a mean and 5th to 95th percentile (90% interval).
### 4.0 Sources behind the loss figures (SLE)
| Scenario | SLE (min / most likely / max) | Basis |
|---|---|---|
| Customer data breach | 4.32M / 4.99M / 6.0M | IBM 2026: global average 4.99M; under-200-day breaches 4.32M; AI-enabled breaches about 6M (S1, S2) |
| Ransomware | 0.14M / 1.84M / 2.47M | Verizon 2026 median ransom paid 139,875 as the low end; Sophos 2026 mean recovery 1.7M plus Verizon median ransom as the mode; Sophos median payment 769,000 plus recovery for the high end (S3-S5) |
| Phishing / BEC | 20,699 / 123,000 / 500,000 | FBI IC3 2025: all-complaint average 20,699 as low; BEC losses of 3.05B over 24,768 complaints gives about 123,000 as the mode (derived); high end is Declared (S6, S7) |
| Credential theft | 20,000 / 80,000 / 300,000 | Declared; no direct benchmark found |
| Service outage | 10,000 / 40,000 / 150,000 | Declared; no benchmark sourced |

Every source is listed with its link and a verification status in `sample-data/model.json` and on the live page. Figures reached through secondary articles are marked and must be checked against the original IBM, Verizon, Sophos and FBI reports before publication.
Benchmarks describe average organisations in those studies, not any single bank. `sle_scale` in `model.json` (default 1.0) rescales all SLEs to a smaller or larger organisation and is a Declared assumption.
**Not sourced:** attack frequencies (ARO) are Declared for every scenario because no public source gives a per-organisation annual rate; fix costs and fix effectiveness are Declared.

### 4.1 Alert evidence drives frequency
Each scenario lists the MITRE techniques/tactics that count as evidence for it (`signals` in `model.json`). Alerts at or above level 7 that match are counted, and the declared ARO range is scaled by `1 + min(1, alerts / 10)`, so observed activity can at most double the declared frequency. The level cut-off and the divisor of 10 are Declared assumptions. Exposure therefore rises when attacks are observed and the after-fix alert counts are reported beside the modelled drop as evidence. One alert can count toward more than one scenario (for example a macro-execution alert supports both ransomware and phishing); this is deliberate and noted as a limitation.

### 4.2 Ghana layer (cedi view and regulatory impact)
- **Currency:** all modelling is in US dollars. The cedi view multiplies by an editable rate (default about GHS 11.66 per USD, the Bank of Ghana interbank rate on 5 November 2026, source S14). The rate moves, so it is a Declared input with a note.
- **Obligations:** `ghana_obligations` in `model.json` lists, for each duty, the regulator, the law and section, the deadline, the reported penalty, when it applies, a source id and a verification status. Scenarios carry `triggers` that link them to duties. Duties covered: Data Protection Act 2012 (Act 843) breach notification to the Data Protection Commission and affected people, as soon as reasonably practicable; Cybersecurity Act 2020 (Act 1038) 24-hour incident reporting for critical information infrastructure owners; the CII Directive 72-hour vulnerability disclosure; and the Bank of Ghana Cyber and Information Security Directive 2026.
- **What is not verified:** the Bank of Ghana directive's incident-reporting deadline, the penalty amounts, and the exact wording of the CII Directive. These come from news and law-firm summaries and are marked in the status column. Whether the organisation is a designated CII owner is assumed for the lab.
- **Scope:** the table supports analysis and does not give legal advice. It does not price regulatory penalties into the dollar exposure.

## 5. Overlap-aware optimizer
Fixes overlap, so reductions are not additive. For scenario s and chosen set F:
`residual_s = baseline_s x product over f in F of (1 - effectiveness[f][s])`.
With under 15 candidate fixes the optimizer checks every subset within budget, so the answer is exact. Ties go to lower cost, then fewer fixes. The tool also prints what a naive additive model would have claimed, to show the size of the error it avoids.
Effectiveness values are Declared analyst judgement. They are sensitivity-tested: each value is perturbed by up to +/-20% over 100 trials and the share of trials returning the same recommended set is reported.

## 6. Verification
Each Atomic Red Team test records the host, the expected outcome before and after remediation, and the Wazuh rule IDs that mean "detected" and "blocked". A test is VERIFIED only when both observed outcomes match. A test is reported "not applicable" when the recommended set contains none of the fixes that could change its outcome, so the tool never claims verification it cannot support.

## 7. Validation
- Known-answer unit tests for the scoring formula, PERT bounds, seeded reproducibility, overlap arithmetic, the optimizer, and verify classification (`pytest`).
- CVSS-only comparison: the top 10 under the model are shown against CVSS rank with the reason for each difference (EPSS, criticality, active alerts).

## 8. Results on the sample data (illustrative, not evidence)
Re-run after the benchmark update: at a 50,000 budget the recommendation was stable in about 97% of sensitivity trials and the additive model overclaimed by about 32%; at 80,000, 92% and 49%. Earlier figures below came from the placeholder ranges and are superseded.
- At a 50,000 budget the recommendation is stable in only about a third of sensitivity trials; at 80,000 it is stable in about nine in ten. A recommendation that flips under small assumption changes should be presented as one of several near-equivalent options.
- The additive model overstated savings by roughly 30% at 50,000 and 50% at 80,000.

## 9. Limitations
- Effectiveness, SLE and ARO are assumptions; the model is only as good as their documentation.
- Alert evidence can only scale declared frequency by up to 2x, using a simple linear rule; the mapping from techniques to scenarios is analyst judgement and one alert can support several scenarios.
- Fixes are treated as independent multiplicative reductions; real controls can be correlated or have dependencies.
- Technical findings cover endpoints and logs only. Governance, people and physical controls are out of scope and are not scored.
- One tested technique is a demonstration of the loop, not coverage evidence.
- Sample data is synthetic; results show the method works, not how any real organisation performs.
- Fix costs are Declared and look small next to benchmark-scale losses (a quarter of a million dollars of exposure reduction per fix is common), which exaggerates payback; replace them with quotes for the organisation being modelled.
- Several benchmark figures were read from secondary summaries and still need checking against the original reports.
