"""End-to-end run: Measure -> Quantify -> Prioritize -> Fix -> Verify."""
import json, os, random
from . import scoring, fair, optimizer, signals, ghana, verify as vf


def _load(d, name):
    with open(os.path.join(d, name)) as f:
        return json.load(f)


def heatmap(alerts, assets):
    crit = {a["name"]: a["criticality"] for a in assets}
    tot = {}
    for a in alerts:
        for t in a["rule"].get("mitre", {}).get("tactic", []):
            tot[t] = tot.get(t, 0) + a["rule"]["level"] * crit.get(a["agent"]["name"], 1)
    top = max(tot.values()) if tot else 1
    rows = []
    for t, v in sorted(tot.items(), key=lambda kv: -kv[1]):
        r = v / top
        rows.append({"tactic": t, "weight": v, "color": "red" if r >= .66 else "orange" if r >= .33 else "yellow"})
    return rows


def register(scenarios, ale_mean, chosen_effect_ids, effect):
    def bucket(x, hi, mid): return 5 if x >= hi else 3 if x >= mid else 1
    rows = []
    for s in scenarios:
        aro = s["aro"][1]; sle = s["sle"][1]
        L, I = bucket(aro, 0.5, 0.15), bucket(sle, 300000, 60000)
        covered = any(effect.get(f, {}).get(s["id"], 0) >= 0.25 for f in chosen_effect_ids)
        rows.append({"risk": s["name"], "likelihood": L, "impact": I, "score": L * I, "owner": s["owner"],
                     "ale_mean": round(ale_mean[s["id"]]), "treatment": "mitigate" if covered else "accept (review)",
                     "source": "Declared (SLE/ARO) + Measured (alerts)"})
    return sorted(rows, key=lambda r: (-r["score"], -r["ale_mean"]))


def run(data_dir, budget, seed=None, with_sensitivity=True):
    m = _load(data_dir, "model.json")
    cfg = m["assumptions"]
    seed = cfg["seed"] if seed is None else seed
    before = _load(data_dir, "alerts_before.json")
    after = _load(data_dir, "alerts_after.json")
    tests = _load(data_dir, "verify.json")

    # Prioritize (Measured: findings + alerts; Declared: asset criticality)
    scored = scoring.score_findings(m["findings"], m["assets"], before, cfg)
    vuln_before = scoring.enterprise_score([f["priority"] for f in scored], cfg["score_k"])

    # Quantify (FAIR-lite Monte Carlo, seeded)
    scaled = [{**sc, "sle": [x * cfg.get("sle_scale", 1.0) for x in sc["sle"]]} for sc in m["scenarios"]]
    adj, sig_before = signals.adjust_scenarios(scaled, before, cfg)
    sig_after = signals.count_signals(after, m["scenarios"], cfg["signal_min_level"])
    samples = fair.simulate(adj, cfg["mc_iterations"], seed)
    ale_mean = {k: fair.mean(v) for k, v in samples.items()}
    exp_before = fair.total_distribution(samples)

    # Fix (overlap-aware optimizer)
    effect = m["effectiveness"]
    sol = optimizer.solve(ale_mean, m["fixes"], effect, budget)
    fac = optimizer.residual_factors(sol["fixes"], effect, ale_mean)
    exp_after = fair.total_distribution(samples, fac)
    naive = optimizer.naive_additive_reduction(sol["fixes"], ale_mean, effect)
    sens = (optimizer.sensitivity(ale_mean, m["fixes"], effect, budget, random.Random(seed))
            if with_sensitivity else None)

    # Score after: close findings the chosen fixes remediate; use post-fix alerts
    closed = {fid for fx in m["fixes"] if fx["id"] in sol["fixes"] for fid in fx["closes"]}
    scored_after = scoring.score_findings([f for f in m["findings"] if f["id"] not in closed],
                                          m["assets"], after, cfg)
    vuln_after = scoring.enterprise_score([f["priority"] for f in scored_after], cfg["score_k"])
    score_before = scoring.blended_score(vuln_before, exp_before["mean"], cfg["exposure_ref"], cfg["weight_vuln"])
    score_after = scoring.blended_score(vuln_after, exp_after["mean"], cfg["exposure_ref"], cfg["weight_vuln"])

    names = {f["id"]: f["name"] for f in m["fixes"]}
    return {
        "assumptions_version": cfg["version"], "seed": seed, "budget": budget,
        "score": {"before": round(score_before, 1), "after": round(score_after, 1),
                  "vuln_before": round(vuln_before, 1), "vuln_after": round(vuln_after, 1),
                  "rating_before": scoring.rating(score_before), "rating_after": scoring.rating(score_after)},
        "exposure_before": exp_before, "exposure_after": exp_after,
        "recommendation": {"fixes": [names[i] for i in sol["fixes"]], "fix_ids": sol["fixes"], "cost": sol["cost"],
                           "reduction_correct": sol["reduction"], "reduction_naive_claim": naive,
                           "overclaim_pct": 100 * (naive - sol["reduction"]) / sol["reduction"] if sol["reduction"] else 0},
        "standalone_ranking": optimizer.standalone_ranking(ale_mean, m["fixes"], effect),
        "sensitivity": sens,
        "signals": [{"scenario": sc["name"], "alerts_before": sig_before[sc["id"]]["alerts"],
                     "aro_multiplier": sig_before[sc["id"]]["aro_multiplier"],
                     "alerts_after_fix": sig_after[sc["id"]]} for sc in m["scenarios"]],
        "ghana": {"usd_ghs": cfg.get("usd_ghs", 11.66), "fx_note": cfg.get("usd_ghs_note", ""),
                  "obligations": m.get("ghana_obligations", []),
                  "scenario_map": ghana.scenario_map(m["scenarios"], m.get("ghana_obligations", [])),
                  "findings_count": len(m["findings"])},
        "sources": m.get("sources", []),
        "scenario_basis": [{"scenario": sc["name"], "sle_low": sc["sle"][0], "sle_mode": sc["sle"][1],
                            "sle_high": sc["sle"][2], "sle_basis": sc.get("sle_basis", "Declared"),
                            "aro_basis": "Declared"} for sc in scaled],
        "top_findings": scored[:5], "cvss_comparison": scoring.cvss_only_comparison(scored),
        "heatmap": heatmap(before, m["assets"]),
        "register": register(adj, ale_mean, sol["fixes"], effect),
        "verification": vf.verify(tests, before, after, sol["fixes"]),
        "labels": {"Measured (Wazuh)": ["alerts", "MITRE tags", "findings", "CVSS/EPSS (enrichment)"],
                   "Declared (manual)": ["asset criticality", "SLE/ARO ranges", "fix costs", "fix effectiveness", "owners"]},
    }
