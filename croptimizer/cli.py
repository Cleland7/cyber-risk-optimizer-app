import argparse, json, os
from . import pipeline, store

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def money(x): return "$%s" % format(round(x), ",")


def main():
    p = argparse.ArgumentParser(prog="croptimizer", description="Budget-Constrained Cyber Risk Optimizer (replay mode)")
    p.add_argument("--data", default=os.path.join(HERE, "sample-data"))
    p.add_argument("--budget", type=float, default=50000)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--db", help="write before/after snapshots to this SQLite file")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    a = p.parse_args()
    r = pipeline.run(a.data, a.budget, a.seed)
    if a.db:
        eb, ea = r["exposure_before"], r["exposure_after"]
        for label, sc, e in [("before", r["score"]["before"], eb), ("after", r["score"]["after"], ea)]:
            store.save_snapshot(a.db, label, r["assumptions_version"],
                [("enterprise_score", sc, "Measured"), ("exposure_mean", e["mean"], "Declared"),
                 ("exposure_p5", e["p5"], "Declared"), ("exposure_p95", e["p95"], "Declared")], r["recommendation"])
    if a.json:
        print(json.dumps(r, indent=1, default=str)); return
    s, eb, ea, rec = r["score"], r["exposure_before"], r["exposure_after"], r["recommendation"]
    print(f"Enterprise risk score: {s['before']} ({s['rating_before']}) -> {s['after']} ({s['rating_after']})")
    print(f"Annual exposure before: {money(eb['mean'])} (90% CI {money(eb['p5'])} to {money(eb['p95'])})")
    print(f"Budget {money(r['budget'])}: spend {money(rec['cost'])} on {', '.join(rec['fixes']) or 'nothing'}")
    print(f"Annual exposure after:  {money(ea['mean'])} (90% CI {money(ea['p5'])} to {money(ea['p95'])})")
    print(f"Naive additive model would claim {money(rec['reduction_naive_claim'])} saved; overlap-aware says "
          f"{money(rec['reduction_correct'])} ({rec['overclaim_pct']:.0f}% overclaim avoided)")
    if r["sensitivity"]:
        print(f"Recommendation stability under +/-20% effectiveness error: {r['sensitivity']['stability']:.0%}")
    print("\nTop findings (priority = crit x CVSS x EPSS x threat):")
    for f in r["top_findings"]:
        print(f"  {f['id']} {f['asset']:<6} {f['priority']:>6}  {f['title']}")
    print("\nModel vs CVSS-only ranking:")
    for c in r["cvss_comparison"]:
        print(f"  #{c['model_rank']} (CVSS #{c['cvss_rank']}) {c['id']}: {c['why']}")
    print("\nAlert evidence (Measured) scaling scenario frequency (Declared):")
    for g in r["signals"]:
        print(f"  {g['scenario']:<38} alerts {g['alerts_before']:>2} -> x{g['aro_multiplier']}  (after fix: {g['alerts_after_fix']} alerts)")
    print("\nMITRE heatmap:", ", ".join(f"{h['tactic']}={h['color']}" for h in r["heatmap"]))
    print("\nVerify:")
    for v in r["verification"]:
        if v["verified"] is None:
            print(f"  {v['test_id']} {v['note']}")
        else:
            print(f"  {v['test_id']} {v['before']} -> {v['after']}  {'VERIFIED' if v['verified'] else 'NOT VERIFIED'}")


if __name__ == "__main__":
    main()
