"""Overlap-aware fix optimizer.

Naive models add up each fix's risk reduction, which double-counts when two fixes hit the same
scenario (MFA and EDR both reduce credential theft). Here residual risk for a scenario is

    residual = baseline x PRODUCT over chosen fixes of (1 - effectiveness[fix][scenario])

With <= ~14 candidate fixes, exhaustive search over subsets is exact and easy to test.
"""
from itertools import combinations


def residual_factors(chosen, effect, scenarios):
    f = {}
    for s in scenarios:
        r = 1.0
        for fx in chosen:
            r *= 1.0 - effect.get(fx, {}).get(s, 0.0)
        f[s] = r
    return f


def exposure(chosen, baseline, effect):
    fac = residual_factors(chosen, effect, baseline)
    return sum(baseline[s] * fac[s] for s in baseline)


def naive_additive_reduction(chosen, baseline, effect):
    """What a double-counting model would claim (kept to show the flaw, never used to decide)."""
    return sum(baseline[s] * effect.get(fx, {}).get(s, 0.0) for fx in chosen for s in baseline)


def solve(baseline, fixes, effect, budget):
    """Exact best subset within budget. Ties break toward lower cost, then fewer fixes."""
    ids = [f["id"] for f in fixes]
    cost = {f["id"]: f["cost"] for f in fixes}
    base_total = sum(baseline.values())
    best = ((), 0.0, 0)
    for r in range(len(ids) + 1):
        for combo in combinations(ids, r):
            c = sum(cost[i] for i in combo)
            if c > budget:
                continue
            red = base_total - exposure(combo, baseline, effect)
            if (red, -c, -len(combo)) > (best[1], -best[2], -len(best[0])):
                best = (combo, red, c)
    chosen, red, c = best
    return {"fixes": list(chosen), "cost": c, "reduction": red,
            "residual": base_total - red, "baseline": base_total}


def standalone_ranking(baseline, fixes, effect):
    """Per-fix risk reduced per dollar, in isolation (useful context, not the decision)."""
    base = sum(baseline.values())
    rows = []
    for f in fixes:
        red = base - exposure([f["id"]], baseline, effect)
        rows.append({"id": f["id"], "name": f["name"], "cost": f["cost"],
                     "reduction": red, "per_dollar": red / f["cost"]})
    return sorted(rows, key=lambda r: -r["per_dollar"])


def sensitivity(baseline, fixes, effect, budget, rng, trials=100, swing=0.2, cap=0.95):
    """Perturb every effectiveness by +/-swing; report how often the recommended set stays the same."""
    ref = tuple(sorted(solve(baseline, fixes, effect, budget)["fixes"]))
    same = 0
    seen = {}
    for _ in range(trials):
        pe = {fx: {s: min(cap, max(0.0, v * rng.uniform(1 - swing, 1 + swing))) for s, v in d.items()}
              for fx, d in effect.items()}
        pick = tuple(sorted(solve(baseline, fixes, pe, budget)["fixes"]))
        seen[pick] = seen.get(pick, 0) + 1
        same += pick == ref
    return {"stability": same / trials, "alternatives": sorted(seen.items(), key=lambda kv: -kv[1])[:3]}
