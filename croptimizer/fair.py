"""FAIR-lite: ALE = SLE x ARO per scenario, with PERT distributions and a seeded Monte Carlo."""
import random


def pert(rng, lo, mode, hi):
    if hi == lo:
        return lo
    a = 1 + 4 * (mode - lo) / (hi - lo)
    b = 1 + 4 * (hi - mode) / (hi - lo)
    return lo + rng.betavariate(a, b) * (hi - lo)


def simulate(scenarios, n, seed):
    """Return {scenario: [ALE samples]}. Same seed => identical samples (reproducible)."""
    rng = random.Random(seed)
    out = {}
    for s in scenarios:
        out[s["id"]] = [pert(rng, *s["aro"]) * pert(rng, *s["sle"]) for _ in range(n)]
    return out


def mean(xs):
    return sum(xs) / len(xs)


def percentile(sorted_xs, p):
    i = min(len(sorted_xs) - 1, max(0, int(round(p / 100 * (len(sorted_xs) - 1)))))
    return sorted_xs[i]


def total_distribution(samples, factors=None):
    """Sum scenario ALE samples (paired by iteration), scaling each by its residual factor."""
    factors = factors or {}
    names = list(samples)
    n = len(samples[names[0]])
    tot = [sum(samples[k][i] * factors.get(k, 1.0) for k in names) for i in range(n)]
    tot.sort()
    return {"mean": mean(tot), "p5": percentile(tot, 5), "p50": percentile(tot, 50), "p95": percentile(tot, 95)}
