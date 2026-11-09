"""Alert evidence -> scenario frequency.

Each scenario lists the MITRE techniques/tactics that count as evidence for it. Observed alerts
(Measured) scale the Declared ARO range: multiplier = 1 + min(1, n_alerts / alerts_for_max_signal),
so evidence can at most double the declared frequency. The cap and divisor are Declared assumptions.
"""


def _matches(alert, sig):
    m = alert["rule"].get("mitre", {})
    ids = m.get("id", [])
    tactics = m.get("tactic", [])
    return (any(i.startswith(t) for i in ids for t in sig.get("techniques", []))
            or any(t in sig.get("tactics", []) for t in tactics))


def count_signals(alerts, scenarios, min_level):
    return {s["id"]: sum(1 for a in alerts
                         if a["rule"]["level"] >= min_level and _matches(a, s.get("signals", {})))
            for s in scenarios}


def multiplier(n, alerts_for_max):
    return 1.0 + min(1.0, n / alerts_for_max)


def adjust_scenarios(scenarios, alerts, cfg):
    """Return (scenarios with ARO scaled by evidence, per-scenario signal detail)."""
    counts = count_signals(alerts, scenarios, cfg["signal_min_level"])
    out, detail = [], {}
    for s in scenarios:
        m = multiplier(counts[s["id"]], cfg["alerts_for_max_signal"])
        out.append({**s, "aro": [x * m for x in s["aro"]]})
        detail[s["id"]] = {"alerts": counts[s["id"]], "aro_multiplier": round(m, 2)}
    return out, detail
