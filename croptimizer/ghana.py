"""Ghana layer: cedi conversion and incident-to-obligation mapping.

The obligation table lives in sample-data/model.json so it can be corrected without touching code.
Every row carries a source id and a verification status. This is analysis support, not legal advice."""


def to_ghs(usd, rate):
    return usd * rate


def obligations_for(scenario, obligations):
    trig = set(scenario.get("triggers", []))
    return [o for o in obligations if trig & set(o["triggers"])]


def scenario_map(scenarios, obligations):
    rows = []
    for s in scenarios:
        obs = obligations_for(s, obligations)
        hours = [o["deadline_hours"] for o in obs if o.get("deadline_hours")]
        rows.append({"id": s["id"], "scenario": s["name"],
                     "obligations": [o["id"] for o in obs],
                     "regulators": sorted({o["regulator"] for o in obs}),
                     "shortest_deadline_hours": min(hours) if hours else None})
    return rows
