"""Verify step: each Atomic Red Team test has an expected outcome and the Wazuh rule that should fire."""


def observe(test, alerts):
    hits = [a for a in alerts if a["agent"]["name"] == test["host"]
            and test["test_id"] in a["rule"].get("mitre", {}).get("id", [])]
    ids = {a["rule"]["id"] for a in hits}
    if ids & set(test["block_rules"]):
        return "blocked"
    if ids & set(test["detect_rules"]):
        return "detected"
    return "missed"


def verify(tests, alerts_before, alerts_after, applied_fixes=None):
    out = []
    for t in tests:
        req = t.get("requires_any")
        if applied_fixes is not None and req and not set(req) & set(applied_fixes):
            out.append({"test_id": t["test_id"], "name": t["name"], "before": "-", "after": "-",
                        "expected_before": t["expected_before"], "expected_after": t["expected_after"],
                        "verified": None, "note": "not applicable: recommended set has none of " + ", ".join(req)})
            continue
        b, a = observe(t, alerts_before), observe(t, alerts_after)
        out.append({"test_id": t["test_id"], "name": t["name"], "before": b, "after": a,
                    "expected_before": t["expected_before"], "expected_after": t["expected_after"],
                    "verified": b == t["expected_before"] and a == t["expected_after"]})
    return out
