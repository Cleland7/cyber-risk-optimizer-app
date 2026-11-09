"""Risk Prioritization Engine (a transparent weighted score, not AI).

priority = AssetCriticality(1-5) x CVSS(0-10) x EPSS(0-1) x ThreatMultiplier(1-2)   -> 0..100
enterprise score = 100 * (1 - exp(-sum(priority) / K))                               -> 0..100
"""
import math


def threat_multiplier(alerts, host, high_level=10, cap_alerts=5):
    """1.0 with no related alerts, rising linearly to 2.0 at `cap_alerts` high-severity alerts on the host."""
    n = sum(1 for a in alerts
            if a["agent"]["name"] == host and a["rule"]["level"] >= high_level)
    return 1.0 + min(1.0, n / cap_alerts)


def finding_priority(finding, criticality, multiplier):
    return criticality * finding["cvss"] * finding["epss"] * multiplier


def score_findings(findings, assets, alerts, cfg):
    """Return findings enriched with criticality, multiplier, priority (sorted high to low)."""
    crit = {a["name"]: a["criticality"] for a in assets}
    out = []
    for f in findings:
        m = threat_multiplier(alerts, f["asset"], cfg["high_alert_level"], cfg["alerts_for_max_multiplier"])
        c = crit[f["asset"]]
        out.append({**f, "criticality": c, "threat_multiplier": round(m, 2),
                    "priority": round(finding_priority(f, c, m), 2)})
    return sorted(out, key=lambda x: -x["priority"])


def enterprise_score(priorities, k):
    return 100.0 * (1.0 - math.exp(-sum(priorities) / k))


def blended_score(vuln_score, exposure_mean, exposure_ref, weight_vuln):
    """Blend the vulnerability-driven score with residual dollar exposure so the headline
    score cannot read 0 while money is still at risk (phishing, insider misuse, unknowns)."""
    exp_component = 100.0 * (1.0 - math.exp(-exposure_mean / exposure_ref))
    return weight_vuln * vuln_score + (1.0 - weight_vuln) * exp_component


def rating(score):
    return "HIGH" if score >= 66 else "MODERATE" if score >= 33 else "LOW"


def cvss_only_comparison(scored, top=10):
    """Compare the model's ranking with a plain CVSS ranking and say why they differ."""
    by_cvss = sorted(scored, key=lambda f: (-f["cvss"], f["id"]))
    cvss_rank = {f["id"]: i + 1 for i, f in enumerate(by_cvss)}
    rows = []
    for i, f in enumerate(scored[:top], start=1):
        delta = cvss_rank[f["id"]] - i
        why = []
        if f["epss"] >= 0.5: why.append("high exploit probability (EPSS)")
        if f["criticality"] >= 5: why.append("crown-jewel asset")
        if f["threat_multiplier"] > 1.0: why.append("active alerts on host")
        if f["epss"] < 0.1: why.append("low EPSS pulls it down")
        if f["criticality"] <= 2: why.append("low-value asset pulls it down")
        rows.append({"id": f["id"], "model_rank": i, "cvss_rank": cvss_rank[f["id"]],
                     "moved": delta, "why": "; ".join(why) or "similar under both"})
    return rows
