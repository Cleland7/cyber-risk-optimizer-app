"""Generates the replay dataset. All values are FICTIONAL placeholders for a lab called Pinnacle Bank Ghana.
Replace SLE/ARO/effectiveness with cited figures (IBM Cost of a Data Breach, Verizon DBIR) before publishing results."""
import json, os, random
here = os.path.dirname(os.path.abspath(__file__))
rng = random.Random(7)

model = {
 "assumptions": {"version": "2026.11-a", "seed": 42, "mc_iterations": 10000,
   "score_k": 120.0, "signal_min_level": 7, "alerts_for_max_signal": 10, "exposure_ref": 1500000, "sle_scale": 1.0, "weight_vuln": 0.6, "high_alert_level": 10, "alerts_for_max_multiplier": 5,
   "sle_aro_source": "SLE anchored to cited benchmarks where marked Cited; ARO (frequency) is DECLARED for every scenario (no public per-organisation source)",
   "effectiveness_source": "DECLARED analyst judgement; sensitivity-tested at +/-20%"},

 "sources": [
  {"id": "S1", "claim": "Global average data breach cost USD 4.99M (2026), up 12%", "source": "IBM Cost of a Data Breach Report 2026", "url": "https://www.ibm.com/reports/data-breach", "status": "Primary page seen"},
  {"id": "S2", "claim": "Breaches over 200 days cost USD 5.65M vs 4.32M under 200 days; AI-enabled breaches about USD 6M", "source": "IBM 2026 as reported by secondary sites (deepstrike.io, IBM newsroom)", "url": "https://newsroom.ibm.com/campaign?item=2889", "status": "Verify the 4.32M/5.65M split in the IBM report"},
  {"id": "S3", "claim": "Median ransom paid USD 139,875 (2026), 69% of victims did not pay; ransomware in 48% of breaches", "source": "Verizon 2026 DBIR as reported by securitypointbreak.com", "url": "https://securitypointbreak.com/2026/05/20/verizon-2026-dbir-biggest-security-shifts/", "status": "Secondary; verify in the DBIR. One site quotes a different median (115,000), so confirm."},
  {"id": "S4", "claim": "Mean ransomware recovery cost excluding ransom USD 1.7M (2026)", "source": "Sophos State of Ransomware 2026 as reported by stingrai.io", "url": "https://www.stingrai.io/blog/ransomware-statistics-2026", "status": "Secondary; verify in the Sophos report"},
  {"id": "S5", "claim": "Median ransom payment USD 769,000 (2026 survey)", "source": "Sophos State of Ransomware 2026 as reported by usecarly.com", "url": "https://www.usecarly.com/blog/ransomware-statistics/", "status": "Secondary; verify in the Sophos report"},
  {"id": "S6", "claim": "BEC: USD 3.05B reported losses across 24,768 complaints in 2025 (derived average about USD 123,000)", "source": "FBI IC3 2025 Internet Crime Report", "url": "https://www.ic3.gov/annualreport/reports", "status": "Figures via secondary summaries; derived average is my division, verify against the report"},
  {"id": "S7", "claim": "Average reported loss across all IC3 complaints USD 20,699 (2025)", "source": "FBI IC3 2025 Internet Crime Report", "url": "https://www.ic3.gov/annualreport/reports", "status": "Figures via secondary summaries"},
  {"id": "S8", "claim": "Vulnerability exploitation is the top initial access vector (31%); median 43 days to fully fix a CISA KEV vulnerability", "source": "Verizon 2026 DBIR (via SecurityWeek, Stingrai)", "url": "https://www.securityweek.com/verizon-dbir-2026-vulnerability-exploitation-overtakes-credential-theft-as-top-breach-vector/", "status": "Context for patching priority; not a model input"}
 ],
 "assets": [
  {"name": "DC01", "role": "Windows domain controller", "criticality": 5},
  {"name": "DB01", "role": "Customer database", "criticality": 5},
  {"name": "WEB01", "role": "Linux web server", "criticality": 4},
  {"name": "VPN01", "role": "Remote access gateway", "criticality": 4},
  {"name": "WS01", "role": "Teller workstation", "criticality": 2},
  {"name": "WS02", "role": "Back-office workstation", "criticality": 2}],
 "findings": [
  {"id": "F-001", "asset": "DC01", "title": "Unpatched privilege-escalation flaw", "cvss": 8.8, "epss": 0.92},
  {"id": "F-002", "asset": "VPN01", "title": "Exposed gateway, known exploit", "cvss": 9.1, "epss": 0.88},
  {"id": "F-003", "asset": "DB01", "title": "Weak service-account policy", "cvss": 7.5, "epss": 0.40},
  {"id": "F-004", "asset": "WEB01", "title": "Outdated web framework (RCE)", "cvss": 9.8, "epss": 0.70},
  {"id": "F-005", "asset": "WS01", "title": "Office macro handling flaw", "cvss": 7.8, "epss": 0.55},
  {"id": "F-006", "asset": "WS02", "title": "Old browser, memory corruption", "cvss": 8.8, "epss": 0.06},
  {"id": "F-007", "asset": "WEB01", "title": "TLS misconfiguration", "cvss": 5.3, "epss": 0.03},
  {"id": "F-008", "asset": "DB01", "title": "Unencrypted backup share", "cvss": 6.5, "epss": 0.12},
  {"id": "F-009", "asset": "DC01", "title": "SMB signing not enforced", "cvss": 5.9, "epss": 0.30},
  {"id": "F-010", "asset": "WS01", "title": "Local admin reuse", "cvss": 7.2, "epss": 0.35}],
 "scenarios": [
  {"id": "ransomware", "signals": {"techniques": ["T1204", "T1505", "T1068"]}, "name": "Ransomware", "owner": "CISO", "aro": [0.05, 0.15, 0.50], "sle": [140000, 1840000, 2470000], "sle_basis": "Cited (mixed sources, see S3-S5)"},
  {"id": "data_breach", "signals": {"techniques": ["T1041"]}, "name": "Customer data breach", "owner": "DPO", "aro": [0.03, 0.10, 0.30], "sle": [4320000, 4990000, 6000000], "sle_basis": "Cited (IBM 2026, see S1-S2)"},
  {"id": "credential_theft", "signals": {"techniques": ["T1003", "T1078"]}, "name": "Credential theft and abuse", "owner": "IT Security", "aro": [0.20, 0.60, 1.50], "sle": [20000, 80000, 300000], "sle_basis": "Declared (no direct benchmark)"},
  {"id": "phishing_bec", "signals": {"techniques": ["T1204"]}, "name": "Phishing / business email compromise", "owner": "Head of Ops", "aro": [0.30, 1.00, 3.00], "sle": [20699, 123000, 500000], "sle_basis": "Cited low/mode (S6-S7), declared high"},
  {"id": "downtime", "signals": {"tactics": ["Impact"]}, "name": "Service outage", "owner": "CIO", "aro": [0.10, 0.40, 1.00], "sle": [10000, 40000, 150000], "sle_basis": "Declared (no benchmark sourced)"}],
 "fixes": [
  {"id": "mfa", "name": "MFA rollout", "cost": 12000, "closes": ["F-003", "F-010"]},
  {"id": "patch_core", "name": "Patch DC01 and VPN01", "cost": 6000, "closes": ["F-001", "F-002", "F-009"]},
  {"id": "patch_web", "name": "Patch web stack", "cost": 5000, "closes": ["F-004", "F-007"]},
  {"id": "edr", "name": "EDR upgrade", "cost": 28000, "closes": ["F-005", "F-006"]},
  {"id": "backup", "name": "Immutable offline backups", "cost": 9000, "closes": ["F-008"]},
  {"id": "training", "name": "Phishing awareness programme", "cost": 4000, "closes": []},
  {"id": "segmentation", "name": "Network segmentation", "cost": 18000, "closes": []},
  {"id": "pam", "name": "Privileged access management", "cost": 22000, "closes": []},
  {"id": "db_monitor", "name": "Database activity monitoring", "cost": 15000, "closes": []}],
 "effectiveness": {
  "mfa": {"credential_theft": 0.60, "phishing_bec": 0.35, "data_breach": 0.15, "ransomware": 0.10},
  "patch_core": {"ransomware": 0.30, "data_breach": 0.20, "credential_theft": 0.15, "downtime": 0.15},
  "patch_web": {"data_breach": 0.20, "ransomware": 0.10, "downtime": 0.10},
  "edr": {"ransomware": 0.45, "credential_theft": 0.35, "data_breach": 0.15, "downtime": 0.20},
  "backup": {"ransomware": 0.25, "downtime": 0.45},
  "training": {"phishing_bec": 0.40, "credential_theft": 0.10, "ransomware": 0.05},
  "segmentation": {"ransomware": 0.25, "data_breach": 0.25, "downtime": 0.10},
  "pam": {"credential_theft": 0.45, "data_breach": 0.15, "ransomware": 0.10},
  "db_monitor": {"data_breach": 0.30}}
}

def alert(host, rid, level, desc, tid, tactic):
    return {"timestamp": "2026-11-01T10:%02d:00Z" % rng.randint(0, 59), "agent": {"name": host},
            "rule": {"id": str(rid), "level": level, "description": desc,
                     "mitre": {"id": [tid], "tactic": [tactic]}}}

before = ([alert("DC01", 100100, 12, "LSASS memory access (credential dumping)", "T1003.001", "Credential Access") for _ in range(4)]
 + [alert("DC01", 100110, 10, "Privilege escalation attempt", "T1068", "Privilege Escalation") for _ in range(2)]
 + [alert("VPN01", 100120, 10, "Repeated VPN auth failures then success", "T1078", "Initial Access") for _ in range(3)]
 + [alert("WEB01", 100130, 8, "Web shell indicator", "T1505.003", "Persistence") for _ in range(2)]
 + [alert("WS01", 100140, 9, "Suspicious macro child process", "T1204.002", "Execution") for _ in range(3)]
 + [alert("DB01", 100150, 7, "Bulk data read by service account", "T1041", "Exfiltration") for _ in range(2)]
 + [alert("WS02", 100160, 5, "Browser spawned shell", "T1059", "Execution")])
after = ([alert("DC01", 100101, 12, "LSASS access BLOCKED by EDR", "T1003.001", "Credential Access")]
 + [alert("WS01", 100140, 6, "Suspicious macro child process (blocked)", "T1204.002", "Execution")])

verify = [{"test_id": "T1003.001", "name": "Atomic Red Team: LSASS credential dumping", "host": "DC01",
           "expected_before": "detected", "expected_after": "blocked",
           "requires_any": ["edr", "pam"], "detect_rules": ["100100"], "block_rules": ["100101"]}]

for name, obj in [("model.json", model), ("alerts_before.json", before), ("alerts_after.json", after), ("verify.json", verify)]:
    with open(os.path.join(here, name), "w") as f:
        json.dump(obj, f, indent=1)
print("sample data written")
