# Lab setup (live mode)

Isolated, host-only network. Never connect this lab to production or the internet-facing LAN.

| VM | Role | Criticality (declared) |
|----|------|------------------------|
| DC01 | Windows Server, Active Directory | 5 |
| DB01 | Database server | 5 |
| WEB01 | Linux web server | 4 |
| VPN01 | Remote access gateway | 4 |
| WS01-02 | Windows workstations | 2 |

1. Deploy Wazuh (pin the version in your notes; vulnerability data location differs across 4.x releases) and enrol each VM as an agent.
2. Add custom rules (IDs 100100+) that tag the technique you test, one rule for "detected" and one for "blocked".
3. Run one Atomic Red Team test at a time (for the credential-access example, the test for T1003.001 from the public Atomic Red Team library). Record before/after in `sample-data/verify.json` format: expected outcome and the Wazuh rule that should fire.
4. Export the alerts from the Wazuh indexer to JSON in the shape of `sample-data/alerts_before.json`, scrub hostnames/IPs, and point `--data` at your folder.

Replay mode needs none of this.
