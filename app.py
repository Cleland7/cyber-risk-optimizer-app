"""Streamlit front end: budget slider, cedi/dollar toggle, Ghana regulatory impact analyzer.
Run: pip install streamlit && streamlit run app.py"""
import os
import streamlit as st
from croptimizer import pipeline

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-data")
st.set_page_config(page_title="Cyber Risk Optimizer | Bernard Kartey Larbi", layout="wide")
st.title("Budget-Constrained Cyber Risk Optimizer")
st.warning("Demonstration on a FICTIONAL organisation (Pinnacle Bank Ghana lab). Loss sizes (SLE) are anchored to cited "
           "benchmarks where the table below says Cited; attack frequencies, fix costs and fix effectiveness are DECLARED "
           "assumptions. Legal and benchmark figures read from secondary sources still need checking against the originals. "
           "Not legal advice.")
st.caption("Measured = from Wazuh alerts/findings. Declared = manual inputs. Loop: Measure, Quantify, Prioritize, Fix, Verify.")

with st.sidebar:
    st.header("Settings")
    cur = st.radio("Currency", ["USD", "GHS (cedi)"])
    r0 = pipeline.run(DATA, 0, with_sensitivity=False)
    rate = st.number_input("Cedis per US dollar", value=float(r0["ghana"]["usd_ghs"]), step=0.05, format="%.2f")
    st.caption(r0["ghana"]["fx_note"])

mult = rate if cur.startswith("GHS") else 1.0
sym = "GH₵" if cur.startswith("GHS") else "$"
m = lambda x: f"{sym}{x * mult:,.0f}"

budget_usd = st.slider("Security budget (USD)", 0, 150000, 50000, 1000)
if mult != 1.0:
    st.caption(f"Budget in cedis: {m(budget_usd)}. Fix costs are modelled in USD.")
r = pipeline.run(DATA, budget_usd, with_sensitivity=False)
eb, ea, rec = r["exposure_before"], r["exposure_after"], r["recommendation"]

c1, c2, c3 = st.columns(3)
c1.metric("Risk score", f"{r['score']['after']}", f"{r['score']['after'] - r['score']['before']:+.1f} vs before (Measured)")
c2.metric("Annual exposure (mean)", m(ea["mean"]), f"-{m(eb['mean'] - ea['mean'])} (Declared model)")
c3.metric("Spend", m(rec["cost"]))
st.write(f"**90% CI:** {m(ea['p5'])} to {m(ea['p95'])}  |  **Fixes:** {', '.join(rec['fixes']) or 'none'}")
st.info(f"A naive additive model would claim {m(rec['reduction_naive_claim'])} saved; "
        f"overlap-aware estimate is {m(rec['reduction_correct'])}.")

# ---- Ghana regulatory impact analyzer
g = r["ghana"]
st.header("Ghana regulatory impact analyzer")
st.caption("Pick an incident to see which Ghanaian obligations it can trigger, who the regulator is and how long you have.")
by_id = {o["id"]: o for o in g["obligations"]}
names = {x["scenario"]: x for x in g["scenario_map"]}
pick = st.selectbox("Incident", list(names))
sel = names[pick]
if sel["shortest_deadline_hours"]:
    st.error(f"Shortest fixed deadline: {sel['shortest_deadline_hours']} hours from detection. "
             f"Regulators involved: {', '.join(sel['regulators'])}.")
else:
    st.warning(f"No fixed-hours deadline verified. Regulators involved: {', '.join(sel['regulators'])}.")
st.dataframe([{"Obligation": by_id[i]["name"], "Regulator": by_id[i]["regulator"], "Law": by_id[i]["law"],
               "Deadline": by_id[i]["deadline"], "Applies if": by_id[i]["applies_if"],
               "Penalty": by_id[i]["penalty"], "Status": by_id[i]["status"]} for i in sel["obligations"]],
             use_container_width=True)
v = by_id.get("cii_vuln_72h")
if v:
    st.info(f"Vulnerability disclosure: if the bank is a designated critical information infrastructure owner, the CII Directive "
            f"(per a law-firm summary; verify wording) expects vulnerabilities found in audits to be disclosed within 72 hours. "
            f"This lab's register holds {g['findings_count']} findings.")
lo, hi = 3000, 120000
st.caption(f"Context: the reported Act 1038 administrative penalty range (GHS 3,000 to 120,000, about "
           f"${lo / rate:,.0f} to ${hi / rate:,.0f}) is small beside the modelled loss from an incident. The cost that matters "
           f"most is the loss itself, plus enforcement and reputational consequences that this model does not price.")

st.subheader("Regulator view: where each scenario lands")
st.dataframe([{"Scenario": x["scenario"], "Regulators": ", ".join(x["regulators"]),
               "Obligations": len(x["obligations"]), "Shortest fixed deadline (hours)": x["shortest_deadline_hours"]}
              for x in g["scenario_map"]], use_container_width=True)

# ---- model detail
st.subheader("Alert evidence driving frequency"); st.dataframe(r["signals"], use_container_width=True)
st.subheader("Risk register")
st.dataframe([{**x, "ale_mean": round(x["ale_mean"] * mult)} for x in r["register"]], use_container_width=True)
st.subheader("MITRE ATT&CK heatmap (by weighted alert volume)"); st.dataframe(r["heatmap"], use_container_width=True)
st.subheader("Model vs CVSS-only ranking"); st.dataframe(r["cvss_comparison"], use_container_width=True)
st.subheader("Verification"); st.dataframe(r["verification"], use_container_width=True)
st.subheader("Where the loss figures come from")
st.caption(f"Loss ranges shown in {cur.split()[0]}.")
st.dataframe([{**x, "sle_low": round(x["sle_low"] * mult), "sle_mode": round(x["sle_mode"] * mult),
               "sle_high": round(x["sle_high"] * mult)} for x in r["scenario_basis"]], use_container_width=True)
st.dataframe(r["sources"], use_container_width=True)
