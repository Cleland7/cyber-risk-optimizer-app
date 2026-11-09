"""Streamlit front end with the budget slider.  Run: pip install streamlit && streamlit run app.py"""
import os
import streamlit as st
from croptimizer import pipeline

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-data")
st.set_page_config(page_title="Cyber Risk Optimizer | Bernard Kartey Larbi", layout="wide")
st.title("Budget-Constrained Cyber Risk Optimizer")
st.warning("Demonstration on a FICTIONAL organisation (Pinnacle Bank Ghana lab). Loss sizes (SLE) are anchored to cited "
           "benchmarks where the table below says Cited; attack frequencies, fix costs and fix effectiveness are DECLARED "
           "assumptions. Figures marked secondary still need checking against the original reports.")
st.caption("Measured = from Wazuh alerts/findings. Declared = manual inputs. Loop: Measure, Quantify, Prioritize, Fix, Verify.")

budget = st.slider("Security budget (USD)", 0, 150000, 50000, 1000)
r = pipeline.run(DATA, budget, with_sensitivity=False)
eb, ea, rec = r["exposure_before"], r["exposure_after"], r["recommendation"]

c1, c2, c3 = st.columns(3)
c1.metric("Risk score", f"{r['score']['after']}", f"{r['score']['after'] - r['score']['before']:+.1f} vs before (Measured)")
c2.metric("Annual exposure (mean)", f"${ea['mean']:,.0f}", f"-${eb['mean'] - ea['mean']:,.0f} (Declared model)")
c3.metric("Spend", f"${rec['cost']:,.0f}")
st.write(f"**90% CI:** ${ea['p5']:,.0f} to ${ea['p95']:,.0f}  |  **Fixes:** {', '.join(rec['fixes']) or 'none'}")
st.info(f"A naive additive model would claim ${rec['reduction_naive_claim']:,.0f} saved; "
        f"overlap-aware estimate is ${rec['reduction_correct']:,.0f}.")

st.subheader("Alert evidence driving frequency"); st.dataframe(r["signals"], use_container_width=True)
st.subheader("Risk register"); st.dataframe(r["register"], use_container_width=True)
st.subheader("MITRE ATT&CK heatmap (by weighted alert volume)"); st.dataframe(r["heatmap"], use_container_width=True)
st.subheader("Model vs CVSS-only ranking"); st.dataframe(r["cvss_comparison"], use_container_width=True)
st.subheader("Verification"); st.dataframe(r["verification"], use_container_width=True)

st.subheader("Where the loss figures come from")
st.dataframe(r["scenario_basis"], use_container_width=True)
st.dataframe(r["sources"], use_container_width=True)
