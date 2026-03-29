import pandas as pd
import plotly.express as px
import streamlit as st

from scanner.nmap_scanner import run_nmap_scan
from threat_intel.shodan_client import enrich_with_shodan, load_config
from risk.scoring import score_vulnerabilities, aggregate_risk


st.set_page_config(
    page_title="Cyber Risk Assessment & Threat Intelligence Platform",
    layout="wide",
)

st.title("Cyber Risk Assessment & Threat Intelligence Platform")

cfg = load_config()

with st.sidebar:
    st.header("Scan Settings")
    targets_text = st.text_area(
        "Targets (comma-separated IP/host)",
        value=",".join(cfg.get("default_targets", ["127.0.0.1"])),
    )
    enable_shodan = st.checkbox("Use Shodan Threat Intelligence", value=True)
    run_btn = st.button("Run Assessment")

if not run_btn:
    st.info("Enter targets and click 'Run Assessment' to start.")
else:
    targets = [t.strip() for t in targets_text.split(",") if t.strip()]
    st.write(f"Targets: {targets}")

    st.subheader("Step 1 – Vulnerability Scanning (Nmap)")
    scan_df = run_nmap_scan(targets)
    st.dataframe(scan_df)

    if enable_shodan:
        st.subheader("Step 2 – Threat Intelligence (Shodan)")
        intel_df = enrich_with_shodan(scan_df["host"].unique().tolist())
        st.dataframe(intel_df)
    else:
        intel_df = pd.DataFrame(columns=["ip", "organization", "isp", "open_ports", "tags", "vuln_count"])

    st.subheader("Step 3 – Risk Scoring & Analytics")
    merged_df = score_vulnerabilities(scan_df, intel_df)
    st.dataframe(merged_df)

    summary = aggregate_risk(merged_df)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Assets", summary.get("asset_total", 0))
    c2.metric("Average Risk", round(summary.get("avg_risk", 0), 2))
    c3.metric("Max Risk", summary.get("max_risk", 0))
    c4.metric("Critical Assets", summary.get("critical_assets", 0))

    if not merged_df.empty:
        st.subheader("Severity Distribution")
        sev_counts = (
            merged_df.groupby("severity")["host"]
            .nunique()
            .reset_index(name="asset_count")
        )
        fig = px.bar(sev_counts, x="severity", y="asset_count", color="severity")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Download Report")
    st.download_button(
        "Download CSV Report",
        data=merged_df.to_csv(index=False),
        file_name="cyber_risk_report.csv",
        mime="text/csv",
    )
