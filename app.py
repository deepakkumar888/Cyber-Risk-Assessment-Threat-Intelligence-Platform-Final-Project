import streamlit as st
import pandas as pd
import plotly.express as px

from scanner import fake_scan
from threat_intel import enrich_with_threat_intel
from risk_engine import add_risk_scores
from reporting import generate_pdf_report
from notifications import send_email_alert

# ----------------- PAGE CONFIG -----------------
st.set_page_config(
    page_title="Cyber Risk Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- HEADER -----------------
st.markdown(
    "<h1 style='text-align: left; color: #1f4e79;'>Cyber Risk Assessment & Threat Intelligence Platform</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "Real-time view of vulnerabilities, risk scores, and compliance posture."
)

# ----------------- SIDEBAR CONTROLS -----------------
st.sidebar.header("Scan & Filters")

target_ip = st.sidebar.text_input("Target IP / Host", value="192.168.1.10")

env_choice = st.sidebar.selectbox(
    "Environment",
    ["Production", "Staging", "Development"]
)

owner = st.sidebar.text_input("System Owner (optional)", value="Security Team")

run_scan_btn = st.sidebar.button("Run Scan / Refresh")

severity_filter = st.sidebar.multiselect(
    "Severity filter",
    options=["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"]
)

# ----------------- SESSION STATE -----------------
if "scan_df" not in st.session_state:
    st.session_state["scan_df"] = pd.DataFrame()

if run_scan_btn:
    with st.spinner("Running vulnerability scan and updating intelligence..."):
        df = fake_scan(target_ip)
        df["environment"] = env_choice
        df["owner"] = owner

        df = enrich_with_threat_intel(df)
        df = add_risk_scores(df)

        st.session_state["scan_df"] = df
        st.success("Scan complete and dashboard updated!")

df = st.session_state["scan_df"]

# Apply severity filter
if not df.empty:
    df = df[df["severity"].isin(severity_filter)]

# ----------------- NO DATA MESSAGE -----------------
if df.empty:
    st.info("Run a scan from the sidebar to view results.")
    st.stop()

# ----------------- TOP METRICS (KPI CARDS) -----------------
total_findings = len(df)
critical = (df["severity"] == "Critical").sum()
high = (df["severity"] == "High").sum()
medium = (df["severity"] == "Medium").sum()
low = (df["severity"] == "Low").sum()
avg_risk = round(df["risk_score"].mean(), 2)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Findings", total_findings)
col2.metric("Critical", critical)
col3.metric("High", high)
col4.metric("Medium", medium)
col5.metric("Avg Risk Score", avg_risk)

st.markdown("---")

# ----------------- TABS -----------------
tab_overview, tab_hosts, tab_compliance, tab_settings = st.tabs(
    ["📊 Overview", "🖥️ Host Details", "📄 Compliance & Reports", "⚙️ Settings"]
)

# ===== TAB 1: OVERVIEW =====
with tab_overview:
    left_col, right_col = st.columns([2, 1])

    with left_col:
        st.subheader("Severity Distribution (Bar)")
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig_bar = px.bar(
            sev_counts,
            x="severity",
            y="count",
            color="severity",
            title="Number of Findings per Severity",
            color_discrete_map={
                "Critical": "#d7191c",
                "High": "#fdae61",
                "Medium": "#ffffbf",
                "Low": "#1a9641",
            },
        )
        fig_bar.update_layout(xaxis_title="Severity", yaxis_title="Count")
        st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("Risk Score Histogram")
        fig_hist = px.histogram(
            df,
            x="risk_score",
            nbins=10,
            title="Distribution of Risk Scores",
            color="severity",
        )
        fig_hist.update_layout(xaxis_title="Risk Score", yaxis_title="Frequency")
        st.plotly_chart(fig_hist, use_container_width=True)

    with right_col:
        st.subheader("Severity Share (Pie Chart)")
        fig_pie = px.pie(
            sev_counts,
            names="severity",
            values="count",
            title="Severity Share",
            color="severity",
            color_discrete_map={
                "Critical": "#d7191c",
                "High": "#fdae61",
                "Medium": "#ffffbf",
                "Low": "#1a9641",
            },
        )
        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Threat Intelligence Snapshot")
        top_ti = df[["host", "port", "service", "ti_reputation", "ti_notes"]].head(5)
        st.dataframe(top_ti, use_container_width=True, height=230)

# ===== TAB 2: HOST DETAILS =====
with tab_hosts:
    st.subheader("Per-Host Vulnerability View")

    host_list = df["host"].unique().tolist()
    selected_host = st.selectbox("Select Host", options=host_list)

    host_df = df[df["host"] == selected_host]

    c1, c2 = st.columns(2)
    with c1:
        st.write(f"Environment: **{host_df['environment'].iloc[0]}**")
        st.write(f"Owner: **{host_df['owner'].iloc[0]}**")
    with c2:
        host_avg_risk = round(host_df["risk_score"].mean(), 2)
        host_max_severity = host_df["severity"].value_counts().idxmax()
        st.write(f"Avg Risk: **{host_avg_risk}**")
        st.write(f"Dominant Severity: **{host_max_severity}**")

    st.markdown("### Open Ports & Findings")
    st.dataframe(
        host_df[["port", "service", "product", "state", "severity", "risk_score", "ti_reputation"]],
        use_container_width=True,
        height=300,
    )

# ===== TAB 3: COMPLIANCE & REPORTS =====
with tab_compliance:
    st.subheader("Compliance Overview (Simplified)")

    st.write(
        "- Map **Critical/High** findings to urgent remediation.\n"
        "- Medium/Low findings align with best-practice hardening.\n"
        "- Use this report as evidence for audits."
    )

    sev_group = df.groupby("severity")["risk_score"].agg(["count", "mean"]).reset_index()
    sev_group.rename(columns={"count": "num_findings", "mean": "avg_risk"}, inplace=True)
    st.dataframe(sev_group, use_container_width=True)

    st.markdown("### Generate & Download PDF Report")
    if st.button("Generate PDF Report"):
        pdf_bytes = generate_pdf_report(df, target_ip)
        st.download_button(
            label="Download PDF",
            data=pdf_bytes,
            file_name=f"cyber_risk_report_{target_ip}.pdf",
            mime="application/pdf",
        )

# ===== TAB 4: SETTINGS (EMAIL ALERTS) =====
with tab_settings:
    st.subheader("Alerting Configuration")

    st.write(
        "Configure basic email alerts. For production, store secrets in environment variables or Streamlit secrets."
    )

    to_email = st.text_input("Alert recipient email")
    min_severity_for_alert = st.selectbox(
        "Minimum severity to alert on",
        options=["Critical", "High", "Medium"],
        index=0,
    )

    severity_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    threshold = severity_order[min_severity_for_alert]
    alert_df = df[df["severity"].map(severity_order) >= threshold]

    st.write(f"Findings that will trigger alerts: **{len(alert_df)}**")

    if st.button("Send Alert Email Now"):
        if alert_df.empty:
            st.warning("No findings match the selected severity threshold.")
        else:
            try:
                send_email_alert(to_email, target_ip, alert_df)
                st.success("Alert email sent.")
            except Exception as e:
                st.error(f"Failed to send email: {e}")