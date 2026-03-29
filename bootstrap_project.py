import os
from pathlib import Path
import textwrap

ROOT = Path("cyber_risk_platform")

files = {
    "config.json": textwrap.dedent("""
    {
      "shodan_api_key": "YOUR_SHODAN_API_KEY",
      "default_targets": ["127.0.0.1"]
    }
    """).strip() + "\n",

    "main.py": textwrap.dedent("""
    import os
    import subprocess
    import sys


    def main():
        os.environ.setdefault("PYTHONPATH", os.path.dirname(__file__))
        cmd = [sys.executable, "-m", "streamlit", "run", "dashboard/app.py"]
        subprocess.run(cmd)


    if __name__ == "__main__":
        main()
    """).strip() + "\n",

    "scanner/__init__.py": "",
    "scanner/nmap_scanner.py": textwrap.dedent("""
    import nmap
    import pandas as pd


    def run_nmap_scan(targets):
        nm = nmap.PortScanner()
        nm.scan(hosts=" ".join(targets), arguments="-sV -T4 --top-ports 100")

        rows = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]
                    rows.append(
                        {
                            "host": host,
                            "protocol": proto,
                            "port": port,
                            "state": service["state"],
                            "name": service.get("name", ""),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                        }
                    )
        return pd.DataFrame(rows or [], columns=[
            "host", "protocol", "port", "state", "name", "product", "version"
        ])
    """).strip() + "\n",

    "threat_intel/__init__.py": "",
    "threat_intel/shodan_client.py": textwrap.dedent("""
    import json
    from pathlib import Path

    import pandas as pd
    import shodan


    def load_config(path="config.json"):
        return json.loads(Path(path).read_text())


    def build_client(config_path="config.json"):
        cfg = load_config(config_path)
        return shodan.Shodan(cfg["shodan_api_key"])


    def enrich_with_shodan(ip_list, config_path="config.json"):
        api = build_client(config_path)
        rows = []
        for ip in ip_list:
            try:
                host = api.host(ip)
                vulns = host.get("vulns", []) or []
                rows.append(
                    {
                        "ip": ip,
                        "organization": host.get("org", ""),
                        "isp": host.get("isp", ""),
                        "open_ports": ",".join(str(p) for p in host.get("ports", [])),
                        "tags": ",".join(host.get("tags", [])),
                        "vuln_count": len(vulns),
                    }
                )
            except shodan.APIError:
                rows.append(
                    {
                        "ip": ip,
                        "organization": "",
                        "isp": "",
                        "open_ports": "",
                        "tags": "",
                        "vuln_count": 0,
                    }
                )
        return pd.DataFrame(rows)
    """).strip() + "\n",

    "risk/__init__.py": "",
    "risk/scoring.py": textwrap.dedent("""
    import pandas as pd


    def score_vulnerabilities(scan_df, intel_df):
        if scan_df is None or scan_df.empty:
            return pd.DataFrame()

        merged = scan_df.merge(intel_df, left_on="host", right_on="ip", how="left")

        def calc_score(row):
            score = 1
            if row["state"] == "open":
                score += 2
            if row.get("vuln_count", 0) > 0:
                score += 3
            if row["port"] in (22, 23, 80, 443, 3389):
                score += 2
            return min(score, 10)

        merged["risk_score"] = merged.apply(calc_score, axis=1)

        def label(score):
            if score >= 9:
                return "Critical"
            if score >= 7:
                return "High"
            if score >= 4:
                return "Medium"
            return "Low"

        merged["severity"] = merged["risk_score"].map(label)
        return merged


    def aggregate_risk(merged_df):
        if merged_df is None or merged_df.empty:
            return {}

        sev_counts = (
            merged_df.groupby("severity")["host"]
            .nunique()
            .reset_index(name="asset_count")
        )

        summary = {
            "asset_total": int(merged_df["host"].nunique()),
            "avg_risk": float(merged_df["risk_score"].mean()),
            "max_risk": int(merged_df["risk_score"].max()),
        }
        for _, row in sev_counts.iterrows():
            summary[f"{row['severity'].lower()}_assets"] = int(row["asset_count"])
        return summary
    """).strip() + "\n",

    "dashboard/__init__.py": "",
    "dashboard/app.py": textwrap.dedent("""
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
    """).strip() + "\n",
}


def main():
    ROOT.mkdir(exist_ok=True)
    for path, content in files.items():
        file_path = ROOT / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
    print(f"Project created at: {ROOT.resolve()}")


if __name__ == "__main__":
    main()
