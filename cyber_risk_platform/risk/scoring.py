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
