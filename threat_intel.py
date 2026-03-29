import pandas as pd

def enrich_with_threat_intel(vuln_df: pd.DataFrame) -> pd.DataFrame:
    intel_data = []
    for _, row in vuln_df.iterrows():
        reputation = "clean"
        notes = ""
        if row['port'] == 3389:
            reputation = "suspicious"
            notes = "RDP exposed to internet is a common attack vector."
        elif row['port'] == 22:
            reputation = "medium"
            notes = "SSH brute-force attacks are common; use strong auth."

        intel_data.append({
            'host': row['host'],
            'port': row['port'],
            'ti_reputation': reputation,
            'ti_notes': notes
        })

    intel_df = pd.DataFrame(intel_data)
    return vuln_df.merge(intel_df, on=['host', 'port'], how='left')