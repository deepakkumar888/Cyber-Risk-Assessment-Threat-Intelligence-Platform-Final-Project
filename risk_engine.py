import pandas as pd

def calculate_risk_score(row) -> int:
    score = 0
    if row['state'] == 'open':
        score += 3
    if row['port'] in [22, 3389, 445]:
        score += 4
    if 'Apache' in str(row['product']):
        score += 2
    if row.get('ti_reputation') == 'suspicious':
        score += 4
    elif row.get('ti_reputation') == 'medium':
        score += 2
    return min(score, 10)

def assign_severity(score: int) -> str:
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"

def add_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    df['risk_score'] = df.apply(calculate_risk_score, axis=1)
    df['severity'] = df['risk_score'].apply(assign_severity)
    return df