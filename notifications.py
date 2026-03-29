import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SENDER_EMAIL = "deepakkumar226010@gmail.com"
SENDER_PASSWORD = "wdnu zglt qvab tuwx"  # use Gmail app password

def send_email_alert(to_email: str, target_ip: str, high_risk_df):
    subject = f"[ALERT] High-Risk Vulnerabilities on {target_ip}"
    body_lines = [
        f"High/Critical vulnerabilities detected on {target_ip}:",
        ""
    ]
    for _, row in high_risk_df.iterrows():
        body_lines.append(
            f"- {row['host']}:{row['port']} ({row['service']}) "
            f"Severity: {row['severity']} Score: {row['risk_score']}"
        )
    body = "\n".join(body_lines)

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
    server.quit()