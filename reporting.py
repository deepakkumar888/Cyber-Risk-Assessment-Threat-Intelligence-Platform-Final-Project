from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def generate_pdf_report(df, target_ip: str) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setTitle("Cyber Risk Assessment Report")

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Cyber Risk Assessment Report")
    y -= 30

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Target: {target_ip}")
    y -= 15

    total_findings = len(df)
    critical = (df['severity'] == 'Critical').sum()
    high = (df['severity'] == 'High').sum()
    medium = (df['severity'] == 'Medium').sum()
    low = (df['severity'] == 'Low').sum()

    lines = [
        f"Total findings: {total_findings}",
        f"Critical: {critical}",
        f"High: {high}",
        f"Medium: {medium}",
        f"Low: {low}",
        "",
        "Top Findings:"
    ]

    for line in lines:
        c.drawString(50, y, line)
        y -= 15

    for _, row in df.head(15).iterrows():
        if y < 50:
            c.showPage()
            y = height - 50
        text = (
            f"{row['host']}:{row['port']} - {row['service']} "
            f"Sev: {row['severity']} Score: {row['risk_score']}"
        )
        c.drawString(50, y, text)
        y -= 12

    c.showPage()
    c.save()

    pdf = buffer.getvalue()
    buffer.close()
    return pdf