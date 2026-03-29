from scanner import WebScanner
from email_alert import send_alert_if_needed

# Use a known test target that generates High findings
url = "http://httpbin.org"

scanner = WebScanner(url)
result = scanner.scan()
print("Scan status:", result["status"])
print("Overall score:", result.get("overall_score"))
print("Findings:", len(result.get("findings", [])))
for f in result.get("findings", []):
    print(f" - {f['name']} ({f['severity']})")

print("\nTriggering alert (if any High/Critical findings)...")
send_alert_if_needed(result)
