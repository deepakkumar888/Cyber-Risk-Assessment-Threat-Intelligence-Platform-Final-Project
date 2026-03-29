from flask import Flask, render_template, request
from scanner import WebScanner
from email_alert import send_alert_if_needed

app = Flask(__name__)
last_scan_result = None  # store last scan in memory

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global last_scan_result
    error = None

    if request.method == "POST":
        target = request.form.get("target")
        scanner = WebScanner(target)
        result = scanner.scan()

        if result["status"] == "error":
            error = f"Scan failed: {result['error']}"
            last_scan_result = None
        else:
            last_scan_result = result
            # automatically send email if High/Critical found
            send_alert_if_needed(result)

    return render_template("dashboard.html", scan=last_scan_result, error=error)

if __name__ == "__main__":
    app.run(debug=True)
