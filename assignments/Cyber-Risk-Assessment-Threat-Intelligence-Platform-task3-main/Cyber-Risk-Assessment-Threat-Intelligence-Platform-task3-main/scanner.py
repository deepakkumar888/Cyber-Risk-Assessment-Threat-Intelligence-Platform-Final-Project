import requests
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class WebScanner:
    def __init__(self, target_url: str):
        # Ensure scheme is present
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        self.target_url = target_url
        self.findings = []

    def scan(self):
        # Main scan function, safe on errors
        try:
            resp = requests.get(self.target_url, timeout=10)
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "target": self.target_url
            }

        # Run all checks (7 vulnerability types)
        self.check_https()
        self.check_security_headers(resp)
        self.check_directory_listing(resp)
        self.check_xss()
        self.check_sql_injection()
        self.check_sensitive_info(resp)
        self.check_mixed_content_images(resp)

        overall_score = self.calculate_overall_score()
        return {
            "status": "ok",
            "target": self.target_url,
            "timestamp": datetime.utcnow().isoformat(),
            "overall_score": overall_score,
            "findings": self.findings
        }

    def add_finding(self, name, severity, score, description, recommended_action, url=None):
        self.findings.append({
            "name": name,
            "severity": severity,        # Critical/High/Medium/Low/Informational
            "score": score,              # numeric score
            "description": description,
            "recommended_action": recommended_action,
            "url": url or self.target_url,
            "timestamp": datetime.utcnow().isoformat()
        })

    def check_https(self):
        # 1) Insecure transport
        parsed = urlparse(self.target_url)
        if parsed.scheme == "http":
            self.add_finding(
                "Insecure Transport (HTTP)",
                "High",
                8,
                "Site is served over HTTP, traffic can be intercepted.",
                "Configure HTTPS with a valid TLS certificate."
            )

    def check_security_headers(self, resp):
        # 2) Missing security headers
        headers = resp.headers
        required = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        missing = [h for h in required if h not in headers]
        if missing:
            self.add_finding(
                "Missing Security Headers",
                "Medium",
                5,
                f"Response is missing headers: {', '.join(missing)}.",
                "Set recommended security headers on the web server or framework."
            )

    def check_directory_listing(self, resp):
        # 3) Directory listing
        if "Index of /" in resp.text:
            self.add_finding(
                "Directory Listing Enabled",
                "Medium",
                6,
                "Server appears to expose directory listing.",
                "Disable autoindex / directory listing on the server."
            )

    def check_xss(self):
        # 4) Reflected XSS pattern
        test_url = self.target_url
        payload = "<script>alert(1)</script>"
        if "?" in test_url:
            test_url = test_url + "&q=" + payload
        else:
            test_url = test_url + "?q=" + payload
        try:
            resp = requests.get(test_url, timeout=10)
            if payload in resp.text:
                self.add_finding(
                    "Reflected XSS",
                    "High",
                    9,
                    "Reflected XSS detected using parameter 'q'.",
                    "Sanitize and encode all user-controlled input before rendering."
                )
        except Exception:
            # Ignore, just don't crash
            pass

    def check_sql_injection(self):
        # 5) Basic SQL injection error pattern
        inj_url = self.target_url
        payload = "' OR 1=1--"
        if "?" in inj_url:
            inj_url = inj_url + "&id=" + payload
        else:
            inj_url = inj_url + "?id=" + payload
        try:
            resp = requests.get(inj_url, timeout=10)
            sql_errors = ["SQL syntax", "mysql_fetch", "warning: pg_", "ODBC driver", "SQLSTATE"]
            if any(err.lower() in resp.text.lower() for err in sql_errors):
                self.add_finding(
                    "Possible SQL Injection",
                    "High",
                    9,
                    "Database error messages suggest possible SQL injection.",
                    "Use parameterized queries and input validation."
                )
        except Exception:
            pass

    def check_sensitive_info(self, resp):
        # 6) Sensitive information keyword
        if "password" in resp.text.lower():
            self.add_finding(
                "Sensitive Information in Response",
                "Medium",
                5,
                "The page contains 'password', may disclose sensitive information.",
                "Avoid exposing sensitive details in public responses."
            )

    def check_mixed_content_images(self, resp):
        # 7) Mixed content in images
        parsed_target = urlparse(self.target_url)
        if parsed_target.scheme != "https":
            return  # Only check for HTTPS pages
        soup = BeautifulSoup(resp.text, 'html.parser')
        mixed_images = []
        for img in soup.find_all('img'):
            src = img.get('src')
            if src:
                parsed_src = urlparse(src)
                if parsed_src.scheme == "http" or (not parsed_src.scheme and parsed_src.netloc):  # relative URLs are ok, but if netloc and no scheme, assume http
                    # For simplicity, check if starts with http://
                    if src.startswith("http://"):
                        mixed_images.append(src)
        if mixed_images:
            self.add_finding(
                "Mixed Content in Images",
                "Medium",
                6,
                f"Images loaded over HTTP on HTTPS page: {', '.join(mixed_images[:3])}",  # limit to 3
                "Ensure all images are served over HTTPS."
            )

    def calculate_overall_score(self):
        if not self.findings:
            return 0
        total = sum(f["score"] for f in self.findings)
        return round(total / len(self.findings), 2)
