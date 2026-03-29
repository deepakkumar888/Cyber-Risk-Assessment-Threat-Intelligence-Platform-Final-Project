# Assignment 3 Report: Web Application Vulnerability Scanning System

## Design Decisions

### Architecture
The system is built using Flask for the web framework, providing a simple yet effective structure for the dashboard and API endpoints. The scanner is implemented as a separate class (`WebScanner`) to encapsulate scanning logic, making it modular and testable.

### Vulnerability Detection
I implemented 6 vulnerability checks to exceed the minimum requirement of 5:
1. **Insecure Transport**: Checks if the site uses HTTP instead of HTTPS
2. **Missing Security Headers**: Verifies presence of essential security headers (CSP, X-Frame-Options, X-Content-Type-Options)
3. **Directory Listing**: Detects if directory browsing is enabled
4. **Reflected XSS**: Basic test using a script payload in query parameters
5. **SQL Injection**: Checks for common SQL error patterns in responses
6. **Sensitive Information**: Searches for keywords like "password" in responses

Each finding includes severity levels (Critical, High, Medium, Low, Informational) and numeric scores for risk calculation.

### Dashboard Design
The dashboard features:
- Clean, dark theme for professional appearance
- Scan form at the top
- Risk summary card with color-coded risk levels (green/yellow/red)
- Severity distribution bars for quick visual assessment
- Detailed findings table with all vulnerability information

This design differs from typical class examples by using a horizontal bar chart for severity distribution and color-coded risk indicators.

### Email Alert System
The alert system automatically triggers only for High and Critical findings, sending HTML-formatted emails with:
- Severity-based subject line
- Summary table of findings
- Scan metadata (URL, timestamp, overall score)
- Recommended actions for each issue
- Automated disclaimer

### Error Handling
The scanner includes comprehensive error handling to prevent crashes on invalid URLs or network issues, returning appropriate error messages to the user.

## Challenges Faced

### Vulnerability Detection Accuracy
Implementing accurate vulnerability detection without false positives was challenging. The basic pattern-matching approach used (especially for XSS and SQL injection) may not catch all real-world cases but provides a good foundation for educational purposes.

### Email Configuration
Setting up SMTP for alerts required careful handling of authentication (especially for Gmail's app passwords) and error handling to prevent the application from crashing if email sending fails.

### Dashboard Responsiveness
Ensuring the dashboard works well on different screen sizes while maintaining the custom styling required some CSS adjustments.

### Testing
Testing the scanner on various test sites revealed that some vulnerabilities are harder to detect reliably without more advanced techniques like parsing HTML or using specialized libraries.

## Future Improvements
- Integrate more sophisticated scanning techniques (e.g., using Selenium for JavaScript-heavy sites)
- Add more vulnerability types (CSRF, SSRF, etc.)
- Implement user authentication and scan history storage
- Add export functionality for reports
- Enhance the dashboard with interactive charts using JavaScript libraries

## Conclusion
This project successfully implements all required components of the assignment, providing a functional vulnerability scanning system with visualization and alerting capabilities. The modular design makes it easy to extend and improve in the future.