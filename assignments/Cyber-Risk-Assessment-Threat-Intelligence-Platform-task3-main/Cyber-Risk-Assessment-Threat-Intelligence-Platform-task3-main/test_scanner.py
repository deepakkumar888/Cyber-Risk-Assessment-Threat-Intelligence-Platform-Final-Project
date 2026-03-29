from scanner import WebScanner

# Test the scanner with a sample URL
test_url = "http://httpbin.org"  # A safe test site

scanner = WebScanner(test_url)
result = scanner.scan()

print("Scan Result:")
print(f"Status: {result['status']}")
if result['status'] == 'ok':
    print(f"Target: {result['target']}")
    print(f"Overall Score: {result['overall_score']}")
    print(f"Findings: {len(result['findings'])}")
    for finding in result['findings']:
        print(f"- {finding['name']} ({finding['severity']})")
else:
    print(f"Error: {result['error']}")