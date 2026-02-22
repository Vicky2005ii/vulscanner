import requests
from urllib.parse import urljoin
from reporting import report_finding


def test_xss(base_url):
    print(f"\nTesting {base_url} for XSS...\n")

    search_url = urljoin(base_url, "/search")

    payload = "<script>alert('XSS')</script>"

    try:
        test_url = f"{search_url}?q={payload}"

        response = requests.get(test_url, timeout=5)

        # Check if payload is reflected in response
        if payload in response.text:
            report_finding(
                target=test_url,
                vuln_type="Cross-Site Scripting (XSS)",
                severity="HIGH",
                details="Reflected XSS detected with payload"
            )
            print("[!] XSS detected!")
        else:
            print("[-] No XSS detected.")

    except Exception as e:
        print(f"Error testing XSS: {e}")