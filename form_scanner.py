import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from reporting import report_finding


def extract_forms(url):
    forms = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
    except:
        pass
    return forms


def test_forms(base_url):
    print(f"\n[+] Extracting forms from {base_url}")

    forms = extract_forms(base_url)

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()

        form_url = urljoin(base_url, action)

        inputs = form.find_all("input")

        sql_data = {}
        xss_data = {}

        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                sql_data[name] = "admin' OR 1=1 --"
                xss_data[name] = "<script>alert('XSS')</script>"

        try:
            # -------- SQL TEST --------
            if method == "post":
                sql_response = requests.post(form_url, data=sql_data, timeout=5)
            else:
                sql_response = requests.get(form_url, params=sql_data, timeout=5)

            if "Welcome" in sql_response.text:
                report_finding(
                    target=form_url,
                    vuln_type="SQL Injection (Form)",
                    severity="CRITICAL",
                    details="Possible login bypass via form injection"
                )
                print(f"[!] SQL Injection detected in form at {form_url}")

            # -------- XSS TEST --------
            if method == "post":
                xss_response = requests.post(form_url, data=xss_data, timeout=5)
            else:
                xss_response = requests.get(form_url, params=xss_data, timeout=5)

            if "<script>alert('XSS')</script>" in xss_response.text:
                report_finding(
                    target=form_url,
                    vuln_type="Cross-Site Scripting (Form)",
                    severity="HIGH",
                    details="Reflected XSS detected via form input"
                )
                print(f"[!] XSS detected in form at {form_url}")

        except:
            pass