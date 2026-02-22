from form_scanner import test_forms
from crawler import crawl_site
from html_report import generate_html_report
from port_scanner import scan_ports
from urllib.parse import urlparse
from sql_injection import test_sql_injection
from xss_scanner import test_xss
import requests

def check_target(url):
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
    except:
        print("Target unreachable")

if __name__ == "__main__":
    target = input("Enter target URL: ")

    urls = crawl_site(target)

    # Always include common endpoints
    urls.append(target + "/login")
    urls.append(target + "/search")

    print("Testing URLs:", urls)

    for url in urls:
        print("Checking:", url)
        test_sql_injection(url)
        test_xss(url)

    test_forms(target)

    generate_html_report()




