from flask import Flask, render_template, request
from urllib.parse import urlparse
import sqlite3

from scanner import check_target
from sql_injection import test_sql_injection
from xss_scanner import test_xss
from port_scanner import scan_ports
from html_report import generate_html_report

app = Flask(__name__)


def run_scan(target):
    # Clear old results
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    conn.commit()
    conn.close()

    check_target(target)

    parsed = urlparse(target)
    host = parsed.hostname

    scan_ports(host)
    test_sql_injection(target)
    test_xss(target)

    generate_html_report()


def get_results():
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()
    cursor.execute("SELECT target, vulnerability, severity, details, timestamp FROM findings")
    results = cursor.fetchall()
    conn.close()
    return results


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form["url"]
        run_scan(target)
        results = get_results()

        # Count severity levels
        summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "INFO": 0
        }

        for r in results:
            severity = r[2]
            if severity in summary:
                summary[severity] += 1

        return render_template("results.html", results=results, summary=summary)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
