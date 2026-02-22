import sqlite3


def generate_html_report():
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()

    cursor.execute("SELECT target, vulnerability, severity, details, timestamp FROM findings")
    findings = cursor.fetchall()

    conn.close()

    # Count severity levels
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = finding[2]
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Simple risk score formula
    risk_score = (
        severity_counts["CRITICAL"] * 5 +
        severity_counts["HIGH"] * 3 +
        severity_counts["MEDIUM"] * 2 +
        severity_counts["INFO"] * 1
    )

    # Normalize score to 10
    max_possible = max(len(findings) * 5, 1)
    normalized_score = round((risk_score / max_possible) * 10, 1)

    # Risk level label
    if normalized_score >= 7:
        risk_level = "HIGH"
    elif normalized_score >= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "gold",
        "INFO": "blue"
    }

    html_content = f"""
    <html>
    <head>
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial; background-color: #f4f4f4; }}
            h1 {{ text-align: center; }}
            table {{ width: 90%; margin: auto; border-collapse: collapse; }}
            th, td {{ padding: 10px; border: 1px solid #ccc; text-align: left; }}
            th {{ background-color: #333; color: white; }}
            .summary {{ width: 90%; margin: 20px auto; padding: 15px; background: white; }}
        </style>
    </head>
    <body>
        <h1>Vulnerability Scan Report</h1>

        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Critical:</strong> {severity_counts["CRITICAL"]}</p>
            <p><strong>High:</strong> {severity_counts["HIGH"]}</p>
            <p><strong>Medium:</strong> {severity_counts["MEDIUM"]}</p>
            <p><strong>Info:</strong> {severity_counts["INFO"]}</p>
            <p><strong>Risk Score:</strong> {normalized_score}/10</p>
            <p><strong>Overall Risk Level:</strong> {risk_level}</p>
        </div>

        <table>
            <tr>
                <th>Target</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Details</th>
                <th>Timestamp</th>
            </tr>
    """

    for finding in findings:
        target, vuln, severity, details, timestamp = finding
        color = severity_colors.get(severity, "black")

        html_content += f"""
            <tr>
                <td>{target}</td>
                <td>{vuln}</td>
                <td style="color:{color}; font-weight:bold;">{severity}</td>
                <td>{details}</td>
                <td>{timestamp}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open("report.html", "w") as file:
        file.write(html_content)

    print("\n[+] HTML report generated with summary: report.html")