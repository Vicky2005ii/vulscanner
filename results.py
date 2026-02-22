results = []

def add_result(target, vulnerability, severity, details):
    results.append({
        "target": target,
        "vulnerability": vulnerability,
        "severity": severity,
        "details": details
    })

def get_results():
    return results
