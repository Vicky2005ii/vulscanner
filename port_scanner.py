import socket
from concurrent.futures import ThreadPoolExecutor
from reporting import report_finding

def scan_single_port(target, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            report_finding(
                target=target,
                vuln_type="Open Port",
                severity="INFO",
                details=f"Port {port} is open"
            )

        s.close()
    except:
        pass


def scan_ports(target):
    print(f"\nScanning ports on {target}...\n")

    common_ports = [21, 22, 80, 443, 3306, 5000]

    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in common_ports:
            executor.submit(scan_single_port, target, port)
