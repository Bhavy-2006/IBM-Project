
import socket
import subprocess
import json
import datetime
import argparse
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  RISK DATABASE
# ─────────────────────────────────────────────

RISKY_PORTS = {
    21:  {"service": "FTP",         "risk": "High",   "reason": "Plaintext credentials; often exploited for anonymous login."},
    22:  {"service": "SSH",         "risk": "Medium", "reason": "Brute-force target; ensure key-based auth is enforced."},
    23:  {"service": "Telnet",      "risk": "High",   "reason": "Completely unencrypted; credentials sent in plaintext."},
    25:  {"service": "SMTP",        "risk": "Medium", "reason": "Can be abused for spam relay if misconfigured."},
    53:  {"service": "DNS",         "risk": "Low",    "reason": "May allow zone transfer if misconfigured."},
    80:  {"service": "HTTP",        "risk": "Medium", "reason": "Unencrypted web traffic; sensitive data may be exposed."},
    110: {"service": "POP3",        "risk": "Medium", "reason": "Plaintext email retrieval."},
    135: {"service": "MS-RPC",      "risk": "High",   "reason": "Target of many Windows exploits (e.g., MS03-026)."},
    139: {"service": "NetBIOS",     "risk": "High",   "reason": "Legacy Windows sharing; vulnerable to enumeration."},
    143: {"service": "IMAP",        "risk": "Medium", "reason": "Plaintext email access if TLS not enforced."},
    443: {"service": "HTTPS",       "risk": "Low",    "reason": "Encrypted web traffic; verify certificate validity."},
    445: {"service": "SMB",         "risk": "High",   "reason": "EternalBlue / WannaCry target; keep patched."},
    1433: {"service": "MSSQL",      "risk": "High",   "reason": "Database port exposed; risk of SQL injection & brute-force."},
    1521: {"service": "Oracle DB",  "risk": "High",   "reason": "Database port exposed to network."},
    3306: {"service": "MySQL",      "risk": "High",   "reason": "Database port should never be internet-facing."},
    3389: {"service": "RDP",        "risk": "High",   "reason": "BlueKeep target; brute-force & credential-stuffing risk."},
    4444: {"service": "Metasploit", "risk": "High",   "reason": "Default Metasploit reverse shell port."},
    5432: {"service": "PostgreSQL", "risk": "High",   "reason": "Database port exposed to network."},
    5900: {"service": "VNC",        "risk": "High",   "reason": "Remote desktop with weak default auth."},
    6379: {"service": "Redis",      "risk": "High",   "reason": "Often runs without authentication; RCE risk."},
    8080: {"service": "HTTP-Alt",   "risk": "Medium", "reason": "Alternate HTTP port; check for admin panels."},
    8443: {"service": "HTTPS-Alt",  "risk": "Low",    "reason": "Alternate HTTPS port."},
    27017: {"service": "MongoDB",   "risk": "High",   "reason": "Database exposed; often runs with no auth by default."},
}

COMMON_PORTS = list(RISKY_PORTS.keys()) + [
    20, 69, 111, 161, 389, 636, 989, 990, 993, 995,
    1080, 1194, 2049, 2181, 2375, 2376, 4000, 5000,
    5601, 6443, 7001, 8000, 8888, 9000, 9090, 9200,
    9300, 10250, 11211, 50000
]
COMMON_PORTS = sorted(set(COMMON_PORTS))

# ─────────────────────────────────────────────
#  SCANNER CORE
# ─────────────────────────────────────────────

def resolve_host(target: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Try to connect to a single port. Return info dict if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                risk_info = RISKY_PORTS.get(port, {
                    "service": "Unknown",
                    "risk": "Low",
                    "reason": "Non-standard port; investigate manually."
                })
                return {
                    "port": port,
                    "state": "open",
                    "service": risk_info["service"],
                    "risk": risk_info["risk"],
                    "reason": risk_info["reason"],
                    "banner": banner,
                }
    except Exception:
        pass
    return None


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Attempt a banner grab on the open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else "No banner"
    except Exception:
        return "No banner"


def run_nmap(target: str, ports: list) -> str:
    """Run nmap for OS/version detection if available."""
    try:
        port_str = ",".join(str(p) for p in ports)
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-p", port_str, target],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout
    except FileNotFoundError:
        return "nmap not installed — skipping advanced scan."
    except subprocess.TimeoutExpired:
        return "nmap scan timed out."
    except Exception as e:
        return f"nmap error: {e}"


def classify_overall_risk(open_ports: list) -> str:
    """Derive overall risk from all open ports."""
    risks = [p["risk"] for p in open_ports]
    if "High" in risks:
        return "High"
    if "Medium" in risks:
        return "Medium"
    return "Low"


def scan_target(target: str, port_list: list = None, threads: int = 100, timeout: float = 1.0) -> dict:
    """Full scan pipeline. Returns structured result dict."""
    print(f"\n[*] Resolving {target}...")
    ip = resolve_host(target)
    if not ip:
        print(f"[!] Could not resolve {target}")
        sys.exit(1)
    print(f"[*] Target IP  : {ip}")

    ports_to_scan = port_list or COMMON_PORTS
    print(f"[*] Scanning {len(ports_to_scan)} ports with {threads} threads...\n")

    open_ports = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports_to_scan}
        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            if result:
                open_ports.append(result)
                risk_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(result["risk"], "⚪")
                print(f"  {risk_color} Port {result['port']:>5}/tcp  OPEN  [{result['service']}]  Risk: {result['risk']}")

    open_ports.sort(key=lambda x: x["port"])

    # Optional nmap deep scan on open ports
    nmap_output = ""
    if open_ports:
        print("\n[*] Running nmap service scan on open ports...")
        nmap_output = run_nmap(ip, [p["port"] for p in open_ports])

    overall_risk = classify_overall_risk(open_ports) if open_ports else "Low"

    scan_result = {
        "target": target,
        "ip": ip,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ports_scanned": len(ports_to_scan),
        "open_count": len(open_ports),
        "overall_risk": overall_risk,
        "open_ports": open_ports,
        "nmap_output": nmap_output,
        "summary": build_summary(open_ports),
    }

    return scan_result


def build_summary(open_ports: list) -> dict:
    """Count findings by risk level."""
    summary = {"High": 0, "Medium": 0, "Low": 0}
    for p in open_ports:
        summary[p["risk"]] = summary.get(p["risk"], 0) + 1
    return summary


# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────

def save_json_report(result: dict, filename: str = None) -> str:
    """Save raw scan results as JSON."""
    if not filename:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", result["target"])
        filename = f"report_{safe}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return filename


def generate_html_report(result: dict, filename: str = None) -> str:
    """Inject scan data into the dashboard HTML template."""
    if not filename:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", result["target"])
        filename = f"report_{safe}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    # Read template
    template_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if not os.path.exists(template_path):
        print("[!] dashboard.html not found — skipping HTML report.")
        return None

    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Inject JSON data into the template
    json_data = json.dumps(result, indent=2)
    injection = f"<script>window.SCAN_DATA = {json_data};</script>"
    html = html.replace("<!-- SCAN_DATA_INJECTION -->", injection)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


# ─────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────

def print_banner():
    print("""
╔═══════════════════════════════════════════════╗
║         CyberScan — Vulnerability Scanner     ║
║         Internship Project  •  Python + Nmap  ║
╚═══════════════════════════════════════════════╝
""")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="CyberScan: Port Scanner & Vulnerability Reporter"
    )
    parser.add_argument("target", help="Target hostname or IP (e.g. scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Comma-separated ports or range (e.g. 22,80,443 or 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--html", action="store_true", help="Generate HTML dashboard report")
    parser.add_argument("-o", "--output", help="Output filename (without extension)")
    args = parser.parse_args()

    # Parse ports
    port_list = None
    if args.ports:
        port_list = []
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))

    # Run scan
    result = scan_target(args.target, port_list, args.threads, args.timeout)

    # Print summary
    print(f"""
╔══════════════ SCAN SUMMARY ══════════════╗
  Target         : {result['target']} ({result['ip']})
  Scan Time      : {result['scan_time']}
  Ports Scanned  : {result['ports_scanned']}
  Open Ports     : {result['open_count']}
  Overall Risk   : {result['overall_risk']}
  High Risk      : {result['summary']['High']}
  Medium Risk    : {result['summary']['Medium']}
  Low Risk       : {result['summary']['Low']}
╚══════════════════════════════════════════╝
""")

    # Save reports
    base = args.output or f"report_{re.sub(r'[^a-zA-Z0-9_-]', '_', result['target'])}"

    if args.json or not args.html:
        json_file = save_json_report(result, f"{base}.json")
        print(f"[✓] JSON report saved → {json_file}")

    if args.html:
        html_file = generate_html_report(result, f"{base}.html")
        if html_file:
            print(f"[✓] HTML report saved → {html_file}")
            print(f"[*] Open in browser: file://{os.path.abspath(html_file)}")


if __name__ == "__main__":
    main()
