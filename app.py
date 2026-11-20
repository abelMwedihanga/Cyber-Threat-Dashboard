# Cyber Threat Dashboard - Abel Mwedihanga
# Combines Port Scanner + Phishing Checker + Log Analyzer into one Flask web app

from flask import Flask, render_template, request
import socket
import re
from urllib.parse import urlparse
from collections import Counter

app = Flask(__name__)

# ---------- 1. PORT SCANNER ----------
def scan_ports(host, ports=[21,22,23,25,53,80,110,443,3306,8080]):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            if s.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append({"port": port, "service": service})
        except:
            pass
        finally:
            s.close()
    return open_ports

# ---------- 2. PHISHING CHECKER ----------
def check_phishing(url):
    score = 0
    reasons = []
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)

    if parsed.scheme != "https":
        score += 2
        reasons.append("No HTTPS - not secure")
    if len(url) > 75:
        score += 1
        reasons.append("Very long URL")
    if "@" in url or "-" in parsed.netloc:
        score += 1
        reasons.append("Suspicious characters (@ or -) in URL")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 2
        reasons.append("Uses IP address instead of domain")
    if "login" in url.lower() or "verify" in url.lower() or "bank" in url.lower():
        score += 1
        reasons.append("Contains sensitive keywords: login/verify/bank")

    if score >= 4:
        result = "HIGH RISK - Likely Phishing"
        color = "red"
    elif score >= 2:
        result = "MEDIUM RISK - Be Careful"
        color = "orange"
    else:
        result = "LOW RISK - Looks Safe"
        color = "green"
    return {"url": url, "score": score, "result": result, "color": color, "reasons": reasons}

# ---------- 3. LOG ANALYZER ----------
def analyze_logs(log_text):
    lines = log_text.strip().split("\n")
    failed = 0
    ips = []
    for line in lines:
        if "Failed" in line or "failed" in line or "ERROR" in line:
            failed += 1
        # find IPs
        found = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        ips.extend(found)
    top_ips = Counter(ips).most_common(5)
    return {"total_lines": len(lines), "failed": failed, "top_ips": top_ips}

# ---------- ROUTES ----------
@app.route("/", methods=["GET", "POST"])
def index():
    port_result = None
    phishing_result = None
    log_result = None

    if request.method == "POST":
        form_type = request.form.get("form_type")

        if form_type == "port":
            host = request.form.get("host", "127.0.0.1")
            port_result = {"host": host, "ports": scan_ports(host)}

        if form_type == "phishing":
            url = request.form.get("url", "")
            phishing_result = check_phishing(url)

        if form_type == "logs":
            log_text = request.form.get("logs", "")
            if log_text:
                log_result = analyze_logs(log_text)

    return render_template("index.html",
                           port_result=port_result,
                           phishing_result=phishing_result,
                           log_result=log_result)

if __name__ == "__main__":
    app.run(debug=True)