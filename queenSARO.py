#!/usr/bin/env python3
"""
SARO QUEEN - Integrated Security Recon & Report Framework
Usage: sudo python3 saro_queen.py <target-domain>
Platform: Kali Linux (All 30 modules from original bash script)
"""

import sys
import os
import subprocess
import re
import json
from datetime import datetime

# --- Terminal Color Configurations ---
RED = '\033[0;31m'
BOLD_RED = '\033[1;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
RESET = '\033[0m'

BANNER_TEXT = f"""{BOLD_RED}
 ██████  █████  ██████   ██████       ██████  ██    ██ ███████ ███████ ███    ██ 
██      ██   ██ ██   ██ ██    ██     ██    ██ ██    ██ ██      ██      ████   ██ 
███████ ███████ ██████  ██    ██     ██    ██ ██    ██ █████   █████   ██ ██  ██ 
     ██ ██   ██ ██   ██ ██    ██     ██ ▄▄ ██ ██    ██ ██      ██      ██  ██ ██ 
███████ ██   ██ ██   ██  ██████       ██████   ██████  ███████ ███████ ██   ████ 
                                         ▀▀                                      
{RED}             [+] WARNING: SARO QUEEN IS WATCHING YOU... [+]{RESET}
"""

if len(sys.argv) < 2:
    print(BANNER_TEXT)
    print(f"{YELLOW}Usage: sudo python3 {sys.argv[0]} <domain>{RESET}")
    sys.exit(1)

TARGET = sys.argv[1].strip()
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTDIR = f"recon_{TARGET}_{TIMESTAMP}"
LOGDIR = os.path.join(OUTDIR, "raw_logs")
REPORT_TXT = os.path.join(OUTDIR, "FULL_REPORT.txt")
OUT_HTML = os.path.join(OUTDIR, "report.html")

# Initialize Directories
os.makedirs(LOGDIR, exist_ok=True)
report_file = open(REPORT_TXT, "w")

def log_and_print(text, section_mode=False, warn_mode=False):
    """Handles runtime logging to stdout and the document simultaneously"""
    if section_mode:
        print(f"\n{GREEN}[+] {text}{RESET}")
        report_file.write(f"\n\n========== {text} ==========\n")
    elif warn_mode:
        print(f"  {RED}⚠ {text}{RESET}")
        report_file.write(f"  ⚠ {text}\n")
    else:
        print(f"  {CYAN}→{RESET} {text}")
        report_file.write(f"  → {text}\n")

def check_tool(tool_name):
    """Validates binary presence on the system"""
    return subprocess.call(f"command -v {tool_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run_command(cmd, log_name):
    """Executes level shell tools and stores the raw response streams"""
    log_path = os.path.join(LOGDIR, log_name)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        with open(log_path, "w") as lf:
            lf.write(result.stdout + "\n" + result.stderr)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "[!] Execution context exceeded timeout limitation."
    except Exception as e:
        return f"[!] Exception occurred: {str(e)}"

# --- Begin Execution Pipeline ---
print(BANNER_TEXT)
log_and_print(f"MEGA RECON — {TARGET}")
report_file.write(f"Target: {TARGET}\n")
report_file.write(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# 1. WHOIS
log_and_print("1. WHOIS — Registrar & Ownership", section_mode=True)
whois_out = run_command(f"whois {TARGET}", "whois.txt")
for line in whois_out.splitlines():
    if any(k in line.lower() for k in ["registrar:", "registrant", "creation", "expir", "updated", "name server", "status", "country", "email", "phone", "org"]):
        log_and_print(line.strip())

# 2. DNS RECORDS
log_and_print("2. DNS Records — A / AAAA / MX / TXT / NS / SOA / CNAME", section_mode=True)
run_command(f"dig ANY {TARGET}", "dns_any.txt")
for r_type in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]:
    res = subprocess.getoutput(f"dig +short {r_type} {TARGET}").strip()
    if res:
        log_and_print(f"{r_type}: {res.replace('\n', ', ')}")
    else:
        log_and_print(f"{r_type}: (none)")

# 3. IP & GEO
log_and_print("3. IP Resolution & Geolocation", section_mode=True)
ip_addr = subprocess.getoutput(f"dig +short A {TARGET} | head -1").strip()
log_and_print(f"Primary IP: {ip_addr}")
if ip_addr:
    geo_raw = run_command(f"curl -s https://ipapi.co/{ip_addr}/json/", "geo.json")
    try:
        geo = json.loads(geo_raw)
        log_and_print(f"Country:    {geo.get('country_name', 'Unknown')}")
        log_and_print(f"City:       {geo.get('city', 'Unknown')}")
        log_and_print(f"ISP/Org:    {geo.get('org', 'Unknown')}")
        log_and_print(f"ASN:        {geo.get('asn', 'Unknown')}")
        log_and_print(f"Timezone:   {geo.get('timezone', 'Unknown')}")
    except:
        log_and_print("Failed to parse Geolocation remote endpoint response.")

# 4. REVERSE DNS
log_and_print("4. Reverse DNS (PTR)", section_mode=True)
if ip_addr:
    ptr = subprocess.getoutput(f"dig +short -x {ip_addr}").strip()
    log_and_print(f"PTR Record: {ptr if ptr else '(none)'}")

# 5. SUBDOMAIN ENUMERATION
log_and_print("5. Subdomain Enumeration", section_mode=True)
if check_tool("sublist3r"):
    run_command(f"sublist3r -d {TARGET} -o {LOGDIR}/subdomains.txt -t 50", "sublist3r.log")
    sub_path = os.path.join(LOGDIR, "subdomains.txt")
    if os.path.exists(sub_path):
        with open(sub_path) as sf:
            subs = sf.read().splitlines()
        log_and_print(f"Subdomains found: {len(subs)}")
        for s in subs[:20]: log_and_print(f"  {s}")
else:
    log_and_print("Fallback: brute-forcing common subdomains...")
    for sub in ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "portal", "cdn", "blog", "shop", "test"]:
        res = subprocess.getoutput(f"dig +short A {sub}.{TARGET}").strip()
        if res: log_and_print(f"{sub}.{TARGET} → {res}")

# 6. HTTP HEADERS
log_and_print("6. HTTP Response Headers", section_mode=True)
headers = run_command(f"curl -sI https://{TARGET}", "headers.txt")
for line in headers.splitlines():
    if line.strip(): log_and_print(line.strip())

# 7. TECHNOLOGY STACK
log_and_print("7. Technology Stack Detection (WhatWeb)", section_mode=True)
if check_tool("whatweb"):
    ww = run_command(f"whatweb -a 3 https://{TARGET}", "whatweb.txt")
    for line in ww.splitlines(): log_and_print(line.strip())
else:
    log_and_print("WhatWeb tool not found.", warn_mode=True)

# 8. SSL/TLS CERTIFICATE
log_and_print("8. SSL/TLS Certificate Info", section_mode=True)
ssl_info = run_command(f"echo | openssl s_client -connect {TARGET}:443 -servername {TARGET} 2>/dev/null | openssl x509 -noout -text", "ssl.txt")
for line in ssl_info.splitlines():
    if any(k in line for k in ["Subject:", "Issuer:", "Not Before", "Not After", "DNS:", "Serial"]):
        log_and_print(line.strip())

# 9. SSL VULNERABILITIES
log_and_print("9. SSL/TLS Vulnerabilities (sslyze)", section_mode=True)
if check_tool("sslyze"):
    sslyze_out = run_command(f"sslyze --regular {TARGET}:443", "sslyze.txt")
    for line in sslyze_out.splitlines():
        if any(k in line for k in ["WARN", "ERROR", "OK", "TLS", "Heartbleed", "ROBOT", "BEAST", "POODLE", "cipher"]):
            log_and_print(line.strip())
elif check_tool("sslscan"):
    sslscan_out = run_command(f"sslscan {TARGET}", "sslscan.txt")
    for line in sslscan_out.splitlines():
        if any(k in line for k in ["Heartbleed", "POODLE", "accepted", "preferred", "TLS", "SSLv"]):
            log_and_print(line.strip())
else:
    log_and_print("Neither sslyze nor sslscan found.", warn_mode=True)

# 10. WAF DETECTION
log_and_print("10. WAF / CDN Detection (wafw00f)", section_mode=True)
if check_tool("wafw00f"):
    waf = run_command(f"wafw00f https://{TARGET}", "waf.txt")
    for line in waf.splitlines():
        if line.strip(): log_and_print(line.strip())
else:
    log_and_print("Wafw00f tool not found.", warn_mode=True)

# 11. PORT SCAN — TOP 1000
log_and_print("11. Nmap Port Scan — Top 1000 Ports", section_mode=True)
if check_tool("nmap"):
    nm = run_command(f"nmap -sS -sV --open -T4 --top-ports 1000 {TARGET}", "nmap_top1000.txt")
    for line in nm.splitlines():
        if any(k in line for k in ["open", "filtered", "Service", "OS"]):
            log_and_print(line.strip())
else:
    log_and_print("Nmap tool not found.", warn_mode=True)

# 12. FULL PORT SCAN (Background Process Simulation)
log_and_print("12. Nmap Full Port Scan (1-65535)", section_mode=True)
log_and_print(f"Running full port scan in background → {LOGDIR}/nmap_full.txt")
if check_tool("nmap"):
    # Executing as an asynchronous process to simulate original background execution behavior
    full_scan_proc = subprocess.Popen(f"nmap -sS -p- -T4 --min-rate 5000 {TARGET} -oN {LOGDIR}/nmap_full.txt", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
else:
    full_scan_proc = None
    log_and_print("Nmap not available for background mapping.", warn_mode=True)

# 13. OS DETECTION
log_and_print("13. OS + Service Version Detection (Nmap -A)", section_mode=True)
if check_tool("nmap"):
    nmap_os = run_command(f"nmap -A -T4 {TARGET}", "nmap_os.txt")
    for line in nmap_os.splitlines():
        if any(k in line for k in ["OS", "Service", "Version", "Running", "CPE", "open"]):
            log_and_print(line.strip())

# 14. VULNERABILITY SCAN
log_and_print("14. Nmap Vuln Scripts", section_mode=True)
if check_tool("nmap"):
    nmap_vuln = run_command(f"nmap --script vuln {TARGET}", "nmap_vuln.txt")
    for line in nmap_vuln.splitlines():
        if any(k in line for k in ["VULNERABLE", "CVE", "EXPLOIT", "State", "Risk"]):
            log_and_print(line.strip(), warn_mode=True)

# 15. NIKTO WEB SCAN
log_and_print("15. Nikto Web Vulnerability Scan", section_mode=True)
if check_tool("nikto"):
    nikto_out = run_command(f"nikto -h https://{TARGET}", "nikto.txt")
    count = 0
    for line in nikto_out.splitlines():
        if line.startswith("+") and count < 30:
            log_and_print(line.strip(), warn_mode=True)
            count += 1
else:
    log_and_print("Nikto tool not found.", warn_mode=True)

# 16. EMAIL HARVESTING
log_and_print("16. Email Harvesting (theHarvester)", section_mode=True)
if check_tool("theHarvester"):
    harvester_out = run_command(f"theHarvester -d {TARGET} -b all -l 200", "harvester.txt")
    for line in harvester_out.splitlines():
        if "@" in line or "IP:" in line:
            log_and_print(line.strip())
else:
    log_and_print("theHarvester tool not found.", warn_mode=True)

# 17. ROBOTS.TXT & SITEMAP
log_and_print("17. Robots.txt & Sitemap", section_mode=True)
log_and_print("--- robots.txt ---")
robots = run_command(f"curl -s https://{TARGET}/robots.txt", "robots.txt")
for line in robots.splitlines()[:30]:
    log_and_print(line.strip())
log_and_print("--- sitemap.xml ---")
sitemap = run_command(f"curl -s https://{TARGET}/sitemap.xml", "sitemap.xml")
matches = re.findall(r'loc>\K[^<]+', sitemap)
for m in matches[:20]:
    log_and_print(m)

# 18. SECURITY HEADERS
log_and_print("18. Security Headers Analysis", section_mode=True)
for H in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"]:
    match = re.search(f"^{H}:.*", headers, re.IGNORECASE | re.M)
    if match:
        log_and_print(f"✓ {match.group(0).strip()}")
    else:
        log_and_print(f"✗ MISSING: {H}", warn_mode=True)

# 19. SHODAN LOOKUP
log_and_print("19. Shodan Lookup", section_mode=True)
if check_tool("shodan") and ip_addr:
    shodan_out = run_command(f"shodan host {ip_addr}", "shodan.txt")
    for line in shodan_out.splitlines():
        log_and_print(line.strip())
else:
    log_and_print(f"Shodan CLI not configured — visit: https://www.shodan.io/host/{ip_addr}")

# 20. DNSRECON
log_and_print("20. DNSRecon — Zone Transfer & Enum", section_mode=True)
if check_tool("dnsrecon"):
    dr_std = run_command(f"dnsrecon -d {TARGET} -t std", "dnsrecon_std.txt")
    for line in dr_std.splitlines():
        if any(k in line for k in ["DST", "[*]", "SOA", "NS", "MX", "A", "CNAME"]):
            log_and_print(line.strip())
    log_and_print("Attempting Zone Transfer...")
    dr_axfr = run_command(f"dnsrecon -d {TARGET} -t axfr", "dnsrecon_axfr.txt")
    for line in dr_axfr.splitlines():
        if not line.startswith("["):
            log_and_print(line.strip(), warn_mode=True)

# 21. DNSX
log_and_print("21. DNSX — Wildcard & Record Check", section_mode=True)
if check_tool("dnsx"):
    dnsx_out = run_command(f"echo {TARGET} | dnsx -a -aaaa -cname -mx -ns -txt -ptr -resp", "dnsx.txt")
    for line in dnsx_out.splitlines():
        log_and_print(line.strip())

# 22. DIRECTORY BRUTEFORCE
log_and_print("22. Directory & File Bruteforce (gobuster/dirb)", section_mode=True)
wordlist = "/usr/share/wordlists/dirb/common.txt"
if not os.path.exists(wordlist):
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

if check_tool("gobuster") and os.path.exists(wordlist):
    gobuster_out = run_command(f"gobuster dir -u https://{TARGET} -w {wordlist} -t 50 -q", "gobuster.txt")
    for line in gobuster_out.splitlines()[:30]:
        log_and_print(line.strip())
elif check_tool("dirb") and os.path.exists(wordlist):
    dirb_out = run_command(f"dirb https://{TARGET} {wordlist} -S", "dirb.txt")
    for line in dirb_out.splitlines():
        if line.startswith("+"):
            log_and_print(line.strip())
else:
    log_and_print("Neither Gobuster nor Dirb wordlists were accessible.", warn_mode=True)

# 23. CMS DETECTION
log_and_print("23. CMS Detection", section_mode=True)
web_page = subprocess.getoutput(f"curl -sL https://{TARGET} | head -200")
is_wordpress = False
for cms in ["WordPress", "Joomla", "Drupal", "Magento", "Laravel", "Django", "Ruby on Rails", "Next.js"]:
    if re.search(cms, web_page, re.IGNORECASE):
        log_and_print(f"Detected: {cms}")
        if cms == "WordPress": is_wordpress = True

if check_tool("wpscan") and is_wordpress:
    log_and_print("Running WPScan...")
    wps = run_command(f"wpscan --url https://{TARGET} --no-update", "wpscan.txt")
    for line in wps.splitlines():
        if "[+]" in line or "[!]" in line:
            log_and_print(line.strip())

# 24. TRACEROUTE
log_and_print("24. Traceroute — Network Path", section_mode=True)
trace = run_command(f"traceroute -n {TARGET}", "traceroute.txt")
for line in trace.splitlines():
    log_and_print(line.strip())

# 25. CLOUDFLARE / CDN CHECK
log_and_print("25. CDN / Cloudflare Detection", section_mode=True)
cf_match = re.findall(r'(cf-ray|cloudflare|x-cdn|x-amz|fastly|akamai|incapsula)', headers, re.IGNORECASE)
if cf_match:
    log_and_print("CDN/WAF Detected:", warn_mode=True)
    for match in set(cf_match):
        log_and_print(f"  Detected Header Reference: {match}", warn_mode=True)
else:
    log_and_print("No obvious CDN headers detected — may be direct IP")

# 26. COMMON MISCONFIG ENDPOINTS
log_and_print("26. Common Misconfig Endpoints", section_mode=True)
endpoints = ["/.git/HEAD", "/.env", "/config.php", "/wp-config.php", "/admin", "/phpmyadmin", "/.htaccess", "/server-status", "/actuator", "/api/v1", "/.DS_Store", "/crossdomain.xml"]
for path in endpoints:
    code = subprocess.getoutput(f"curl -s -o /dev/null -w '%{{http_code}}' https://{TARGET}{path}").strip()
    if code == "200":
        log_and_print(f"ACCESSIBLE [{code}]: {TARGET}{path}", warn_mode=True)
    elif code in ["301", "302"]:
        log_and_print(f"REDIRECT  [{code}]: {TARGET}{path}")
    elif code == "403":
        log_and_print(f"FORBIDDEN [{code}]: {TARGET}{path}")

# 27. EMAIL SECURITY — SPF / DMARC / DKIM
log_and_print("27. Email Security — SPF / DMARC / DKIM", section_mode=True)
spf = subprocess.getoutput(f"dig +short TXT {TARGET} | grep spf").strip()
dmarc = subprocess.getoutput(f"dig +short TXT _dmarc.{TARGET}").strip()
dkim = subprocess.getoutput(f"dig +short TXT default._domainkey.{TARGET}").strip()
log_and_print(f"SPF:   {spf if spf else 'NOT CONFIGURED'}", warn_mode=not spf)
log_and_print(f"DMARC: {dmarc if dmarc else 'NOT CONFIGURED'}", warn_mode=not dmarc)
log_and_print(f"DKIM:  {dkim if dkim else 'NOT CONFIGURED'}", warn_mode=not dkim)

# 28. ASN & BGP
log_and_print("28. ASN / BGP Info", section_mode=True)
if ip_addr:
    asn_raw = subprocess.getoutput(f"curl -s https://api.bgpview.io/ip/{ip_addr}")
    try:
        asn_data = json.loads(asn_raw)
        prefixes = asn_data.get('data', {}).get('prefixes', [])
        for p in prefixes[:3]:
            log_and_print(f"ASN: {p['asn']['asn']} | Name: {p['asn']['name']} | Prefix: {p['prefix']}")
    except:
        log_and_print("BGP API reference structure not parsed successfully.")

# 29. PASTEBIN / BREACH CHECK (OSINT)
log_and_print("29. OSINT — Dork Queries (run manually)", section_mode=True)
log_and_print(f"Google dorks to run for {TARGET}:")
log_and_print(f"  site:{TARGET} filetype:pdf")
log_and_print(f"  site:{TARGET} filetype:sql OR filetype:log OR filetype:bak")
log_and_print(f"  site:{TARGET} inurl:admin OR inurl:login OR inurl:dashboard")
log_and_print(f"  \"{TARGET}\" site:pastebin.com")
log_and_print(f"  \"{TARGET}\" site:github.com")

# 30. SCAN SUMMARY
log_and_print("30. Scan Summary", section_mode=True)
log_and_print(f"Target:          {TARGET}")
log_and_print(f"IP:              {ip_addr}")
log_and_print(f"Output dir:      {OUTDIR}/")
log_and_print(f"Full report:     {REPORT_TXT}")

if full_scan_proc:
    log_and_print("Waiting for full background port scan verification layer to conclude...")
    full_scan_proc.wait()

log_and_print("Completed execution pipeline.")
report_file.close()

# --- Post-Processing & Automated HTML Compilation ---
with open(REPORT_TXT) as f:
    raw_data = f.read()

sections = re.split(r"\n={5,} (.+?) ={5,}\n", raw_data)
parsed_sections = []

for i in range(1, len(sections), 2):
    title = sections[i].strip()
    body = sections[i+1].strip() if i+1 < len(sections) else ""
    lines = body.split("\n")
    items = []
    for ln in lines:
        ln = ln.strip()
        if not ln: continue
        if ln.startswith("⚠"):
            items
