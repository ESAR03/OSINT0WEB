# 👑 SARO QUEEN

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu-red.svg)](https://www.kali.org)
[![Category](https://img.shields.io/badge/Category-Information%20Gathering-orange.svg)](https://github.com/)

**SARO QUEEN** is an advanced, high-performance Automated Reconnaissance & Security Auditing Framework written in Python 3. Designed specifically for Penetration Testers, Red Teamers, and Bug Bounty Hunters, it consolidates a multi-layered footprinting pipeline into a unified engine. 

Instead of jumping between dozens of terminal windows, **SARO QUEEN** orchestrates **30 critical modular phases** sequentially and asynchronously, outputting both structured raw logs and comprehensive consolidated security intelligence reports.

---

## 🚀 Key Architectural Features

* **Unified Tool Orchestration:** Seamlessly integrates industry-standard binaries (`nmap`, `sublist3r`, `whatweb`, `wafw00f`, `nikto`, `theHarvester`, `dnsrecon`, `dnsx`, `wpscan`).
* **Intelligent Resilient Fallbacks:** Contains native fallback mechanisms (e.g., active DNS brute-forcing) if third-party OSINT tools are missing or throttled.
* **Hybrid Execution Model:** Runs resource-intensive operations (like full 65535-port TCP scans) in asynchronous background sub-processes to guarantee optimal pipeline velocity.
* **Automated Defensive Control Profiling:** Instantly audits target environments for Content Delivery Networks (CDNs), Web Application Firewalls (WAFs), and missing critical HTTP Security Headers.
* **Dual-Format Reporting:** Automatically aggregates real-time stdout streams into structured raw logs (`/raw_logs`), an absolute plain-text master report, and a high-visibility HTML visual dashboard.

---

## 📊 Pipeline Matrix (30 Modules Mapping)

| # | Phase Category | Technical Mechanism / Tooling |
|---|---|---|
| **01-04** | **Core Footprinting** | WHOIS Registrar Parsing, Multicast DNS Record Enumeration (`dig`), Geolocation Endpoint Resolution, Reverse DNS Lookup (PTR). |
| **05-08** | **Infrastructure Intelligence** | Active/Passive Subdomain Discovery (`sublist3r`), HTTP Header Extraction, Technology Stack Fingerprinting (`whatweb`), SSL/TLS Certificate X.509 Parsing. |
| **09-12** | **Attack Surface Mapping** | Cryptographic Vulnerability Assessment (`sslyze`/`sslscan`), WAF/CDN Fingerprinting (`wafw00f`), Top-1000 Port Scanning & Full 65535-Port Async Discovery (`nmap`). |
| **13-16** | **Vulnerability & OSINT** | OS/Service Version Fingerprinting (`nmap -A`), NSE Vulnerability Scripting, Web Server Directory Auditing (`nikto`), Passive OSINT Email Harvesting (`theHarvester`). |
| **17-20** | **Spiders & Active Recon** | Endpoint Map Scraping (`robots.txt`/`sitemap.xml`), Defensive Security Header Compliance Checks, Passive Threat Intelligence Shodan API Queries, DNS Zone Transfer Auditing (`dnsrecon`). |
| **21-25** | **App-Layer Inspection** | Wildcard Resolution (`dnsx`), Multi-Threaded Directory Bruteforcing (`gobuster`/`dirb`), CMS/WordPress Signature Verification (`wpscan`), Network Path Traceroute, Active CDN Bypass Detection. |
| **26-30** | **Exposure Auditing** | High-Risk Misconfiguration Endpoint Probing (`/.env`, `/.git`, etc.), Email Trust Validation (SPF, DMARC, DKIM), ASN/BGP Routing Table Analytics, Auto-Generated Google Dork Vectors, Summary Matrix Generation. |

---

## 🛠️ Installation & Requirements

### System Requirements
* Operating System: **Kali Linux** (Recommended), Parrot OS, or Ubuntu Server.
* Permissions: **Root privileges (`sudo`)** required for raw socket manipulation via Nmap.

### Dependencies
Ensure system binaries are accessible within your native `$PATH`:
```bash
sudo apt update && sudo apt install -y nmap sublist3r whatweb wafw00f nikto theHarvester dnsrecon gobuster dirb openssl curl traceroute
