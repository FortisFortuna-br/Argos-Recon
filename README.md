# 🔍 Recon Tool V11 — Advanced Web Reconnaissance Framework

> **⚠️ LEGAL NOTICE: This tool is intended for authorized security testing only. Only use against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.**

---

## 🚀 What is Recon Tool V11?

A fast, modular, async-powered web reconnaissance framework built for bug bounty hunters and penetration testers. Combines 25+ modules into a single automated pipeline.

## ✨ Features

| Module | Description |
|--------|-------------|
| 🛡️ Security Headers | CSP, HSTS, X-Frame-Options analysis |
| 🍪 Cookie Analysis | HttpOnly, Secure, SameSite flag detection |
| 🌐 Subdomain Enum | crt.sh + HackerTarget + DNS brute force |
| 🔓 Port Scanning | Async TCP scan on 25 common ports |
| 📜 JS Analysis | Secret scanning, endpoint extraction, source maps |
| 🪣 S3 Bucket Check | Passive misconfiguration detection |
| 🐙 GitHub Dorking | Credential leak detection via GitHub API |
| ⚡ Nuclei Integration | Auto-runs Nuclei if installed |
| 🧩 Parameter Discovery | HTML forms + JS + Wayback URL extraction |
| 📸 Screenshot | Playwright-based visual capture |
| 🔀 Open Redirect | Automated parameter testing |
| 🔨 HTTP Methods | PUT/DELETE/TRACE fuzzing |
| 🗺️ Wayback Machine | Historical endpoint extraction |
| 🤖 Robots/Sitemap | Path harvesting |
| 🔐 SSL Analysis | Certificate info extraction |
| 📧 Email Harvesting | From HTML + JS |
| 💥 CVE Hints | Technology-based CVE suggestions |
| 🔁 CORS Testing | Origin reflection detection |
| 🕵️ WAF Detection | Cloudflare, Akamai, Sucuri, etc. |
| 🧬 Tech Fingerprint | 30+ technology signatures |
| 🌍 DNS Records | A, AAAA, MX, TXT, NS, SOA |
| 📂 Directory Brute | 60+ sensitive path checks |
| 🗂️ GraphQL Probe | Introspection detection |
| 📋 Executive Summary | Risk score + severity breakdown |
| 📊 HTML/JSON Report | Full professional output |

---

## ⚙️ Speed System

```
--speed 100   🐢 STEALTH   — Very slow, hard to detect
--speed 500   🚶 CAREFUL   — Slow and safe
--speed 1000  🚗 NORMAL    — Default balanced speed
--speed 2000  ✈️ AGGRESSIVE — Fast, use carefully
--speed 5000  ☢️ MAXIMUM   — Full speed, may trigger WAF
```

---

## 📦 Installation

```bash
git clone https://github.com/FortisFortuna-br/Argos-Recon
cd recon-v11
pip install -r requirements.txt
```

### requirements.txt
```
httpx[http2]
beautifulsoup4
rich
aiodns
```

### Optional (for extra features)
```bash
# Screenshot support
pip install playwright
playwright install chromium

# Nuclei integration
# Download from: https://github.com/projectdiscovery/nuclei/releases
```

---

## 🔧 Usage

```bash
# Basic scan
python Argos.py -u example.com

# Fast scan with HTML report
python Argos.py -u example.com --speed 2000 --html

# Stealth scan
python Argos.py -u example.com --speed 100

# With GitHub dorking
python Argos.py -u example.com --github-token ghp_yourtoken

# With screenshot
python Argos.py -u example.com --screenshot

# With Nuclei
python Argos.py -u example.com --nuclei-path /usr/local/bin/nuclei

# With User Flag
python Argos.py -u example.com --speed 500 --html --h1-user (Your Flag username)

# Multiple targets from file
python Argos.py -f targets.txt --speed 1000 --html

# Full options
python Argos.py -u example.com \
  --speed 1000 \
  --html \
  --github-token ghp_xxx \
  --screenshot \
  --nuclei-path nuclei \
  --depth 3 \
  --timeout 15
```

---

## 📊 Example Output

```
╭─────────────────── Scan Summary ───────────────────╮
│ Target: https://example.com                         │
│ Status: 200 | Response Time: 0.342s                 │
│ Speed: 1000 | Severity: HIGH | Risk Score: 28       │
│ CRIT:1  HIGH:4  MED:8  LOW:12                       │
╰─────────────────────────────────────────────────────╯

📊 Statistics:
  • JS Files: 12
  • Endpoints: 47
  • Subdomains: 23
  • Open Ports: 4 [80, 443, 8080, 8443]
  • Secrets Found: 2
  • Emails Found: 5
  • Parameters Discovered: 89
  • S3 Findings: 1
  • CVE Hints: 3
```

---

## 🏗️ Architecture

```
recon-v11/
├── recon.py              # Main tool
├── README.md
├── LICENSE
├── requirements.txt
└── reports/              # Auto-generated reports
    ├── example_com_*.json
    └── example_com_*.html
```

---

## ⚖️ Legal & Ethical Use

This tool is provided for **educational and authorized security testing purposes only**.

**You MUST:**
- Only scan systems you own or have **explicit written authorization** to test
- Comply with the terms of bug bounty programs (scope, rules of engagement)
- Follow responsible disclosure practices

**This tool does NOT:**
- Write data to any system (no PUT/DELETE operations)
- Exploit vulnerabilities — detection only
- Bypass authentication

The author is **not responsible** for any misuse or illegal use of this tool. Using this tool against systems without authorization is illegal under laws including but not limited to:
- Turkey: TCK 243-244
- USA: Computer Fraud and Abuse Act (CFAA)
- EU: Directive on Attacks Against Information Systems

---

## 🤝 Contributing

PRs welcome. Please open an issue first for major changes.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file.

---

## 👤 Author

Made with ❤️ for the bug bounty community.

*If this tool helped you find a bug, a ⭐ star is appreciated!*
