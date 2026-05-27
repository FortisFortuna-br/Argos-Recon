# Argos is going SaaS

> **TL;DR** — Argos is getting a web platform. No more CLI setup, no dependency hell. Just sign in and scan.

---

## What's happening

Argos started as a single-file CLI recon tool. In one week it got **500 views and 300 clones** on GitHub — which told me people actually want this.

So I'm building the full web platform.

## What the SaaS version looks like

- **Sign up → Scan → Get a report.** That's it. No Python environment, no pip install, no Windows asyncio quirks.
- Scans run on dedicated servers. Results show up in your browser as a formatted report with severity-color-coded findings, attack chain correlation, CVE hints, and download options (JSON / HTML / PDF).
- **Queue system** — scans are processed in order, priority by tier. Free users wait a bit longer; Pro and Enterprise go first.
- **API access** for Enterprise users — pipe Argos into your own toolchain via REST.

## Tiers

| Tier | Scans/day | Formats | Priority |
|------|-----------|---------|----------|
| Free | 1 | JSON | Standard queue |
| Pro ($20/mo) | 10 | JSON + HTML | High priority |
| Enterprise ($50/mo) | Unlimited | JSON + HTML + PDF | Top priority + API key |

## What Argos checks (V12)

51 scan modules. All passive. No third-party service dependencies. Runs everything itself.

Highlights: WAF fingerprinting · SSL/TLS analysis · Subdomain enumeration via cert transparency · S3 bucket misconfiguration · GitHub dorking · CORS testing · JWT analysis · DOM XSS sink detection · Prototype pollution patterns · Clickjacking · Cache poisoning · HTTP request smuggling indicators · DNSSEC · OAuth/OIDC analysis · Email security (SPF/DKIM/DMARC) · Finding chain correlation · **SSRF surface mapping** · **Web cache deception detection** · **PostMessage security scanning** · and more.

## Rules this tool will always follow

1. **No external tool integrations** (no Shodan, no Censys, nothing). Fully self-contained.
2. **No active exploits.** Passive detection only — Argos finds, it doesn't touch.

These two rules are permanent. The value of this tool is that it's independent and safe to run against targets you're authorized to test.

## Timeline

The CLI tool keeps getting updated on this repo.
The web platform is in active development — ETA when it's ready.

---

Star the repo if you want to follow along. Issues and feature requests are open.
