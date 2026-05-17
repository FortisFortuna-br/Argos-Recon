#!/usr/bin/env python3
"""
Recon Tool V11 - Advanced Web Reconnaissance Framework
Refactored: Testable architecture, proper error handling, configurable SSL, modern asyncio
Enhancements: WAF bypass, cookie analysis, open redirect, HTTP fuzzing, CVE hints,
               email harvesting, DNS brute, source map download, wayback endpoint extraction,
               robots/sitemap parsing, executive summary, IP spoofing headers,
               S3 bucket misconfig checker, GitHub dorking, Nuclei integration,
               Parameter discovery, Screenshot capture
"""

import asyncio
import httpx
import json
import argparse
import re
import time
import random
import socket
import ssl
import logging
import sys
import subprocess
import shutil
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Optional, Dict, List, Set, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager

# Windows asyncio fix - must be before any asyncio usage
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

try:
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    import aiodns
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install beautifulsoup4 rich aiodns httpx")
    sys.exit(1)

# =============================================================================
# LOGGING SETUP
# =============================================================================

logger = logging.getLogger("recon")

class ReconError(Exception):
    pass

class NetworkError(ReconError):
    pass

class ConfigError(ReconError):
    pass

class ParseError(ReconError):
    pass

# =============================================================================
# CONSOLE (Injectable)
# =============================================================================

class ConsoleInterface(ABC):
    @abstractmethod
    def print(self, message: str, **kwargs) -> None:
        pass

    @abstractmethod
    def input(self, prompt: str) -> str:
        pass

class RichConsole(ConsoleInterface):
    def __init__(self):
        self._console = Console()

    def print(self, message: str, **kwargs) -> None:
        self._console.print(message, **kwargs)

    def input(self, prompt: str) -> str:
        return self._console.input(prompt)

    @property
    def raw(self) -> Console:
        return self._console

class SilentConsole(ConsoleInterface):
    def __init__(self):
        self.outputs: List[str] = []
        self.inputs: List[str] = []
        self._input_index = 0

    def print(self, message: str, **kwargs) -> None:
        self.outputs.append(message)

    def input(self, prompt: str) -> str:
        if self._input_index < len(self.inputs):
            result = self.inputs[self._input_index]
            self._input_index += 1
            return result
        return ""

    def set_inputs(self, inputs: List[str]) -> None:
        self.inputs = inputs
        self._input_index = 0

_console: ConsoleInterface = RichConsole()

def get_console() -> ConsoleInterface:
    return _console

def set_console(console: ConsoleInterface) -> None:
    global _console
    _console = console

BANNER = """
[bold red]
   ____                      
  / __ \\___  _________  ____ 
 / /_/ / _ \\/ ___/ __ \\/ __ \\
/ _, _/  __/ /__/ /_/ / / / /
/_/ |_|\\___/\\___/\\____/_/ /_/ 

    [cyan]Advanced Recon Tool V11[/cyan]
    [dim]Web Intelligence Framework[/dim]
    [yellow]S3 · GitHub Dork · Nuclei · Screenshot[/yellow]
[/bold red]
"""

# =============================================================================
# SPEED PRESETS
# =============================================================================

SPEED_PRESETS: Dict[int, Tuple[int, int, float, float, float, int, int, int, int, int]] = {
    100:   (3,   10,  25.0, 1.0,  3.0,  2, 10,  50,   20, 5),
    250:   (5,   15,  20.0, 0.5,  2.0,  2, 15,  75,   30, 4),
    500:   (8,   25,  18.0, 0.3,  1.5,  2, 20,  100,  40, 4),
    750:   (12,  35,  15.0, 0.2,  1.0,  3, 25,  125,  50, 3),
    1000:  (15,  50,  15.0, 0.1,  0.5,  3, 30,  150,  60, 3),
    1500:  (25,  75,  12.0, 0.05, 0.3,  3, 40,  200,  75, 3),
    2000:  (40,  100, 10.0, 0.02, 0.15, 4, 50,  250,  100, 2),
    2500:  (60,  150, 8.0,  0.01, 0.1,  4, 60,  300,  125, 2),
    3000:  (80,  200, 7.0,  0.005, 0.05, 5, 75, 400,  150, 2),
    4000:  (120, 300, 5.0,  0.0,  0.02, 5, 100, 500,  200, 1),
    5000:  (200, 500, 4.0,  0.0,  0.0,  6, 150, 750,  300, 1),
}

def get_speed_settings(speed: int) -> Tuple[int, int, float, float, float, int, int, int, int, int]:
    if speed in SPEED_PRESETS:
        return SPEED_PRESETS[speed]
    speeds = sorted(SPEED_PRESETS.keys())
    if speed < speeds[0]:
        return SPEED_PRESETS[speeds[0]]
    if speed > speeds[-1]:
        return SPEED_PRESETS[speeds[-1]]
    lower = max([s for s in speeds if s <= speed])
    upper = min([s for s in speeds if s >= speed])
    if lower == upper:
        return SPEED_PRESETS[lower]
    ratio = (speed - lower) / (upper - lower)
    low_settings = SPEED_PRESETS[lower]
    high_settings = SPEED_PRESETS[upper]
    interpolated: List[Any] = []
    for i in range(len(low_settings)):
        if isinstance(low_settings[i], int):
            interpolated.append(int(low_settings[i] + ratio * (high_settings[i] - low_settings[i])))
        else:
            interpolated.append(low_settings[i] + ratio * (high_settings[i] - low_settings[i]))
    return tuple(interpolated)  # type: ignore

def describe_speed(speed: int) -> str:
    if speed <= 100:
        return "🐢 STEALTH - Çok yavaş, tespit edilmesi zor"
    elif speed <= 250:
        return "🐌 SLOW - Yavaş ve dikkatli"
    elif speed <= 500:
        return "🚶 CAREFUL - Orta-yavaş, güvenli"
    elif speed <= 750:
        return "🚴 MODERATE - Dengeli hız"
    elif speed <= 1000:
        return "🚗 NORMAL - Varsayılan hız"
    elif speed <= 1500:
        return "🏎️ FAST - Hızlı tarama"
    elif speed <= 2000:
        return "✈️ AGGRESSIVE - Agresif, dikkatli ol"
    elif speed <= 2500:
        return "🚀 VERY AGGRESSIVE - Çok agresif"
    elif speed <= 3000:
        return "⚡ EXTREME - Aşırı hızlı"
    elif speed <= 4000:
        return "💥 INSANE - Çılgın hız, risk yüksek"
    else:
        return "☢️ MAXIMUM - Tam gaz! WAF/Rate-limit tetikleyebilir"

# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    max_concurrent: int = 15
    port_scan_concurrent: int = 50
    timeout: float = 15.0
    max_retries: int = 3
    max_depth: int = 3
    max_js_files: int = 30
    max_endpoints: int = 150
    max_subdomains: int = 60
    delay_min: float = 0.1
    delay_max: float = 0.5
    speed: int = 1000
    verify_ssl: bool = False
    github_token: Optional[str] = None
    nuclei_path: str = "nuclei"
    screenshot_enabled: bool = False
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    ])

    def apply_speed(self, speed: int) -> None:
        self.speed = max(100, min(5000, speed))
        settings = get_speed_settings(self.speed)
        self.max_concurrent = settings[0]
        self.port_scan_concurrent = settings[1]
        self.timeout = settings[2]
        self.delay_min = settings[3]
        self.delay_max = settings[4]
        self.max_depth = settings[5]
        self.max_js_files = settings[6]
        self.max_endpoints = settings[7]
        self.max_subdomains = settings[8]
        self.max_retries = settings[9]

    def copy(self) -> 'Config':
        return Config(
            max_concurrent=self.max_concurrent,
            port_scan_concurrent=self.port_scan_concurrent,
            timeout=self.timeout,
            max_retries=self.max_retries,
            max_depth=self.max_depth,
            max_js_files=self.max_js_files,
            max_endpoints=self.max_endpoints,
            max_subdomains=self.max_subdomains,
            delay_min=self.delay_min,
            delay_max=self.delay_max,
            speed=self.speed,
            verify_ssl=self.verify_ssl,
            github_token=self.github_token,
            nuclei_path=self.nuclei_path,
            screenshot_enabled=self.screenshot_enabled,
            user_agents=self.user_agents.copy(),
        )

def create_default_config() -> Config:
    return Config()

# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Finding:
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

@dataclass
class ReconResult:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    speed_used: int = 1000
    status_code: int = 0
    response_time: float = 0.0
    technology: Dict[str, Any] = field(default_factory=dict)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    wayback_urls: List[str] = field(default_factory=list)
    findings: List[Dict[str, str]] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    severity_score: str = "LOW"
    errors: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    cookies_analysis: List[Dict[str, Any]] = field(default_factory=list)
    open_redirect_findings: List[str] = field(default_factory=list)
    http_method_findings: List[Dict[str, Any]] = field(default_factory=list)
    cve_hints: List[Dict[str, str]] = field(default_factory=list)
    robots_paths: List[str] = field(default_factory=list)
    source_map_secrets: List[Dict[str, str]] = field(default_factory=list)
    executive_summary: Dict[str, Any] = field(default_factory=dict)
    # NEW fields
    s3_findings: List[Dict[str, Any]] = field(default_factory=list)
    github_dork_findings: List[Dict[str, Any]] = field(default_factory=list)
    nuclei_findings: List[Dict[str, Any]] = field(default_factory=list)
    discovered_parameters: List[str] = field(default_factory=list)
    screenshot_path: Optional[str] = None

# =============================================================================
# PATTERNS & SIGNATURES
# =============================================================================

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php", "/administrator",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/docs", "/api/swagger",
    "/graphql", "/graphql/playground", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/openapi.json", "/api-docs",
    "/config", "/configuration", "/settings", "/setup",
    "/backup", "/backups", "/db", "/database", "/dump",
    "/debug", "/test", "/testing", "/dev", "/development", "/staging",
    "/internal", "/private", "/secret", "/hidden",
    "/.env", "/.git", "/.git/config", "/.svn", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics", "/health",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/wp-json/wp/v2/users", "/wp-content/debug.log",
    "/.well-known/security.txt", "/security.txt",
    "/console", "/jmx-console", "/manager/html", "/solr/admin",
    "/elmah.axd", "/trace.axd", "/web.config",
    "/package.json", "/yarn.lock", "/package-lock.json",
    "/.DS_Store", "/.env.local", "/.env.production", "/.env.staging",
    "/composer.json", "/composer.lock",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.gitlab-ci.yml", "/.github/workflows", "/Jenkinsfile",
    "/nginx.conf", "/apache.conf", "/.well-known/",
]

FINGERPRINTS: Dict[str, List[Tuple[str, int]]] = {
    "wordpress": [
        ("wp-content", 4), ("wp-includes", 4), ("wp-json", 3), ("xmlrpc.php", 3)
    ],
    "laravel": [
        ("laravel_session", 4), ("XSRF-TOKEN", 2), ("_token", 2)
    ],
    "nextjs": [
        ("__NEXT_DATA__", 4), ("/_next/", 3), ("next/router", 3), ("__next", 2)
    ],
    "nuxtjs": [
        ("__NUXT__", 4), ("/_nuxt/", 3)
    ],
    "react": [
        ("__REACT_DEVTOOLS", 3), ("data-reactroot", 3), ("data-reactid", 3)
    ],
    "vue": [
        ("__VUE__", 3), ("v-cloak", 3), ("vue-router", 3), ("data-v-", 3)
    ],
    "angular": [
        ("ng-version", 4), ("ng-app", 3), ("ng-controller", 3)
    ],
    "django": [
        ("csrfmiddlewaretoken", 4), ("__admin", 2)
    ],
    "flask": [
        ("werkzeug", 3)
    ],
    "express": [
        ("x-powered-by: express", 4)
    ],
    "rails": [
        ("_rails", 3), ("csrf-token", 2)
    ],
    "spring": [
        ("jsessionid", 3), ("actuator", 3)
    ],
    "aspnet": [
        ("__viewstate", 4), ("asp.net", 3), ("__requestverificationtoken", 3)
    ],
    "drupal": [
        ("sites/default", 3), ("drupal.js", 4), ("Drupal.settings", 4)
    ],
    "joomla": [
        ("/media/system/", 3), ("com_content", 3), ("joomla", 3)
    ],
    "firebase": [
        ("firebasestorage.googleapis.com", 4), ("firebaseio.com", 4)
    ],
    "supabase": [
        (".supabase.co", 4)
    ],
    "aws": [
        ("s3.amazonaws.com", 4), ("cloudfront.net", 3), ("x-amz-request-id", 3)
    ],
    "cloudflare": [
        ("cf-ray", 4), ("__cfduid", 3), ("cf-cache-status", 3)
    ],
    "vercel": [
        ("x-vercel-id", 4), ("vercel.app", 3)
    ],
    "netlify": [
        ("x-nf-request-id", 4), (".netlify.app", 3)
    ],
    "graphql": [
        ("__schema", 4), ("__typename", 3)
    ],
    "strapi": [
        ("strapi", 3)
    ],
    "shopify": [
        ("myshopify.com", 4), ("cdn.shopify.com", 4)
    ],
    "jenkins": [
        ("x-jenkins", 4), ("Jenkins-Crumb", 3), ("jenkins", 2)
    ],
    "tomcat": [
        ("apache tomcat", 4), ("catalina", 3)
    ],
    "nginx": [
        ("nginx", 3)
    ],
    "apache": [
        ("apache", 3), ("mod_", 2)
    ],
}

CVE_HINTS: Dict[str, List[Dict[str, str]]] = {
    "wordpress": [
        {"cve": "CVE-2023-5561", "desc": "WordPress < 6.4.2: Privilege escalation via user meta"},
        {"cve": "CVE-2022-21661", "desc": "WordPress < 5.8.3: SQL injection via WP_Query"},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600", "desc": "Drupalgeddon2: Remote Code Execution"},
        {"cve": "CVE-2019-6340", "desc": "Drupal REST RCE without auth"},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129", "desc": "Laravel Debug mode RCE via Ignition"},
        {"cve": "CVE-2018-15133", "desc": "Laravel token unserialize RCE"},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "desc": "Spring4Shell: Spring MVC RCE"},
        {"cve": "CVE-2022-22963", "desc": "Spring Cloud Function SpEL injection"},
    ],
    "express": [
        {"cve": "CVE-2022-24999", "desc": "qs prototype pollution in Express"},
    ],
    "rails": [
        {"cve": "CVE-2019-5418", "desc": "Rails File Content Disclosure via Accept header"},
        {"cve": "CVE-2020-8164", "desc": "Rails strong params bypass"},
    ],
    "jenkins": [
        {"cve": "CVE-2024-23897", "desc": "Jenkins < 2.442: Arbitrary file read via CLI"},
        {"cve": "CVE-2023-27898", "desc": "Jenkins XSS leading to RCE"},
    ],
    "tomcat": [
        {"cve": "CVE-2025-24813", "desc": "Tomcat partial PUT RCE"},
        {"cve": "CVE-2020-1938", "desc": "Ghostcat: AJP file read/inclusion"},
    ],
    "graphql": [
        {"cve": "N/A", "desc": "GraphQL introspection enabled: schema enumeration risk"},
    ],
}

SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key": r"(?i)(?:aws_secret_access_key|aws_secret)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z/+=]{40})['\"]",
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Client ID": r"\b[0-9]{12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
    "JWT Token": r"\beyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b",
    "Stripe Live Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Test Secret Key": r"\bsk_test_[0-9a-zA-Z]{24,}\b",
    "Stripe Publishable Key": r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b",
    "Slack Token": r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "GitHub Personal Access Token": r"\bghp_[A-Za-z0-9_]{36,}\b",
    "GitHub OAuth Token": r"\bgho_[A-Za-z0-9]{36}\b",
    "GitHub App Token": r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b",
    "GitLab Personal Access Token": r"\bglpat-[A-Za-z0-9\-]{20,}\b",
    "Firebase Database URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Private Key Header": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "MongoDB Connection String": r"mongodb(\+srv)?://[^\s\"'<>]{10,}",
    "PostgreSQL Connection String": r"postgres(ql)?://[^\s\"'<>]{10,}",
    "MySQL Connection String": r"mysql://[^\s\"'<>]{10,}",
    "Redis Connection String": r"redis://[^\s\"'<>]{10,}",
    "Discord Bot Token": r"\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b",
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "SendGrid API Key": r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
    "Mailgun API Key": r"\bkey-[0-9a-zA-Z]{32}\b",
    "Anthropic API Key": r"\bsk-ant-[A-Za-z0-9\-_]{40,}\b",
    "OpenAI API Key": r"\bsk-[A-Za-z0-9]{48}\b",
    "Mapbox Token": r"\bpk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
}

TAKEOVER_SIGNATURES: Dict[str, List[str]] = {
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Heroku": ["herokucdn.com/error-pages/no-such-app.html"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Surge.sh": ["project not found"],
    "Fastly": ["Fastly error: unknown domain"],
    "Zendesk": ["Help Center Closed"],
    "Webflow": ["The page you are looking for doesn't exist or has been moved"],
    "Fly.io": ["404 Not Found"],
    "Render": ["Not Found"],
}

SECURITY_HEADERS: Dict[str, Dict[str, str]] = {
    "Content-Security-Policy": {
        "description": "CSP - Mitigates XSS attacks",
        "severity": "HIGH",
        "remediation": "Implement a strict Content-Security-Policy header"
    },
    "Strict-Transport-Security": {
        "description": "HSTS - Forces HTTPS connections",
        "severity": "HIGH",
        "remediation": "Add Strict-Transport-Security header with max-age >= 31536000"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "LOW",
        "remediation": "Set X-Content-Type-Options to nosniff"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter",
        "severity": "LOW",
        "remediation": "Set X-XSS-Protection to 1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "severity": "LOW",
        "remediation": "Set Referrer-Policy to strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "severity": "LOW",
        "remediation": "Implement Permissions-Policy to restrict unnecessary features"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "COOP - Isolates browsing context",
        "severity": "LOW",
        "remediation": "Set Cross-Origin-Opener-Policy to same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "CORP - Protects resources",
        "severity": "LOW",
        "remediation": "Set Cross-Origin-Resource-Policy appropriately"
    },
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
                8888, 9000, 9200, 9443, 27017]

DNS_BRUTE_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "app", "dashboard", "portal", "internal", "vpn", "remote", "cdn", "static",
    "media", "img", "images", "blog", "shop", "store", "secure", "login",
    "auth", "id", "sso", "oauth", "mx", "smtp", "pop", "imap", "ns1", "ns2",
    "m", "mobile", "ws", "socket", "monitor", "status", "ci", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "docs", "support", "help", "kb",
    "data", "analytics", "metrics", "grafana", "kibana", "elastic", "s3",
    "backup", "old", "new", "v1", "v2", "uat", "qa", "preview", "sandbox",
]

OPEN_REDIRECT_PARAMS = [
    "redirect", "return", "url", "next", "goto", "dest", "destination",
    "redirect_uri", "redirect_url", "return_url", "returnUrl", "redirectTo",
    "callback", "r", "u", "link", "target",
]
OPEN_REDIRECT_PAYLOAD = "https://evil-recon-test.com"

HTTP_METHODS_TO_FUZZ = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD", "CONNECT"]

# GitHub dork queries
GITHUB_DORK_QUERIES = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" credentials',
    '"{domain}" .env',
    '"{domain}" config',
    'site:{domain} password',
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")


def normalize_crawl_url(base_url: str, href: str) -> Optional[str]:
    try:
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        normalized = urlunparse((
            parsed.scheme, parsed.netloc,
            parsed.path or "/", "", parsed.query, ""
        ))
        return normalized
    except Exception:
        return None


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


def get_random_ua(config: Config) -> str:
    return random.choice(config.user_agents)


def get_waf_bypass_headers() -> Dict[str, str]:
    fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return {
        "X-Forwarded-For": fake_ip,
        "X-Real-IP": fake_ip,
        "X-Originating-IP": fake_ip,
        "X-Remote-IP": fake_ip,
        "X-Client-IP": fake_ip,
        "CF-Connecting-IP": fake_ip,
        "True-Client-IP": fake_ip,
    }


async def smart_delay(config: Config) -> None:
    if config.delay_max > 0:
        delay = random.uniform(config.delay_min, config.delay_max)
        if delay > 0:
            await asyncio.sleep(delay)


def calculate_severity(findings: List[Finding]) -> str:
    severity_weights = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
    total = sum(severity_weights.get(f.severity, 0) for f in findings)
    if total >= 20:
        return "CRITICAL"
    elif total >= 12:
        return "HIGH"
    elif total >= 6:
        return "MEDIUM"
    elif total >= 2:
        return "LOW"
    return "INFO"


def is_valid_secret(secret_type: str, value: str) -> bool:
    if not value or len(value) < 8:
        return False
    false_positive_patterns = [
        r"^[0-9]+$",
        r"^[a-f0-9]+$" if len(value) < 20 else None,
        r"^(example|test|demo|sample|placeholder|your|my|xxx|aaa|123)",
    ]
    value_lower = value.lower()
    for pattern in false_positive_patterns:
        if pattern and re.match(pattern, value_lower, re.IGNORECASE):
            return False
    if len(set(value)) < len(value) / 3:
        return False
    return True


def extract_emails(content: str) -> List[str]:
    pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    found = set(re.findall(pattern, content))
    filtered = []
    ignore_domains = {"example.com", "test.com", "domain.com", "email.com", "sentry.io"}
    for email in found:
        domain_part = email.split("@")[-1].lower()
        if domain_part not in ignore_domains and not email.endswith((".png", ".jpg", ".js", ".css")):
            filtered.append(email)
    return filtered[:50]

# =============================================================================
# ASYNC HTTP CLIENT
# =============================================================================

class AsyncHTTPClient:
    def __init__(self, config: Config):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
        self.client: Optional[httpx.AsyncClient] = None
        self._waf_backoff: float = 0.0

    async def __aenter__(self) -> 'AsyncHTTPClient':
        self.client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(self.config.timeout),
            verify=self.config.verify_ssl,
            limits=httpx.Limits(max_connections=self.config.max_concurrent * 2),
            http2=True,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self.client:
            await self.client.aclose()

    def _build_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {"User-Agent": get_random_ua(self.config)}
        headers.update(get_waf_bypass_headers())
        if extra:
            headers.update(extra)
        return headers

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True
    ) -> Optional[httpx.Response]:
        merged_headers = self._build_headers(headers)

        async with self.semaphore:
            if self._waf_backoff > 0:
                await asyncio.sleep(self._waf_backoff)

            await smart_delay(self.config)
            last_error: Optional[Exception] = None

            for attempt in range(self.config.max_retries):
                try:
                    start = time.time()
                    response = await self.client.get(
                        url, headers=merged_headers, follow_redirects=allow_redirects
                    )
                    elapsed_time = round(time.time() - start, 3)
                    response.elapsed_time = elapsed_time  # type: ignore[attr-defined]

                    if response.status_code in [429, 503]:
                        retry_after = response.headers.get("Retry-After")
                        backoff = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt * 5)
                        backoff = min(backoff, 60.0)
                        self._waf_backoff = backoff
                        await asyncio.sleep(backoff)
                        merged_headers["User-Agent"] = get_random_ua(self.config)
                        merged_headers.update(get_waf_bypass_headers())
                        continue
                    else:
                        self._waf_backoff = max(0.0, self._waf_backoff - 1.0)

                    return response

                except httpx.TimeoutException as e:
                    last_error = e
                    await asyncio.sleep((2 ** attempt) + random.uniform(0, 1))
                except httpx.ConnectError as e:
                    last_error = e
                    await asyncio.sleep((2 ** attempt) + random.uniform(0, 1))
                except httpx.RemoteProtocolError as e:
                    last_error = e
                    await asyncio.sleep((2 ** attempt) + random.uniform(0, 1))
                except Exception as e:
                    logger.warning(f"Unexpected error on GET {url}: {type(e).__name__}: {e}")
                    return None

            return None

    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[httpx.Response]:
        merged_headers = self._build_headers(headers)
        async with self.semaphore:
            await smart_delay(self.config)
            try:
                return await self.client.post(
                    url, data=data, json=json_data, headers=merged_headers
                )
            except Exception:
                return None

    async def head(self, url: str) -> Optional[httpx.Response]:
        async with self.semaphore:
            await smart_delay(self.config)
            try:
                return await self.client.head(url, headers=self._build_headers())
            except Exception:
                return None

    async def request(self, method: str, url: str, **kwargs: Any) -> Optional[httpx.Response]:
        async with self.semaphore:
            await smart_delay(self.config)
            try:
                headers = self._build_headers(kwargs.pop("headers", None))
                return await self.client.request(method, url, headers=headers, **kwargs)
            except Exception as e:
                logger.debug(f"Method {method} error on {url}: {e}")
                return None


@asynccontextmanager
async def create_http_client(config: Config):
    client = AsyncHTTPClient(config)
    async with client:
        yield client

# =============================================================================
# RECONNAISSANCE MODULES (ORIGINAL)
# =============================================================================

class DNSRecon:
    def __init__(self):
        self.resolver: Optional[aiodns.DNSResolver] = None
        self._init_lock: Optional[asyncio.Lock] = None

    def _get_lock(self) -> asyncio.Lock:
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        return self._init_lock

    async def init_resolver(self) -> bool:
        async with self._get_lock():
            if self.resolver is not None:
                return True
            try:
                self.resolver = aiodns.DNSResolver()
                return True
            except Exception as e:
                logger.warning(f"Failed to initialize DNS resolver: {e}")
                return False

    async def get_records(self, domain: str) -> Dict[str, List[str]]:
        if not await self.init_resolver():
            return {}
        records: Dict[str, List[str]] = defaultdict(list)
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                result = await self.resolver.query(domain, rtype)
                if rtype == 'MX':
                    records[rtype] = [f"{r.host} (priority: {r.priority})" for r in result]
                elif rtype == 'TXT':
                    records[rtype] = [r.text for r in result]
                elif rtype == 'SOA':
                    records[rtype] = [f"{result.nsname} {result.hostmaster}"]
                elif rtype in ['NS', 'CNAME']:
                    records[rtype] = [r.host for r in result]
                else:
                    records[rtype] = [r.host for r in result]
            except Exception:
                pass
        return dict(records)

    async def brute_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> Set[str]:
        if not await self.init_resolver():
            return set()
        if wordlist is None:
            wordlist = DNS_BRUTE_WORDLIST
        found: Set[str] = set()

        async def check_sub(word: str) -> Optional[str]:
            subdomain = f"{word}.{domain}"
            try:
                await self.resolver.query(subdomain, 'A')
                return subdomain
            except Exception:
                return None

        sem = asyncio.Semaphore(20)

        async def bounded_check(word: str) -> Optional[str]:
            async with sem:
                return await check_sub(word)

        results = await asyncio.gather(*[bounded_check(w) for w in wordlist], return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                found.add(r)
        return found


class SubdomainFinder:
    @staticmethod
    async def from_crtsh(client: AsyncHTTPClient, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await client.get(url)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and "*" not in sub and domain in sub:
                                subdomains.add(sub)
                except Exception:
                    pass
        except Exception:
            pass
        return subdomains

    @staticmethod
    async def from_hackertarget(client: AsyncHTTPClient, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = await client.get(url)
            if response and response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub and domain in sub:
                            subdomains.add(sub)
        except Exception:
            pass
        return subdomains


class PortScanner:
    def __init__(self, config: Config):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.port_scan_concurrent)

    async def check_port(self, host: str, port: int, timeout: float = 3.0) -> bool:
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

    async def scan(self, host: str, ports: Optional[List[int]] = None) -> List[int]:
        if ports is None:
            ports = COMMON_PORTS
        tasks = [self.check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [port for port, result in zip(ports, results) if result is True]


class WaybackMachine:
    @staticmethod
    async def get_urls(client: AsyncHTTPClient, domain: str, limit: int = 100) -> List[str]:
        urls: List[str] = []
        try:
            api_url = (
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/..."
                f"?url=*.{domain}/*&output=json&collapse=urlkey&limit={limit}&fl=original"
            )
            response = await client.get(api_url)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for row in data[1:]:
                        if row:
                            urls.append(row[0])
                except Exception:
                    pass
        except Exception:
            pass
        return urls

    @staticmethod
    def extract_endpoints_from_urls(urls: List[str]) -> Set[str]:
        endpoints: Set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                if path and path != "/" and len(path) > 1:
                    endpoints.add(path)
            except Exception:
                pass
        return endpoints


class SSLAnalyzer:
    @staticmethod
    async def analyze(domain: str, port: int = 443) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            loop = asyncio.get_running_loop()

            def get_cert() -> Optional[Dict[str, Any]]:
                try:
                    with socket.create_connection((domain, port), timeout=10) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            return ssock.getpeercert(binary_form=False)
                except Exception:
                    return None

            cert = await loop.run_in_executor(None, get_cert)
            if cert:
                info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                }
        except Exception:
            pass
        return info


class TechnologyDetector:
    @staticmethod
    def detect(headers: httpx.Headers, body: str, cookies: str = "") -> Dict[str, Any]:
        scores: Dict[str, int] = defaultdict(int)
        detected: List[Dict[str, Any]] = []
        body_lower = body.lower()
        headers_str = str(headers).lower()
        cookies_lower = cookies.lower()
        combined = body_lower + headers_str + cookies_lower

        for tech, patterns in FINGERPRINTS.items():
            for keyword, weight in patterns:
                if keyword.lower() in combined:
                    scores[tech] += weight

        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        for tech, score in sorted_scores[:8]:
            if score >= 3:
                detected.append({
                    "name": tech,
                    "confidence": round(min(score / 10, 1.0), 2),
                    "score": score
                })

        waf: Optional[str] = None
        waf_signatures = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "akamai": ["x-akamai"],
            "sucuri": ["x-sucuri-id"],
            "incapsula": ["x-cdn: incapsula"],
            "aws_waf": ["x-amzn-requestid"],
            "fastly": ["x-fastly"],
            "varnish": ["x-varnish"],
        }
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_str:
                    waf = waf_name
                    break
            if waf:
                break

        return {
            "technologies": detected,
            "waf": waf,
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
        }

    @staticmethod
    def get_cve_hints(technology_result: Dict[str, Any]) -> List[Dict[str, str]]:
        hints: List[Dict[str, str]] = []
        seen: Set[str] = set()
        for tech in technology_result.get("technologies", []):
            name = tech.get("name", "").lower()
            if name in CVE_HINTS:
                for cve in CVE_HINTS[name]:
                    key = cve["cve"]
                    if key not in seen:
                        seen.add(key)
                        hints.append({"tech": name, "cve": cve["cve"], "description": cve["desc"]})
        return hints


class SecurityHeadersAnalyzer:
    @staticmethod
    def analyze(headers: httpx.Headers) -> Tuple[Dict[str, Any], List[Finding]]:
        findings: List[Finding] = []
        result: Dict[str, Any] = {"present": {}, "missing": [], "misconfigured": []}

        for header, info in SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                result["present"][header] = value
                if header == "Content-Security-Policy":
                    if "unsafe-inline" in value.lower() and "unsafe-eval" in value.lower():
                        result["misconfigured"].append({"header": header, "issue": "Contains unsafe-inline and unsafe-eval"})
                        findings.append(Finding(
                            category="Security Headers", severity="MEDIUM",
                            title=f"Weak {header}",
                            description="CSP contains both unsafe-inline and unsafe-eval",
                            evidence=value[:200]
                        ))
                elif header == "Strict-Transport-Security":
                    match = re.search(r"max-age=(\d+)", value)
                    if match and int(match.group(1)) < 31536000:
                        findings.append(Finding(
                            category="Security Headers", severity="LOW",
                            title=f"Weak {header}",
                            description=f"HSTS max-age is {match.group(1)}, recommended minimum is 31536000",
                            evidence=value
                        ))
            else:
                result["missing"].append(header)
                if info["severity"] in ["HIGH", "MEDIUM"]:
                    findings.append(Finding(
                        category="Security Headers", severity=info["severity"],
                        title=f"Missing {header}",
                        description=info["description"],
                        remediation=info["remediation"]
                    ))

        powered_by = headers.get("X-Powered-By")
        if powered_by:
            findings.append(Finding(
                category="Information Disclosure", severity="LOW",
                title="X-Powered-By Header Present",
                description="Server technology information is exposed",
                evidence=powered_by
            ))

        cors = headers.get("Access-Control-Allow-Origin")
        acac = headers.get("Access-Control-Allow-Credentials")
        if cors == "*":
            severity = "MEDIUM" if acac and acac.lower() == "true" else "LOW"
            findings.append(Finding(
                category="CORS", severity=severity,
                title="Permissive CORS Configuration",
                description="Access-Control-Allow-Origin is set to wildcard",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to specific trusted origins"
            ))

        return result, findings


class CookieAnalyzer:
    @staticmethod
    def analyze(response: httpx.Response) -> Tuple[List[Dict[str, Any]], List[Finding]]:
        findings: List[Finding] = []
        cookie_details: List[Dict[str, Any]] = []

        set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        if not set_cookie_headers:
            raw = response.headers.get("set-cookie")
            if raw:
                set_cookie_headers = [raw]

        for cookie_str in set_cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_value = parts[0].split("=", 1)
            name = name_value[0].strip()
            flags_lower = cookie_str.lower()

            detail: Dict[str, Any] = {
                "name": name,
                "httponly": "httponly" in flags_lower,
                "secure": "secure" in flags_lower,
                "samesite": None,
            }
            sm = re.search(r"samesite=(\w+)", flags_lower)
            if sm:
                detail["samesite"] = sm.group(1)
            cookie_details.append(detail)

            if not detail["httponly"]:
                findings.append(Finding(
                    category="Cookie Security", severity="MEDIUM",
                    title=f"Cookie Missing HttpOnly: {name}",
                    description="Cookie without HttpOnly flag is accessible via JavaScript",
                    evidence=cookie_str[:150],
                    remediation="Add HttpOnly flag to all session cookies"
                ))
            if not detail["secure"]:
                findings.append(Finding(
                    category="Cookie Security", severity="MEDIUM",
                    title=f"Cookie Missing Secure Flag: {name}",
                    description="Cookie can be transmitted over unencrypted HTTP",
                    evidence=cookie_str[:150],
                    remediation="Add Secure flag to all cookies"
                ))
            if not detail["samesite"]:
                findings.append(Finding(
                    category="Cookie Security", severity="LOW",
                    title=f"Cookie Missing SameSite: {name}",
                    description="Cookie without SameSite may be vulnerable to CSRF",
                    evidence=cookie_str[:150],
                    remediation="Add SameSite=Strict or SameSite=Lax to cookies"
                ))

        return cookie_details, findings


class SubdomainTakeoverChecker:
    @staticmethod
    def check(body: str, headers: Optional[httpx.Headers] = None) -> List[Finding]:
        findings: List[Finding] = []
        body_lower = body.lower()
        for service, signatures in TAKEOVER_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body_lower and len(body) < 50000:
                    findings.append(Finding(
                        category="Subdomain Takeover", severity="HIGH",
                        title=f"Potential {service} Takeover",
                        description=f"Response contains signature indicating unclaimed {service} resource",
                        evidence=sig[:100],
                        remediation="Verify resource ownership and claim or remove the subdomain"
                    ))
                    break
        return findings


class SecretScanner:
    @staticmethod
    def scan(content: str, source: str = "") -> List[Dict[str, str]]:
        secrets: List[Dict[str, str]] = []
        seen_values: Set[str] = set()
        for name, pattern in SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else (match[1] if len(match) > 1 else "")
                    if isinstance(match, str) and len(match) >= 8 and match not in seen_values:
                        seen_values.add(match)
                        if is_valid_secret(name, match):
                            secrets.append({
                                "type": name,
                                "value": match[:50] + "..." if len(match) > 50 else match,
                                "source": source
                            })
            except re.error:
                pass
        return secrets


class EndpointExtractor:
    JS_PATTERNS = [
        r'["\'](/api/[^"\'?\s#]{1,200})["\']',
        r'["\'](/v[0-9]+/[^"\'?\s#]{1,200})["\']',
        r'["\'](/graphql[^"\'?\s#]{0,50})["\']',
        r'["\'](/internal/[^"\'?\s#]{1,200})["\']',
        r'["\'](/admin/[^"\'?\s#]{1,200})["\']',
        r'fetch\s*\(\s*["\']([^"\']{1,300})["\']',
        r'axios\s*\.\s*\w+\s*\(\s*["\']([^"\']{1,300})["\']',
        r'\.ajax\s*\(\s*\{\s*url\s*:\s*["\']([^"\']{1,300})["\']',
    ]

    @staticmethod
    def extract(content: str) -> Set[str]:
        endpoints: Set[str] = set()
        for pattern in EndpointExtractor.JS_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, str):
                        match = match.strip()
                        if (match and not match.startswith(("data:", "#", "javascript:", "mailto:"))
                                and not match.endswith((".png", ".jpg", ".css", ".woff", ".ico"))
                                and len(match) < 500 and len(match) > 1):
                            endpoints.add(match)
            except re.error:
                pass
        return endpoints


class RobotsParser:
    @staticmethod
    async def parse_robots(client: AsyncHTTPClient, base_url: str) -> List[str]:
        paths: List[str] = []
        try:
            response = await client.get(urljoin(base_url, "/robots.txt"))
            if response and response.status_code == 200 and "text/plain" in response.headers.get("content-type", ""):
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/":
                                paths.append(path)
        except Exception:
            pass
        return list(set(paths))[:100]

    @staticmethod
    async def parse_sitemap(client: AsyncHTTPClient, base_url: str) -> List[str]:
        urls: List[str] = []
        try:
            response = await client.get(urljoin(base_url, "/sitemap.xml"))
            if response and response.status_code == 200:
                found = re.findall(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", response.text)
                urls.extend(found[:100])
        except Exception:
            pass
        return urls


class OpenRedirectTester:
    @staticmethod
    async def test(client: AsyncHTTPClient, base_url: str, endpoints: List[str]) -> List[str]:
        vulnerable: List[str] = []
        test_urls: List[str] = []
        for param in OPEN_REDIRECT_PARAMS:
            test_urls.append(f"{base_url}?{param}={OPEN_REDIRECT_PAYLOAD}")
        for ep in endpoints[:20]:
            if ep.startswith("/"):
                full = urljoin(base_url, ep)
                for param in OPEN_REDIRECT_PARAMS[:5]:
                    test_urls.append(f"{full}?{param}={OPEN_REDIRECT_PAYLOAD}")

        sem = asyncio.Semaphore(5)

        async def check_redirect(url: str) -> Optional[str]:
            async with sem:
                try:
                    response = await client.get(url, allow_redirects=False)
                    if response and response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("location", "")
                        if OPEN_REDIRECT_PAYLOAD in location or "evil-recon-test.com" in location:
                            return url
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*[check_redirect(u) for u in test_urls[:50]], return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                vulnerable.append(r)
        return vulnerable


class HTTPMethodFuzzer:
    @staticmethod
    async def fuzz(client: AsyncHTTPClient, base_url: str, paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if paths is None:
            paths = ["/", "/api", "/api/v1", "/admin", "/login"]
        interesting: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(10)

        async def check_method(path: str, method: str) -> Optional[Dict[str, Any]]:
            async with sem:
                url = urljoin(base_url, path)
                try:
                    response = await client.request(method, url)
                    if response and response.status_code not in [404, 405, 501]:
                        return {"method": method, "path": path, "url": url, "status": response.status_code}
                except Exception:
                    pass
                return None

        tasks = [check_method(path, method) for path in paths[:10] for method in HTTP_METHODS_TO_FUZZ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                interesting.append(r)
        return interesting


class JSAnalyzer:
    SOURCE_MAP_PATTERN = r'//[#@]\s*sourceMappingURL=([^\s]+)'

    @staticmethod
    async def analyze(client: AsyncHTTPClient, js_files: List[str], config: Config) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "endpoints": set(), "secrets": [], "source_maps": [],
            "source_map_secrets": [], "interesting": [],
            "domains": set(), "s3_buckets": set(), "emails": [],
        }

        for js_url in js_files[:config.max_js_files]:
            try:
                response = await client.get(js_url)
                if not response or response.status_code != 200:
                    continue
                content = response.text
                if len(content) > 5_000_000:
                    continue

                results["endpoints"].update(EndpointExtractor.extract(content))
                results["secrets"].extend(SecretScanner.scan(content, js_url))
                results["emails"].extend(extract_emails(content))

                source_maps = re.findall(JSAnalyzer.SOURCE_MAP_PATTERN, content)
                for sm in source_maps:
                    sm = sm.strip()
                    if not sm.startswith("data:"):
                        full_map_url = urljoin(js_url, sm)
                        results["source_maps"].append(full_map_url)
                        map_resp = await client.get(full_map_url)
                        if map_resp and map_resp.status_code == 200:
                            results["source_map_secrets"].extend(
                                SecretScanner.scan(map_resp.text, full_map_url)
                            )

                domains = re.findall(r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
                for d in domains:
                    d_lower = d.lower()
                    if any(kw in d_lower for kw in ["internal", "dev.", "staging.", "admin.", "api.", "test."]):
                        results["domains"].add(d)

                s3_matches = re.findall(
                    r'([a-zA-Z0-9][a-zA-Z0-9.-]{2,62})\.s3[.-](?:amazonaws\.com|[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com)',
                    content
                )
                results["s3_buckets"].update(s3_matches)

            except Exception as e:
                logger.warning(f"Error analyzing JS file {js_url}: {e}")

        return {
            "endpoints": list(results["endpoints"])[:config.max_endpoints],
            "secrets": results["secrets"],
            "source_maps": results["source_maps"],
            "source_map_secrets": results["source_map_secrets"],
            "interesting": results["interesting"],
            "internal_domains": list(results["domains"]),
            "s3_buckets": list(results["s3_buckets"]),
            "emails": list(set(results["emails"])),
        }


class GraphQLProbe:
    INTROSPECTION_QUERY = '{"query": "{ __schema { queryType { name } types { name kind } } }"}'

    @staticmethod
    async def probe(client: AsyncHTTPClient, endpoints: List[str], base_url: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        graphql_paths = list(set(["/graphql", "/graphql/", "/api/graphql", "/v1/graphql"] +
                                  [ep for ep in endpoints if "graphql" in ep.lower()]))
        for path in graphql_paths[:10]:
            try:
                url = urljoin(base_url, path)
                response = await client.post(
                    url,
                    json_data={"query": "{ __schema { queryType { name } types { name kind } } }"},
                    headers={"Content-Type": "application/json"}
                )
                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        if data and isinstance(data, dict) and "data" in data and "__schema" in str(data["data"]):
                            results.append({
                                "url": url, "introspection_enabled": True,
                                "types_count": len(data.get("data", {}).get("__schema", {}).get("types", []))
                            })
                    except Exception:
                        pass
            except Exception:
                pass
        return results


class DirectoryBruter:
    @staticmethod
    async def brute(client: AsyncHTTPClient, base_url: str, paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if paths is None:
            paths = COMMON_PATHS
        results: List[Dict[str, Any]] = []

        async def check_path(path: str) -> Optional[Dict[str, Any]]:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, allow_redirects=False)
                if response and response.status_code not in [404, 503, 502, 500]:
                    content_length = len(response.content)
                    if response.status_code in [200, 301, 302, 307, 308, 401, 403] and content_length > 0:
                        return {"path": path, "url": url, "status": response.status_code, "length": content_length}
            except Exception:
                pass
            return None

        results_raw = await asyncio.gather(*[check_path(p) for p in paths], return_exceptions=True)
        for r in results_raw:
            if isinstance(r, dict):
                results.append(r)
        return results


class CORSTester:
    @staticmethod
    async def test(client: AsyncHTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        domain = get_domain(url)
        test_origins = [
            "https://evil.com", "https://attacker.com", "null",
            f"https://{domain}.evil.com", f"https://evil.{domain}",
        ]
        for origin in test_origins:
            try:
                response = await client.get(url, headers={"Origin": origin})
                if response:
                    acao = response.headers.get("Access-Control-Allow-Origin")
                    acac = response.headers.get("Access-Control-Allow-Credentials")
                    if acao and acao == origin and origin != "null":
                        severity = "HIGH" if acac and acac.lower() == "true" else "MEDIUM"
                        findings.append(Finding(
                            category="CORS", severity=severity,
                            title="CORS Origin Reflection",
                            description=f"Server reflects attacker-controlled origin: {origin}",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Implement strict origin validation for CORS"
                        ))
                        break
            except Exception:
                pass
        return findings


class Crawler:
    def __init__(self, client: AsyncHTTPClient, config: Config):
        self.client = client
        self.config = config
        self.visited: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.found_js: Set[str] = set()
        self.found_emails: Set[str] = set()

    async def crawl(self, start_url: str) -> Tuple[Set[str], Set[str]]:
        queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        await queue.put((start_url, 0))
        base_domain = get_domain(start_url)

        while not queue.empty() and len(self.visited) < 100:
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                break

            normalized_url = normalize_crawl_url(url, url)
            if normalized_url:
                url = normalized_url

            if depth > self.config.max_depth or url in self.visited:
                continue
            self.visited.add(url)

            try:
                response = await self.client.get(url)
                if not response or response.status_code != 200:
                    continue
                if "text/html" not in response.headers.get("content-type", "").lower():
                    continue

                self.found_emails.update(extract_emails(response.text))
                soup = BeautifulSoup(response.text, "html.parser")

                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    full_url = normalize_crawl_url(url, href)
                    if not full_url:
                        continue
                    parsed = urlparse(full_url)
                    if (parsed.scheme in ["http", "https"] and
                            parsed.netloc == base_domain and
                            full_url not in self.visited):
                        self.found_urls.add(full_url)
                        if depth + 1 <= self.config.max_depth:
                            await queue.put((full_url, depth + 1))

                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    if src:
                        full_url = urljoin(url, src)
                        if full_url.endswith(".js") or ".js?" in full_url:
                            self.found_js.add(full_url)

            except Exception as e:
                logger.debug(f"Crawl error for {url}: {e}")

        return self.found_urls, self.found_js

# =============================================================================
# NEW MODULE 1: S3 BUCKET MISCONFIG CHECKER
# =============================================================================

class S3BucketChecker:
    """
    Anonim S3 bucket misconfiguration tespiti.
    Bucket adlarını JS analizi ve subdomain'lerden çıkarır,
    public listable durumunu ve izin header'larını pasif olarak test eder.
    NOT: Aktif yazma (PUT/DELETE) yapılmaz — yasal uyumluluk için
         izin tespiti yalnızca OPTIONS ve response header analizi ile yapılır.
    """

    S3_URL_PATTERNS = [
        "https://{bucket}.s3.amazonaws.com/",
        "https://s3.amazonaws.com/{bucket}/",
        "https://{bucket}.s3-website.us-east-1.amazonaws.com/",
        "https://{bucket}.s3-website-us-east-1.amazonaws.com/",
    ]

    @staticmethod
    def extract_bucket_names(
        domain: str,
        subdomains: List[str],
        js_buckets: List[str],
        body: str
    ) -> Set[str]:
        """Birden fazla kaynaktan bucket adları toplar"""
        buckets: Set[str] = set()

        # JS analizinden gelenler
        buckets.update(js_buckets)

        # HTML body'den
        patterns = [
            r'([a-zA-Z0-9][a-zA-Z0-9.\-]{2,62})\.s3[.\-](?:amazonaws\.com|[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com)',
            r's3\.amazonaws\.com/([a-zA-Z0-9][a-zA-Z0-9.\-]{2,62})',
            r's3-[a-z]+-[0-9]+\.amazonaws\.com/([a-zA-Z0-9][a-zA-Z0-9.\-]{2,62})',
        ]
        for pat in patterns:
            found = re.findall(pat, body, re.IGNORECASE)
            buckets.update(found)

        # Domain bazlı tahminler
        domain_base = domain.split(".")[0]
        guesses = [
            domain_base, f"{domain_base}-backup", f"{domain_base}-static",
            f"{domain_base}-assets", f"{domain_base}-media", f"{domain_base}-files",
            f"{domain_base}-uploads", f"{domain_base}-dev", f"{domain_base}-staging",
            f"{domain_base}-prod", f"{domain_base}-data", f"{domain_base}-logs",
            f"{domain_base}-public", f"{domain_base}-private",
        ]
        buckets.update(guesses)

        # Subdomainlerden (s3.* veya bucket.* prefix içerenler)
        for sub in subdomains:
            sub_parts = sub.split(".")
            if len(sub_parts) > 0:
                buckets.add(sub_parts[0])

        return {b for b in buckets if b and len(b) >= 3}

    @staticmethod
    async def check_bucket(client: AsyncHTTPClient, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Tek bir bucket'ı pasif olarak test et"""
        result: Dict[str, Any] = {
            "bucket": bucket_name,
            "url": "",
            "listable": False,
            "writable": False,
            "exists": False,
            "status": "",
            "files_preview": [],
            "severity": "INFO",
        }

        test_url = f"https://{bucket_name}.s3.amazonaws.com/"
        result["url"] = test_url

        try:
            response = await client.get(test_url)
            if not response:
                return None

            if response.status_code == 200:
                result["exists"] = True
                content = response.text

                # Public listable kontrol
                if "<ListBucketResult" in content or "<Key>" in content:
                    result["listable"] = True
                    result["status"] = "PUBLIC_LISTABLE"
                    result["severity"] = "CRITICAL"

                    # İlk 10 dosyayı al
                    keys = re.findall(r"<Key>(.*?)</Key>", content)
                    result["files_preview"] = keys[:10]

                else:
                    result["exists"] = True
                    result["status"] = "EXISTS_NOT_LISTABLE"
                    result["severity"] = "LOW"

            elif response.status_code == 403:
                result["exists"] = True
                result["status"] = "EXISTS_ACCESS_DENIED"
                result["severity"] = "LOW"

                # Aktif yazma yerine OPTIONS ile izin header'larını pasif kontrol et
                write_indicated = await S3BucketChecker._check_write_headers(client, test_url)
                if write_indicated:
                    result["writable"] = True
                    result["status"] = "WRITE_INDICATED_BY_HEADERS"
                    result["severity"] = "HIGH"

            elif response.status_code == 404:
                # Bucket yok veya farklı region
                return None

            elif response.status_code == 301:
                # Region yönlendirmesi
                location = response.headers.get("location", "")
                if location:
                    result["exists"] = True
                    result["url"] = location
                    result["status"] = "REGION_REDIRECT"
                    result["severity"] = "INFO"

                    # Yönlendirilen URL'i test et
                    redir_resp = await client.get(location)
                    if redir_resp and redir_resp.status_code == 200:
                        if "<ListBucketResult" in redir_resp.text:
                            result["listable"] = True
                            result["status"] = "PUBLIC_LISTABLE"
                            result["severity"] = "CRITICAL"
                            keys = re.findall(r"<Key>(.*?)</Key>", redir_resp.text)
                            result["files_preview"] = keys[:10]
            else:
                return None

            return result

        except Exception as e:
            logger.debug(f"S3 check error for {bucket_name}: {e}")
            return None

    @staticmethod
    async def _check_write_headers(client: AsyncHTTPClient, bucket_url: str) -> bool:
        """
        Bucket yazma iznini YALNIZCA OPTIONS header'larından pasif olarak tespit et.
        Hiçbir veri yazılmaz veya silinmez — sadece izin header'ları okunur.
        Bu yaklaşım SQLMap mantığıyla aynıdır: tespit eder, exploit etmez.
        """
        try:
            response = await client.request("OPTIONS", bucket_url)
            if not response:
                return False

            # AWS S3 OPTIONS yanıtında izin verilen metodları kontrol et
            allow_header = response.headers.get("allow", "").upper()
            amz_allow = response.headers.get("x-amz-allow-methods", "").upper()
            access_control_allow = response.headers.get("access-control-allow-methods", "").upper()
            combined = " ".join([allow_header, amz_allow, access_control_allow])

            # PUT veya yazma izni varsa potansiyel write açığı
            if any(method in combined for method in ["PUT", "POST", "DELETE", "WRITE"]):
                logger.debug(f"Write methods indicated by OPTIONS headers for {bucket_url}: {combined}")
                return True

            # 200 döndü ama allow header'da write yok → güvenli
            return False

        except Exception as e:
            logger.debug(f"OPTIONS check error for {bucket_url}: {e}")
            return False

    @staticmethod
    async def run(
        client: AsyncHTTPClient,
        domain: str,
        subdomains: List[str],
        js_buckets: List[str],
        body: str
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:

        bucket_names = S3BucketChecker.extract_bucket_names(domain, subdomains, js_buckets, body)
        findings: List[Finding] = []
        s3_results: List[Dict[str, Any]] = []

        # Max 30 bucket test et
        sem = asyncio.Semaphore(5)

        async def bounded_check(name: str) -> Optional[Dict[str, Any]]:
            async with sem:
                return await S3BucketChecker.check_bucket(client, name)

        results = await asyncio.gather(
            *[bounded_check(b) for b in list(bucket_names)[:30]],
            return_exceptions=True
        )

        for r in results:
            if isinstance(r, dict) and r.get("exists"):
                s3_results.append(r)

                if r["severity"] == "CRITICAL":
                    title = (f"S3 Bucket Public Listable: {r['bucket']}"
                             if r["listable"] else f"S3 Bucket Write Indicated: {r['bucket']}")
                    evidence = f"URL: {r['url']}"
                    if r.get("files_preview"):
                        evidence += f" | Files: {', '.join(r['files_preview'][:5])}"
                    findings.append(Finding(
                        category="S3 Misconfiguration",
                        severity="CRITICAL",
                        title=title,
                        description=(
                            "S3 bucket is publicly listable - all files can be enumerated and downloaded"
                            if r["listable"] else
                            "S3 bucket allows anonymous write - attacker can upload/overwrite files"
                        ),
                        evidence=evidence,
                        remediation=(
                            "Set bucket policy to Block Public Access. "
                            "Use AWS S3 Block Public Access feature and review bucket ACLs."
                        )
                    ))
                elif r["severity"] == "HIGH" and r["status"] == "WRITE_INDICATED_BY_HEADERS":
                    findings.append(Finding(
                        category="S3 Misconfiguration",
                        severity="HIGH",
                        title=f"S3 Bucket Write Permission Indicated: {r['bucket']}",
                        description=(
                            "OPTIONS response headers indicate write methods (PUT/POST/DELETE) may be allowed. "
                            "Manual verification recommended."
                        ),
                        evidence=r["url"],
                        remediation=(
                            "Review bucket ACL and policy. Disable public write access. "
                            "Use AWS S3 Block Public Access feature."
                        )
                    ))
                elif r["severity"] == "LOW" and r["status"] == "EXISTS_ACCESS_DENIED":
                    findings.append(Finding(
                        category="S3 Misconfiguration",
                        severity="LOW",
                        title=f"S3 Bucket Exists (Access Denied): {r['bucket']}",
                        description="S3 bucket exists but is not publicly accessible. Verify ACLs are correct.",
                        evidence=r["url"],
                        remediation="Confirm bucket is intentionally private and ACLs are correct."
                    ))

        return s3_results, findings


# =============================================================================
# NEW MODULE 2: GITHUB DORKING
# =============================================================================

class GitHubDorker:
    """
    GitHub API üzerinden domain/hedef ile ilgili
    credential sızıntısı, config dosyası vb. arar.
    Token opsiyonel — varsa daha fazla sonuç döner.
    """

    GITHUB_API = "https://api.github.com/search/code"

    DORK_QUERIES = [
        '"{domain}" password',
        '"{domain}" secret_key',
        '"{domain}" api_key',
        '"{domain}" access_token',
        '"{domain}" db_password',
        '"{domain}" private_key',
        '"{domain}" .env',
        '"{domain}" credentials',
        '"{domain}" AWS_ACCESS_KEY',
        '"{domain}" PRIVATE_KEY',
        'filename:.env "{domain}"',
        'filename:config.php "{domain}"',
        'filename:database.yml "{domain}"',
        'filename:settings.py "{domain}"',
        'filename:wp-config.php "{domain}"',
        'filename:*.pem "{domain}"',
        'filename:id_rsa "{domain}"',
    ]

    @staticmethod
    async def search(
        client: AsyncHTTPClient,
        domain: str,
        token: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:

        results: List[Dict[str, Any]] = []
        findings: List[Finding] = []
        seen_repos: Set[str] = set()

        headers: Dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            headers["Authorization"] = f"token {token}"

        # Rate limit: authenticated=30/min, unauthenticated=10/min
        # Max 5 query çalıştır
        queries_to_run = GitHubDorker.DORK_QUERIES[:5] if not token else GitHubDorker.DORK_QUERIES[:10]

        for query_template in queries_to_run:
            query = query_template.replace("{domain}", domain)
            try:
                # GitHub API GET isteği
                url = f"{GitHubDorker.GITHUB_API}?q={query}&per_page=10"
                response = await client.get(url, headers=headers)

                if not response:
                    continue

                if response.status_code == 403:
                    logger.warning("GitHub API rate limit hit, stopping dorking")
                    break

                if response.status_code == 422:
                    # Geçersiz query, atla
                    continue

                if response.status_code != 200:
                    continue

                data = response.json()
                items = data.get("items", [])

                for item in items[:5]:
                    repo_full_name = item.get("repository", {}).get("full_name", "")
                    file_path = item.get("path", "")
                    html_url = item.get("html_url", "")

                    if repo_full_name in seen_repos:
                        continue

                    result_entry = {
                        "query": query,
                        "repository": repo_full_name,
                        "file": file_path,
                        "url": html_url,
                        "description": item.get("repository", {}).get("description", ""),
                    }
                    results.append(result_entry)

                    # Kritik dosya isimleri için severity yükselt
                    is_critical = any(kw in file_path.lower() for kw in
                                      [".env", "config", "secret", "password", "credential",
                                       "private_key", "id_rsa", "wp-config", "database"])

                    severity = "HIGH" if is_critical else "MEDIUM"

                    findings.append(Finding(
                        category="GitHub Dorking",
                        severity=severity,
                        title=f"Potential Credential Leak on GitHub: {repo_full_name}",
                        description=f"Query '{query}' found match in {file_path}",
                        evidence=html_url,
                        remediation=(
                            "Review the file immediately. If credentials are exposed: "
                            "rotate keys, revoke tokens, use GitHub secret scanning alerts."
                        )
                    ))
                    seen_repos.add(repo_full_name)

                # Rate limiting için bekle
                await asyncio.sleep(2.0 if not token else 0.5)

            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.debug(f"GitHub dork error for query '{query}': {e}")

        return results, findings


# =============================================================================
# NEW MODULE 3: NUCLEI INTEGRATION
# =============================================================================

class NucleiScanner:
    """
    Sistemde kurulu nuclei binary'sini çalıştırır.
    Kurulu değilse sessizce atlar.
    Sonuçları ReconResult'a dahil eder.
    """

    @staticmethod
    def is_available(nuclei_path: str = "nuclei") -> bool:
        return shutil.which(nuclei_path) is not None

    @staticmethod
    async def scan(
        target: str,
        nuclei_path: str = "nuclei",
        output_dir: Optional[Path] = None,
        severity_filter: str = "medium,high,critical",
        timeout_seconds: int = 120,
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:

        if not NucleiScanner.is_available(nuclei_path):
            logger.info("Nuclei not found in PATH, skipping nuclei scan")
            return [], []

        results: List[Dict[str, Any]] = []
        findings: List[Finding] = []

        # Geçici JSON output dosyası
        if output_dir is None:
            output_dir = Path("./reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_output = output_dir / f"nuclei_{timestamp}.json"

        cmd = [
            nuclei_path,
            "-u", target,
            "-severity", severity_filter,
            "-json-export", str(json_output),
            "-silent",
            "-no-color",
            "-timeout", "5",
            "-bulk-size", "10",
            "-concurrency", "10",
            "-rate-limit", "50",
        ]

        try:
            loop = asyncio.get_running_loop()

            def run_nuclei() -> Tuple[int, str, str]:
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        cwd=str(output_dir)
                    )
                    return proc.returncode, proc.stdout, proc.stderr
                except subprocess.TimeoutExpired:
                    return -1, "", "Nuclei scan timed out"
                except FileNotFoundError:
                    return -2, "", "Nuclei binary not found"
                except Exception as e:
                    return -3, "", str(e)

            returncode, stdout, stderr = await loop.run_in_executor(None, run_nuclei)

            if returncode == -2:
                return [], []

            if returncode not in [0, -1] and returncode != 0:
                logger.warning(f"Nuclei exited with code {returncode}: {stderr[:200]}")

            # JSON output dosyasını oku
            if json_output.exists():
                try:
                    nuclei_data = []
                    with open(json_output, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    nuclei_data.append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass

                    for item in nuclei_data:
                        template_id = item.get("template-id", "unknown")
                        name = item.get("info", {}).get("name", template_id)
                        severity = item.get("info", {}).get("severity", "info").upper()
                        matched_at = item.get("matched-at", "")
                        description = item.get("info", {}).get("description", "")
                        tags = item.get("info", {}).get("tags", [])
                        cve_id = next((t for t in tags if t.startswith("cve-")), None)

                        result_entry = {
                            "template_id": template_id,
                            "name": name,
                            "severity": severity,
                            "matched_at": matched_at,
                            "description": description,
                            "cve": cve_id,
                            "tags": tags,
                        }
                        results.append(result_entry)

                        finding_severity = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "INFO"
                        findings.append(Finding(
                            category=f"Nuclei:{','.join(tags[:3])}",
                            severity=finding_severity,
                            title=f"[Nuclei] {name}",
                            description=description or f"Nuclei template {template_id} matched",
                            evidence=matched_at,
                            remediation="Review Nuclei finding and apply vendor patch or recommended mitigation."
                        ))

                    # Temizle
                    try:
                        json_output.unlink()
                    except Exception:
                        pass

                except Exception as e:
                    logger.warning(f"Failed to parse nuclei output: {e}")

        except Exception as e:
            logger.warning(f"Nuclei scan failed: {e}")

        return results, findings


# =============================================================================
# NEW MODULE 4: PARAMETER DISCOVERY
# =============================================================================

class ParameterDiscovery:
    """
    HTML formlarından, JS kodundan ve URL'lerden
    parametre isimlerini çıkarır.
    Pentest raporunda 'attack surface' genişletmek için kullanılır.
    """

    # Yaygın parametre wordlist'i
    COMMON_PARAMS = [
        "id", "user", "username", "email", "password", "token", "key",
        "api_key", "secret", "hash", "code", "action", "type", "page",
        "limit", "offset", "sort", "order", "filter", "search", "query",
        "q", "term", "keyword", "cat", "category", "tag", "lang", "locale",
        "redirect", "return", "url", "next", "goto", "dest", "callback",
        "file", "path", "dir", "name", "title", "content", "body", "data",
        "format", "output", "view", "template", "theme", "style", "mode",
        "debug", "test", "admin", "superuser", "root", "uid", "uuid",
        "session", "sid", "auth", "jwt", "bearer", "access_token",
        "refresh_token", "client_id", "client_secret", "scope",
        "from", "to", "date", "start", "end", "timestamp", "ts",
        "version", "v", "ver", "ref", "source", "medium", "campaign",
        "phone", "mobile", "address", "city", "country", "zip",
        "amount", "price", "quantity", "currency", "plan", "tier",
    ]

    @staticmethod
    def extract_from_html(html: str) -> Set[str]:
        """HTML form input'larından parametre isimleri çıkar"""
        params: Set[str] = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["input", "select", "textarea"]):
                name = tag.get("name") or tag.get("id") or tag.get("data-name")
                if name and isinstance(name, str) and len(name) < 50:
                    params.add(name.lower())
            for tag in soup.find_all("form"):
                action = tag.get("action", "")
                if action:
                    parsed = urlparse(action)
                    if parsed.query:
                        for key, _ in [p.split("=", 1) for p in parsed.query.split("&") if "=" in p]:
                            params.add(key.lower())
        except Exception:
            pass
        return params

    @staticmethod
    def extract_from_js(js_content: str) -> Set[str]:
        """JS kodundan parametre isimleri çıkar"""
        params: Set[str] = set()
        patterns = [
            r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']:\s*(?:req\.(?:query|body|params)|request\.)',
            r'req\.(?:query|body|params)\.([a-zA-Z_][a-zA-Z0-9_]{1,40})',
            r'request\.(?:get|post|args)\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']',
            r'\$_(?:GET|POST|REQUEST)\[["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']',
            r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']',
            r'getParameter\(["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']',
        ]
        for pat in patterns:
            try:
                found = re.findall(pat, js_content, re.IGNORECASE)
                params.update(f.lower() for f in found if len(f) < 40)
            except re.error:
                pass
        return params

    @staticmethod
    def extract_from_urls(urls: List[str]) -> Set[str]:
        """URL'lerden query parametre isimlerini çıkar"""
        params: Set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    for part in parsed.query.split("&"):
                        if "=" in part:
                            key = part.split("=", 1)[0]
                            if key and len(key) < 50:
                                params.add(key.lower())
            except Exception:
                pass
        return params

    @staticmethod
    async def discover(
        client: AsyncHTTPClient,
        base_url: str,
        html_content: str,
        js_files_content: List[str],
        wayback_urls: List[str],
    ) -> List[str]:
        """Tüm kaynaklardan parametre keşfi"""
        all_params: Set[str] = set()

        # HTML formlarından
        all_params.update(ParameterDiscovery.extract_from_html(html_content))

        # JS dosyalarından
        for js_content in js_files_content:
            all_params.update(ParameterDiscovery.extract_from_js(js_content))

        # Wayback URL'lerinden
        all_params.update(ParameterDiscovery.extract_from_urls(wayback_urls))

        # Yaygın parametreler ile birleştir (test amaçlı wordlist)
        all_params.update(ParameterDiscovery.COMMON_PARAMS)

        return sorted(list(all_params))[:200]


# =============================================================================
# NEW MODULE 5: SCREENSHOT (Playwright)
# =============================================================================

class ScreenshotCapture:
    """
    Playwright kullanarak hedefin ekran görüntüsünü alır.
    Kurulu değilse sessizce atlar.
    Pentest raporlarına görsel kanıt eklemek için idealdir.
    """

    @staticmethod
    def is_available() -> bool:
        try:
            import importlib.util
            return importlib.util.find_spec("playwright") is not None
        except Exception:
            return False

    @staticmethod
    async def capture(
        url: str,
        output_dir: Path,
        timeout: int = 30000,
    ) -> Optional[str]:

        if not ScreenshotCapture.is_available():
            logger.info("Playwright not available, skipping screenshot")
            return None

        try:
            from playwright.async_api import async_playwright

            output_dir.mkdir(parents=True, exist_ok=True)
            domain = get_domain(url).replace(".", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = output_dir / f"screenshot_{domain}_{timestamp}.png"

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--ignore-certificate-errors",
                    ]
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1280, "height": 800},
                )
                page = await context.new_page()

                try:
                    await page.goto(url, wait_until="networkidle", timeout=timeout)
                    await asyncio.sleep(2)
                    await page.screenshot(
                        path=str(screenshot_path),
                        full_page=False,
                        type="png",
                    )
                    logger.info(f"Screenshot saved: {screenshot_path}")
                except Exception as e:
                    logger.warning(f"Screenshot page error for {url}: {e}")
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                        await page.screenshot(path=str(screenshot_path), type="png")
                    except Exception:
                        return None
                finally:
                    await context.close()
                    await browser.close()

            return str(screenshot_path)

        except ImportError:
            logger.info("Playwright not installed")
            return None
        except Exception as e:
            logger.warning(f"Screenshot capture failed for {url}: {e}")
            return None


# =============================================================================
# REPORT GENERATION
# =============================================================================

def build_executive_summary(result: 'ReconResult', all_findings: List[Finding]) -> Dict[str, Any]:
    severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    category_counts: Dict[str, int] = defaultdict(int)

    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] += 1

    severity_weights = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
    risk_score = sum(severity_weights.get(sev, 0) * count for sev, count in severity_counts.items())

    return {
        "overall_severity": result.severity_score,
        "risk_score": risk_score,
        "total_findings": len(all_findings),
        "severity_breakdown": severity_counts,
        "top_categories": dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
        "stats": {
            "subdomains_found": len(result.subdomains),
            "open_ports": len(result.open_ports),
            "js_files": len(result.js_files),
            "endpoints": len(result.endpoints),
            "secrets": len(result.secrets) + len(result.source_map_secrets),
            "emails": len(result.emails),
            "cve_hints": len(result.cve_hints),
            "s3_findings": len(result.s3_findings),
            "github_dork_findings": len(result.github_dork_findings),
            "nuclei_findings": len(result.nuclei_findings),
            "parameters_discovered": len(result.discovered_parameters),
        }
    }


class ReportGenerator:
    @staticmethod
    def generate_json(result: ReconResult) -> str:
        return json.dumps(asdict(result), indent=2, default=str)

    @staticmethod
    def generate_html(result: ReconResult) -> str:
        findings_html = ""
        for f in result.findings:
            severity_color = {
                "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#17a2b8"
            }.get(f.get("severity", "INFO"), "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {severity_color}; padding: 10px; margin: 10px 0; background: #f8f9fa;">
                <strong style="color: {severity_color};">[{f.get('severity', 'INFO')}]</strong>
                <strong>{f.get('title', 'Unknown')}</strong>
                <p>{f.get('description', '')}</p>
                {f'<code>{f.get("evidence", "")}</code>' if f.get('evidence') else ''}
                {f'<p><em>Remediation: {f.get("remediation", "")}</em></p>' if f.get('remediation') else ''}
            </div>"""

        cve_html = ""
        for hint in result.cve_hints:
            cve_html += f"""
            <div style="border-left: 4px solid #e74c3c; padding: 8px; margin: 6px 0; background: #fdf2f2;">
                <strong>[{hint.get('tech','').upper()}]</strong> {hint.get('cve','')} — {hint.get('description','')}
            </div>"""

        s3_html = ""
        for s3 in result.s3_findings:
            color = "#dc3545" if s3.get("severity") == "CRITICAL" else "#ffc107"
            s3_html += f"""
            <div style="border-left: 4px solid {color}; padding: 8px; margin: 6px 0; background: #fdf2f2;">
                <strong>{s3.get('bucket','')}</strong> — {s3.get('status','')}
                <br><code>{s3.get('url','')}</code>
                {f"<br>Files: <code>{', '.join(s3.get('files_preview', [])[:5])}</code>" if s3.get('files_preview') else ''}
            </div>"""

        github_html = ""
        for gh in result.github_dork_findings:
            github_html += f"""
            <div style="border-left: 4px solid #fd7e14; padding: 8px; margin: 6px 0; background: #fff8f0;">
                <strong>{gh.get('repository','')}</strong> / <code>{gh.get('file','')}</code>
                <br><small>Query: {gh.get('query','')}</small>
                <br><a href="{gh.get('url','')}" target="_blank">{gh.get('url','')}</a>
            </div>"""

        nuclei_html = ""
        for nf in result.nuclei_findings:
            color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107",
                     "LOW": "#28a745", "INFO": "#17a2b8"}.get(nf.get("severity", "INFO"), "#6c757d")
            nuclei_html += f"""
            <div style="border-left: 4px solid {color}; padding: 8px; margin: 6px 0; background: #f8f9fa;">
                <strong style="color:{color}">[{nf.get('severity','')}]</strong>
                <strong>{nf.get('name','')}</strong>
                {f"<span style='color:#888'> [{nf.get('cve','')}]</span>" if nf.get('cve') else ''}
                <br><code>{nf.get('matched_at','')}</code>
                <p>{nf.get('description','')}</p>
            </div>"""

        exec_summary = result.executive_summary
        sev_breakdown = exec_summary.get("severity_breakdown", {})
        stats = exec_summary.get("stats", {})

        screenshot_html = ""
        if result.screenshot_path:
            screenshot_html = f"""
            <h2>📸 Screenshot</h2>
            <div class="section">
                <img src="{result.screenshot_path}" style="max-width:100%; border:1px solid #ddd; border-radius:4px;" alt="Target Screenshot">
            </div>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Report V11 - {result.target}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .severity {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }}
        .severity-CRITICAL {{ background: #dc3545; }}
        .severity-HIGH {{ background: #fd7e14; }}
        .severity-MEDIUM {{ background: #ffc107; color: #333; }}
        .severity-LOW {{ background: #28a745; }}
        .severity-INFO {{ background: #17a2b8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; word-break: break-all; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .score-badge {{ display: inline-block; padding: 8px 20px; border-radius: 25px; font-size: 1.2em; font-weight: bold; color: white; background: #343a40; }}
        .sev-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0; }}
        .sev-pill {{ padding: 4px 12px; border-radius: 12px; color: white; font-size: 0.85em; font-weight: bold; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 Reconnaissance Report V11</h1>
    <div class="meta">
        <strong>Target:</strong> {result.target}<br>
        <strong>Timestamp:</strong> {result.timestamp}<br>
        <strong>Speed Used:</strong> {result.speed_used}<br>
        <strong>Overall Severity:</strong> <span class="severity severity-{result.severity_score}">{result.severity_score}</span>
        &nbsp;<span class="score-badge">Risk Score: {exec_summary.get('risk_score', 0)}</span>
    </div>

    {screenshot_html}

    <h2>📋 Executive Summary</h2>
    <div class="section">
        <div class="sev-bar">
            <span class="sev-pill" style="background:#dc3545">CRITICAL: {sev_breakdown.get('CRITICAL', 0)}</span>
            <span class="sev-pill" style="background:#fd7e14">HIGH: {sev_breakdown.get('HIGH', 0)}</span>
            <span class="sev-pill" style="background:#ffc107;color:#333">MEDIUM: {sev_breakdown.get('MEDIUM', 0)}</span>
            <span class="sev-pill" style="background:#28a745">LOW: {sev_breakdown.get('LOW', 0)}</span>
            <span class="sev-pill" style="background:#17a2b8">INFO: {sev_breakdown.get('INFO', 0)}</span>
        </div>
        <table>
            <tr><th>Subdomains</th><td>{stats.get('subdomains_found', 0)}</td>
                <th>Open Ports</th><td>{stats.get('open_ports', 0)}</td></tr>
            <tr><th>JS Files</th><td>{stats.get('js_files', 0)}</td>
                <th>Endpoints</th><td>{stats.get('endpoints', 0)}</td></tr>
            <tr><th>Secrets Found</th><td>{stats.get('secrets', 0)}</td>
                <th>Emails Found</th><td>{stats.get('emails', 0)}</td></tr>
            <tr><th>CVE Hints</th><td>{stats.get('cve_hints', 0)}</td>
                <th>Nuclei Findings</th><td>{stats.get('nuclei_findings', 0)}</td></tr>
            <tr><th>S3 Findings</th><td>{stats.get('s3_findings', 0)}</td>
                <th>GitHub Leaks</th><td>{stats.get('github_dork_findings', 0)}</td></tr>
            <tr><th>Parameters</th><td>{stats.get('parameters_discovered', 0)}</td>
                <th>Total Findings</th><td>{exec_summary.get('total_findings', 0)}</td></tr>
        </table>
    </div>

    <h2>⚠️ CVE / Technology Hints</h2>
    <div class="section">{cve_html if cve_html else '<p>No CVE hints for detected technologies.</p>'}</div>

    <h2>🪣 S3 Bucket Findings</h2>
    <div class="section">{s3_html if s3_html else '<p>No S3 misconfiguration found.</p>'}</div>

    <h2>🐙 GitHub Dorking Findings</h2>
    <div class="section">{github_html if github_html else '<p>No GitHub leaks found.</p>'}</div>

    <h2>⚡ Nuclei Findings</h2>
    <div class="section">{nuclei_html if nuclei_html else '<p>Nuclei not run or no findings.</p>'}</div>

    <h2>📊 Overview</h2>
    <div class="section">
        <table>
            <tr><th>Status Code</th><td>{result.status_code}</td></tr>
            <tr><th>Response Time</th><td>{result.response_time}s</td></tr>
            <tr><th>Technologies</th><td>{', '.join([t.get('name', '') for t in result.technology.get('technologies', [])])}</td></tr>
            <tr><th>WAF/CDN</th><td>{result.technology.get('waf', 'None detected')}</td></tr>
            <tr><th>Server</th><td>{result.technology.get('server', 'N/A')}</td></tr>
        </table>
    </div>

    <h2>🔐 Security Findings</h2>
    {findings_html if findings_html else '<p>No significant findings.</p>'}

    <h2>🧩 Discovered Parameters ({len(result.discovered_parameters)})</h2>
    <div class="section">
        <code>{', '.join(result.discovered_parameters[:100])}</code>
    </div>

    <h2>🍪 Cookie Analysis</h2>
    <div class="section">
        {'<br>'.join([f"<code>{c.get('name')}</code> — HttpOnly:{c.get('httponly')} Secure:{c.get('secure')} SameSite:{c.get('samesite')}" for c in result.cookies_analysis]) or 'No cookies detected'}
    </div>

    <h2>🔀 Open Redirect Findings</h2>
    <div class="section">{'<br>'.join([f'<code>{u}</code>' for u in result.open_redirect_findings]) or 'None found'}</div>

    <h2>🔨 HTTP Method Fuzzing</h2>
    <div class="section">
        {'<br>'.join([f"<code>[{m.get('status')}] {m.get('method')} {m.get('url')}</code>" for m in result.http_method_findings]) or 'No unexpected method responses'}
    </div>

    <h2>📧 Emails Found</h2>
    <div class="section">{'<br>'.join([f'<code>{e}</code>' for e in result.emails]) or 'None found'}</div>

    <h2>🤖 Robots.txt Paths</h2>
    <div class="section">{'<br>'.join([f'<code>{p}</code>' for p in result.robots_paths]) or 'None found'}</div>

    <h2>📜 JavaScript Files ({len(result.js_files)})</h2>
    <div class="section">{'<br>'.join([f'<code>{js}</code>' for js in result.js_files[:20]]) or 'None found'}</div>

    <h2>🔗 Endpoints ({len(result.endpoints)})</h2>
    <div class="section">{'<br>'.join([f'<code>{ep}</code>' for ep in result.endpoints[:30]]) or 'None found'}</div>

    <h2>🌐 Subdomains ({len(result.subdomains)})</h2>
    <div class="section">{'<br>'.join([f'<code>{sd}</code>' for sd in result.subdomains[:30]]) or 'None found'}</div>

    <h2>🔓 Open Ports</h2>
    <div class="section">{', '.join([str(p) for p in result.open_ports]) if result.open_ports else 'No open ports detected'}</div>

    {f'<div style="background:#fff3cd;padding:10px;border-radius:5px;margin-top:20px;"><h3>⚠️ Errors</h3><ul>{"".join([f"<li>{e}</li>" for e in result.errors])}</ul></div>' if result.errors else ''}
</div>
</body>
</html>"""
        return html

    @staticmethod
    def print_summary(result: ReconResult, console: ConsoleInterface) -> None:
        if isinstance(console, RichConsole):
            rich_console = console.raw
            exec_s = result.executive_summary
            sev_bd = exec_s.get("severity_breakdown", {})

            rich_console.print(Panel.fit(
                f"[bold]Target:[/bold] {result.target}\n"
                f"[bold]Status:[/bold] {result.status_code} | "
                f"[bold]Response Time:[/bold] {result.response_time}s\n"
                f"[bold]Speed:[/bold] {result.speed_used} | "
                f"[bold]Severity:[/bold] {result.severity_score} | "
                f"[bold]Risk Score:[/bold] {exec_s.get('risk_score', 0)}\n"
                f"[red]CRIT:{sev_bd.get('CRITICAL',0)}[/red] "
                f"[orange1]HIGH:{sev_bd.get('HIGH',0)}[/orange1] "
                f"[yellow]MED:{sev_bd.get('MEDIUM',0)}[/yellow] "
                f"[green]LOW:{sev_bd.get('LOW',0)}[/green]",
                title="[bold blue]Scan Summary[/bold blue]",
                border_style="blue"
            ))

            if result.technology.get("technologies"):
                table = Table(title="Detected Technologies")
                table.add_column("Technology", style="cyan")
                table.add_column("Confidence", style="green")
                for tech in result.technology["technologies"][:10]:
                    table.add_row(tech["name"], f"{tech['confidence']*100:.0f}%")
                rich_console.print(table)

            if result.cve_hints:
                table = Table(title="CVE Hints")
                table.add_column("Tech", style="cyan")
                table.add_column("CVE", style="red")
                table.add_column("Description")
                for hint in result.cve_hints[:10]:
                    table.add_row(hint.get("tech", ""), hint.get("cve", ""), hint.get("description", ""))
                rich_console.print(table)

            if result.nuclei_findings:
                table = Table(title="⚡ Nuclei Findings")
                table.add_column("Severity", style="bold")
                table.add_column("Name")
                table.add_column("Matched At")
                sev_styles = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}
                for nf in result.nuclei_findings[:10]:
                    sev = nf.get("severity", "INFO")
                    table.add_row(
                        f"[{sev_styles.get(sev, 'white')}]{sev}[/]",
                        nf.get("name", ""),
                        nf.get("matched_at", "")[:60]
                    )
                rich_console.print(table)

            if result.s3_findings:
                table = Table(title="🪣 S3 Bucket Findings")
                table.add_column("Bucket", style="cyan")
                table.add_column("Status", style="bold")
                table.add_column("Severity")
                for s3 in result.s3_findings:
                    sev_color = "red bold" if s3.get("severity") == "CRITICAL" else "yellow"
                    table.add_row(
                        s3.get("bucket", ""),
                        s3.get("status", ""),
                        f"[{sev_color}]{s3.get('severity','')}[/]"
                    )
                rich_console.print(table)

            if result.github_dork_findings:
                table = Table(title="🐙 GitHub Dorking Findings")
                table.add_column("Repository", style="cyan")
                table.add_column("File")
                for gh in result.github_dork_findings[:10]:
                    table.add_row(gh.get("repository", ""), gh.get("file", ""))
                rich_console.print(table)

            if result.findings:
                table = Table(title="Security Findings")
                table.add_column("Severity", style="bold")
                table.add_column("Category")
                table.add_column("Title")
                severity_styles = {
                    "CRITICAL": "red bold", "HIGH": "red",
                    "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"
                }
                for f in result.findings[:15]:
                    sev = f.get("severity", "INFO")
                    table.add_row(
                        f"[{severity_styles.get(sev, 'white')}]{sev}[/]",
                        f.get("category", ""), f.get("title", "")
                    )
                rich_console.print(table)

            stats = exec_s.get("stats", {})
            rich_console.print(f"\n[bold]📊 Statistics:[/bold]")
            rich_console.print(f"  • JS Files: {len(result.js_files)}")
            rich_console.print(f"  • Endpoints: {len(result.endpoints)}")
            rich_console.print(f"  • Subdomains: {len(result.subdomains)}")
            rich_console.print(f"  • Open Ports: {len(result.open_ports)}")
            rich_console.print(f"  • Secrets Found: {len(result.secrets) + len(result.source_map_secrets)}")
            rich_console.print(f"  • Emails Found: {len(result.emails)}")
            rich_console.print(f"  • Parameters Discovered: {len(result.discovered_parameters)}")
            rich_console.print(f"  • S3 Findings: {len(result.s3_findings)}")
            rich_console.print(f"  • GitHub Dork Findings: {len(result.github_dork_findings)}")
            rich_console.print(f"  • Nuclei Findings: {len(result.nuclei_findings)}")
            rich_console.print(f"  • CVE Hints: {len(result.cve_hints)}")
            if result.screenshot_path:
                rich_console.print(f"  • Screenshot: {result.screenshot_path}")

            if result.errors:
                rich_console.print(f"\n[yellow]⚠️ Errors: {len(result.errors)}[/yellow]")
        else:
            console.print(f"Target: {result.target}")
            console.print(f"Status: {result.status_code} | Severity: {result.severity_score}")


# =============================================================================
# MAIN RECONNAISSANCE ENGINE
# =============================================================================

class ReconEngine:
    def __init__(
        self,
        config: Optional[Config] = None,
        console: Optional[ConsoleInterface] = None,
        http_client_factory: Optional[Callable[[Config], AsyncHTTPClient]] = None
    ):
        self.config = config or create_default_config()
        self.console = console or get_console()
        self.http_client_factory = http_client_factory or (lambda c: AsyncHTTPClient(c))
        self.dns = DNSRecon()
        self.port_scanner = PortScanner(self.config)

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ReconResult:
        if options is None:
            options = {}

        url = normalize_url(target)
        domain = get_domain(url)
        result = ReconResult(target=url, speed_used=self.config.speed)
        all_findings: List[Finding] = []

        self.console.print(f"\n[bold blue]{'='*60}[/bold blue]")
        self.console.print(f"[bold blue]TARGET: {url}[/bold blue]")
        self.console.print(f"[bold yellow]SPEED: {self.config.speed} - {describe_speed(self.config.speed)}[/bold yellow]")
        self.console.print(
            f"[dim]Concurrent: {self.config.max_concurrent} | Timeout: {self.config.timeout}s | "
            f"Delay: {self.config.delay_min}-{self.config.delay_max}s | SSL Verify: {self.config.verify_ssl} | "
            f"GitHub Token: {'✓' if self.config.github_token else '✗'} | "
            f"Nuclei: {'✓' if NucleiScanner.is_available(self.config.nuclei_path) else '✗'} | "
            f"Screenshot: {'✓' if self.config.screenshot_enabled and ScreenshotCapture.is_available() else '✗'}[/dim]"
        )
        self.console.print(f"[bold blue]{'='*60}[/bold blue]\n")

        client = self.http_client_factory(self.config)
        async with client:
            if isinstance(self.console, RichConsole):
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=self.console.raw,
                    transient=False,
                ) as progress:
                    result, all_findings = await self._run_recon(
                        client, url, domain, result, all_findings, progress
                    )
            else:
                result, all_findings = await self._run_recon(
                    client, url, domain, result, all_findings, None
                )

        result.findings = [asdict(f) for f in all_findings]
        result.severity_score = calculate_severity(all_findings)
        result.executive_summary = build_executive_summary(result, all_findings)

        return result

    async def _run_recon(
        self,
        client: AsyncHTTPClient,
        url: str,
        domain: str,
        result: ReconResult,
        all_findings: List[Finding],
        progress: Optional[Progress]
    ) -> Tuple[ReconResult, List[Finding]]:

        task_id = None
        if progress:
            task_id = progress.add_task("[cyan]Starting...", total=100)

        def update(description: str, completed: int) -> None:
            if progress and task_id is not None:
                progress.update(task_id, description=description, completed=completed)

        # 1. Initial request
        try:
            update("[cyan]Initial request...", 3)
            response = await client.get(url)
            if not response:
                result.errors.append("Failed to reach target")
                return result, all_findings
            result.status_code = response.status_code
            result.response_time = getattr(response, 'elapsed_time', 0.0)
            body = response.text
        except Exception as e:
            result.errors.append(f"Initial request failed: {e}")
            return result, all_findings

        # 2. Technology detection
        try:
            update("[cyan]Detecting technologies...", 6)
            result.technology = TechnologyDetector.detect(response.headers, body, str(response.cookies))
        except Exception as e:
            result.errors.append(f"Technology detection failed: {e}")

        # 3. CVE hints
        try:
            update("[cyan]Checking CVE hints...", 8)
            result.cve_hints = TechnologyDetector.get_cve_hints(result.technology)
        except Exception as e:
            result.errors.append(f"CVE hint lookup failed: {e}")

        # 4. Security headers
        try:
            update("[cyan]Analyzing security headers...", 11)
            result.security_headers, header_findings = SecurityHeadersAnalyzer.analyze(response.headers)
            all_findings.extend(header_findings)
        except Exception as e:
            result.errors.append(f"Security headers analysis failed: {e}")

        # 5. Cookie analysis
        try:
            update("[cyan]Analyzing cookies...", 13)
            result.cookies_analysis, cookie_findings = CookieAnalyzer.analyze(response)
            all_findings.extend(cookie_findings)
        except Exception as e:
            result.errors.append(f"Cookie analysis failed: {e}")

        # 6. Subdomain takeover
        try:
            update("[cyan]Checking subdomain takeover...", 15)
            takeover_findings = SubdomainTakeoverChecker.check(body, response.headers)
            all_findings.extend(takeover_findings)
        except Exception as e:
            result.errors.append(f"Subdomain takeover check failed: {e}")

        # 7. Email harvesting
        try:
            update("[cyan]Harvesting emails...", 17)
            result.emails = extract_emails(body)
        except Exception as e:
            result.errors.append(f"Email harvesting failed: {e}")

        # 8. Robots.txt + Sitemap
        try:
            update("[cyan]Parsing robots.txt / sitemap...", 19)
            robots_paths = await RobotsParser.parse_robots(client, url)
            sitemap_urls = await RobotsParser.parse_sitemap(client, url)
            result.robots_paths = robots_paths
            extra_paths = [p for p in robots_paths if p not in COMMON_PATHS]
            COMMON_PATHS.extend(extra_paths[:30])
        except Exception as e:
            result.errors.append(f"Robots/sitemap parsing failed: {e}")

        # 9. DNS records
        try:
            update("[cyan]Querying DNS records...", 22)
            result.dns_records = await self.dns.get_records(domain)
        except Exception as e:
            result.errors.append(f"DNS query failed: {e}")

        # 10. Subdomain enumeration
        try:
            update("[cyan]Enumerating subdomains...", 27)
            crtsh_subs = await SubdomainFinder.from_crtsh(client, domain)
            ht_subs = await SubdomainFinder.from_hackertarget(client, domain)
            brute_subs = await self.dns.brute_subdomains(domain)
            all_subs = crtsh_subs | ht_subs | brute_subs
            result.subdomains = list(all_subs)[:self.config.max_subdomains]
        except Exception as e:
            result.errors.append(f"Subdomain enumeration failed: {e}")

        # 11. Port scanning
        try:
            update("[cyan]Scanning ports...", 33)
            result.open_ports = await self.port_scanner.scan(domain)
        except Exception as e:
            result.errors.append(f"Port scanning failed: {e}")

        # 12. SSL analysis
        try:
            update("[cyan]Analyzing SSL certificate...", 36)
            result.ssl_info = await SSLAnalyzer.analyze(domain)
        except Exception as e:
            result.errors.append(f"SSL analysis failed: {e}")

        # 13. Crawling
        try:
            update("[cyan]Crawling website...", 40)
            crawler = Crawler(client, self.config)
            _, js_files = await crawler.crawl(url)
            result.js_files = list(js_files)[:self.config.max_js_files]
            result.emails = list(set(result.emails) | crawler.found_emails)[:100]
        except Exception as e:
            result.errors.append(f"Crawling failed: {e}")

        # 14. JS analysis
        js_files_content: List[str] = []
        try:
            update("[cyan]Analyzing JavaScript files...", 45)
            js_analysis = await JSAnalyzer.analyze(client, result.js_files, self.config)
            result.endpoints = js_analysis["endpoints"]
            result.secrets = js_analysis["secrets"]
            result.source_map_secrets = js_analysis.get("source_map_secrets", [])
            result.emails = list(set(result.emails) | set(js_analysis.get("emails", [])))[:100]

            for secret in result.secrets + result.source_map_secrets:
                all_findings.append(Finding(
                    category="Secrets", severity="HIGH",
                    title=f"Exposed {secret['type']}",
                    description=f"Found in {secret['source']}",
                    evidence=secret['value']
                ))

            # JS içeriklerini parametre keşfi için sakla
            for js_url in result.js_files[:10]:
                try:
                    r = await client.get(js_url)
                    if r and r.status_code == 200:
                        js_files_content.append(r.text)
                except Exception:
                    pass

        except Exception as e:
            result.errors.append(f"JS analysis failed: {e}")

        # 15. Wayback Machine
        try:
            update("[cyan]Fetching Wayback URLs...", 50)
            result.wayback_urls = await WaybackMachine.get_urls(client, domain, limit=50)
            wayback_endpoints = WaybackMachine.extract_endpoints_from_urls(result.wayback_urls)
            result.endpoints = list(set(result.endpoints) | wayback_endpoints)[:self.config.max_endpoints]
        except Exception as e:
            result.errors.append(f"Wayback Machine query failed: {e}")

        # 16. CORS testing
        try:
            update("[cyan]Testing CORS...", 54)
            cors_findings = await CORSTester.test(client, url)
            all_findings.extend(cors_findings)
        except Exception as e:
            result.errors.append(f"CORS testing failed: {e}")

        # 17. GraphQL probing
        try:
            update("[cyan]Probing GraphQL...", 57)
            graphql_results = await GraphQLProbe.probe(client, result.endpoints, url)
            for gql in graphql_results:
                if gql.get("introspection_enabled"):
                    all_findings.append(Finding(
                        category="GraphQL", severity="MEDIUM",
                        title="GraphQL Introspection Enabled",
                        description=f"Introspection is enabled at {gql['url']}",
                        evidence=f"Found {gql.get('types_count', 'unknown')} types"
                    ))
        except Exception as e:
            result.errors.append(f"GraphQL probing failed: {e}")

        # 18. Directory discovery
        try:
            update("[cyan]Discovering directories...", 61)
            dir_results = await DirectoryBruter.brute(client, url)
            sensitive_keywords = ["admin", "debug", "backup", "config", ".env", ".git",
                                   "phpinfo", "actuator", "console", "docker", "package",
                                   "composer", "jenkins", "nginx", "apache"]
            for d in dir_results:
                if d["status"] in [200, 403, 401]:
                    if any(kw in d["path"].lower() for kw in sensitive_keywords):
                        all_findings.append(Finding(
                            category="Directory Discovery",
                            severity="MEDIUM" if d["status"] == 200 else "LOW",
                            title=f"Sensitive Path Found: {d['path']}",
                            description=f"Status: {d['status']}, Size: {d['length']} bytes",
                            evidence=d["url"]
                        ))
        except Exception as e:
            result.errors.append(f"Directory discovery failed: {e}")

        # 19. Open Redirect testing
        try:
            update("[cyan]Testing open redirects...", 65)
            or_findings = await OpenRedirectTester.test(client, url, result.endpoints)
            result.open_redirect_findings = or_findings
            for vuln_url in or_findings:
                all_findings.append(Finding(
                    category="Open Redirect", severity="MEDIUM",
                    title="Open Redirect Detected",
                    description="URL parameter reflects external redirect",
                    evidence=vuln_url,
                    remediation="Validate and whitelist redirect destinations"
                ))
        except Exception as e:
            result.errors.append(f"Open redirect testing failed: {e}")

        # 20. HTTP Method fuzzing
        try:
            update("[cyan]Fuzzing HTTP methods...", 68)
            method_results = await HTTPMethodFuzzer.fuzz(client, url)
            result.http_method_findings = method_results
            for mf in method_results:
                if mf["method"] in ["TRACE", "PUT", "DELETE"] and mf["status"] in [200, 201, 204]:
                    all_findings.append(Finding(
                        category="HTTP Methods", severity="MEDIUM",
                        title=f"Dangerous HTTP Method Allowed: {mf['method']}",
                        description=f"Method {mf['method']} returned status {mf['status']} on {mf['path']}",
                        evidence=mf["url"],
                        remediation=f"Disable {mf['method']} method if not required"
                    ))
        except Exception as e:
            result.errors.append(f"HTTP method fuzzing failed: {e}")

        # =========================================================
        # 21. NEW: S3 Bucket Misconfig Checker
        # =========================================================
        try:
            update("[cyan]Checking S3 buckets...", 72)
            js_buckets = js_analysis.get("s3_buckets", []) if 'js_analysis' in dir() else []
            s3_results, s3_findings = await S3BucketChecker.run(
                client, domain, result.subdomains, js_buckets, body
            )
            result.s3_findings = s3_results
            all_findings.extend(s3_findings)
        except Exception as e:
            result.errors.append(f"S3 bucket check failed: {e}")

        # =========================================================
        # 22. NEW: GitHub Dorking
        # =========================================================
        try:
            update("[cyan]GitHub dorking...", 76)
            gh_results, gh_findings = await GitHubDorker.search(
                client, domain, token=self.config.github_token
            )
            result.github_dork_findings = gh_results
            all_findings.extend(gh_findings)
        except Exception as e:
            result.errors.append(f"GitHub dorking failed: {e}")

        # =========================================================
        # 23. NEW: Nuclei Integration
        # =========================================================
        try:
            update("[cyan]Running Nuclei...", 81)
            if NucleiScanner.is_available(self.config.nuclei_path):
                output_dir = Path("./reports")
                nuclei_results, nuclei_findings = await NucleiScanner.scan(
                    target=url,
                    nuclei_path=self.config.nuclei_path,
                    output_dir=output_dir,
                    severity_filter="medium,high,critical",
                    timeout_seconds=120,
                )
                result.nuclei_findings = nuclei_results
                all_findings.extend(nuclei_findings)
            else:
                logger.info("Nuclei not available, skipping")
        except Exception as e:
            result.errors.append(f"Nuclei scan failed: {e}")

        # =========================================================
        # 24. NEW: Parameter Discovery
        # =========================================================
        try:
            update("[cyan]Discovering parameters...", 88)
            result.discovered_parameters = await ParameterDiscovery.discover(
                client=client,
                base_url=url,
                html_content=body,
                js_files_content=js_files_content,
                wayback_urls=result.wayback_urls,
            )
        except Exception as e:
            result.errors.append(f"Parameter discovery failed: {e}")

        # =========================================================
        # 25. NEW: Screenshot Capture
        # =========================================================
        try:
            update("[cyan]Taking screenshot...", 94)
            if self.config.screenshot_enabled:
                output_dir = Path("./reports")
                screenshot_path = await ScreenshotCapture.capture(url, output_dir)
                result.screenshot_path = screenshot_path
            else:
                logger.info("Screenshot disabled, use --screenshot to enable")
        except Exception as e:
            result.errors.append(f"Screenshot capture failed: {e}")

        update("[cyan]Complete!", 100)
        return result, all_findings


# =============================================================================
# CLI
# =============================================================================

async def async_main(args: argparse.Namespace) -> None:
    console = get_console()
    config = create_default_config()

    speed = max(100, min(5000, args.speed))
    config.apply_speed(speed)
    config.verify_ssl = args.verify_ssl
    config.github_token = getattr(args, 'github_token', None)
    config.nuclei_path = getattr(args, 'nuclei_path', 'nuclei')
    config.screenshot_enabled = getattr(args, 'screenshot', False)

    if args.concurrent:
        config.max_concurrent = args.concurrent
    if args.timeout:
        config.timeout = args.timeout
    if args.depth:
        config.max_depth = args.depth

    console.print(f"\n[bold yellow]⚡ Speed Level: {speed}[/bold yellow]")
    console.print(f"[dim]{describe_speed(speed)}[/dim]")
    console.print(
        f"[dim]Settings: concurrent={config.max_concurrent}, timeout={config.timeout}s, "
        f"delay={config.delay_min:.2f}-{config.delay_max:.2f}s, depth={config.max_depth}, "
        f"ssl_verify={config.verify_ssl}, "
        f"github_token={'✓' if config.github_token else '✗'}, "
        f"nuclei={'✓' if NucleiScanner.is_available(config.nuclei_path) else '✗ (not installed)'}, "
        f"screenshot={'✓' if config.screenshot_enabled else '✗'}[/dim]\n"
    )

    targets: List[str] = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[red]File not found: {args.file}[/red]")
            return
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            return

    if not targets:
        user_input = console.input("[bold]Enter target URL(s) (comma-separated): [/bold]")
        targets = [t.strip() for t in user_input.split(",") if t.strip()]

    if not targets:
        console.print("[red]No targets specified[/red]")
        return

    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Error creating output directory: {e}[/red]")
        return

    engine = ReconEngine(config=config, console=console)

    for target in targets:
        try:
            result = await engine.run(target)

            if not args.quiet:
                ReportGenerator.print_summary(result, console)

            domain = get_domain(result.target).replace(".", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if args.json or (not args.json and not args.html):
                json_path = output_dir / f"{domain}_{timestamp}_speed{speed}.json"
                json_path.write_text(ReportGenerator.generate_json(result))
                console.print(f"\n[green]JSON report saved: {json_path}[/green]")

            if args.html:
                html_path = output_dir / f"{domain}_{timestamp}_speed{speed}.html"
                html_path.write_text(ReportGenerator.generate_html(result))
                console.print(f"[green]HTML report saved: {html_path}[/green]")

            if not args.quiet:
                console.print("\n[bold cyan]JSON Report:[/bold cyan]")
                console.print(ReportGenerator.generate_json(result))

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted[/yellow]")
            break
        except ReconError as e:
            console.print(f"[red]Recon error for {target}: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Unexpected error scanning {target}: {type(e).__name__}: {e}[/red]")
            logger.exception(f"Unexpected error scanning {target}")

    console.print("\n[bold green]✓ Scan complete![/bold green]")


def main() -> None:
    console = get_console()
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="Recon Tool V11 - Advanced Web Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Speed Examples:
  --speed 100   Stealth mode
  --speed 1000  Normal (default)
  --speed 2000  Aggressive
  --speed 5000  Maximum (may trigger WAF)

New Modules:
  --github-token TOKEN   GitHub PAT for dorking (optional but recommended)
  --nuclei-path PATH     Path to nuclei binary (default: nuclei)
  --screenshot           Capture screenshot with Playwright (pip install playwright)

Usage Examples:
  python recon.py -u example.com --speed 1000 --html
  python recon.py -u example.com --github-token ghp_xxx --screenshot
  python recon.py -u example.com --nuclei-path /usr/local/bin/nuclei
  python recon.py -f targets.txt --speed 500 --html
        """
    )

    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-f", "--file", help="File containing target URLs (one per line)")
    parser.add_argument("-o", "--output", help="Output directory for reports", default="./reports")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--html", action="store_true", help="Save HTML report")
    parser.add_argument("--speed", type=int, default=1000,
                        help="Speed/aggression level (100=stealth, 5000=max). Default: 1000")
    parser.add_argument("-c", "--concurrent", type=int, help="Override max concurrent requests")
    parser.add_argument("-t", "--timeout", type=float, help="Override request timeout in seconds")
    parser.add_argument("-d", "--depth", type=int, help="Override crawl depth")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--verify-ssl", action="store_true", dest="verify_ssl",
                        help="Enable SSL certificate verification (default: disabled)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    # NEW args
    parser.add_argument("--github-token", dest="github_token", default=None,
                        help="GitHub Personal Access Token for dorking (optional)")
    parser.add_argument("--nuclei-path", dest="nuclei_path", default="nuclei",
                        help="Path to nuclei binary (default: nuclei)")
    parser.add_argument("--screenshot", action="store_true",
                        help="Capture screenshot with Playwright (requires: pip install playwright && playwright install chromium)")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
        logger.setLevel(logging.WARNING)

    import warnings
    warnings.filterwarnings("ignore")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("aiodns").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
