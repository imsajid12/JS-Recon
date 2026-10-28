#!/usr/bin/env python3
"""
JS Recon — JavaScript Enumeration & Analysis Tool for Pentesters

Auto-spiders the application to discover pages, collects all JS files
(external + inline), then analyzes them for attack surface.

Usage:
  Collect JS from a target (auto-spiders up to 100 pages by default):
    python3 js_recon.py collect -u https://target.com -o ./js_loot
    python3 js_recon.py collect -u https://target.com -c "session=abc123" -o ./js_loot
    python3 js_recon.py collect -u https://target.com -m 200 -o ./js_loot  (spider 200 pages)

  Analyze collected JS files:
    python3 js_recon.py analyze -d ./js_loot
    python3 js_recon.py analyze -d ./js_loot --html report.html

  Full pipeline (collect + analyze):
    python3 js_recon.py full -u https://target.com -o ./js_loot --html report.html
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
import textwrap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip3 install requests beautifulsoup4 rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────────────────────
# Pattern Definitions
# ─────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = {
    "API Routes": [
        r"""['"`](/api/[a-zA-Z0-9_/\-\.{}:]+)['"`]""",
        r"""['"`](/v[0-9]+/[a-zA-Z0-9_/\-\.{}:]+)['"`]""",
        r"""['"`](/rest/[a-zA-Z0-9_/\-\.{}:]+)['"`]""",
        r"""['"`](/graphql[a-zA-Z0-9_/\-]*)['"`]""",
        r"""['"`](/internal/[a-zA-Z0-9_/\-\.{}:]+)['"`]""",
        r"""['"`](/admin/[a-zA-Z0-9_/\-\.{}:]+)['"`]""",
    ],
    "HTTP Methods": [
        r"""\.(get|post|put|delete|patch|options|head)\s*\(""",
        r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""axios\s*[\.\(]\s*['"`]?([^'"`\s,\)]+)""",
        r"""\$\.(ajax|get|post|getJSON)\s*\(""",
        r"""XMLHttpRequest""",
        r"""new\s+Request\s*\(""",
    ],
    "Full URLs": [
        r"""https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9_\-\.?&=%#]*""",
    ],
}

SECRET_PATTERNS = {
    "AWS Keys": [
        r"""AKIA[0-9A-Z]{16}""",
        r"""(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"`]?([A-Za-z0-9/+=]{40})""",
    ],
    "API Keys (Generic)": [
        r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"`]([^'"`\s]{8,})['"`]""",
        r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*([A-Za-z0-9_\-]{16,})""",
    ],
    "Google API": [
        r"""AIza[0-9A-Za-z_\-]{35}""",
    ],
    "GitHub Tokens": [
        r"""gh[pousr]_[A-Za-z0-9_]{36,}""",
        r"""github_pat_[A-Za-z0-9_]{22,}""",
    ],
    "JWT / Bearer Tokens": [
        r"""eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+""",
        r"""[Bb]earer\s+[A-Za-z0-9_\-\.]+""",
    ],
    "Private Keys": [
        r"""-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\sKEY-----""",
    ],
    "Passwords / Secrets in Code": [
        r"""(?:password|passwd|pwd|secret|token|credential)\s*[=:]\s*['"`]([^'"`\s]{4,})['"`]""",
    ],
    "Stripe Keys": [
        r"""(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}""",
    ],
    "Slack Tokens": [
        r"""xox[bpoas]-[0-9]+-[A-Za-z0-9]+""",
    ],
    "Firebase": [
        r"""[a-z0-9\-]+\.firebaseio\.com""",
        r"""[a-z0-9\-]+\.firebaseapp\.com""",
    ],
    "SMTP / DB Connection Strings": [
        r"""(?:smtp|mysql|postgres|mongodb|redis)://[^\s'"`<>]+""",
    ],
    "Hardcoded Credentials": [
        r"""(?:admin|root|user|username)\s*[=:]\s*['"`]([^'"`\s]{3,})['"`]""",
    ],
}

DOM_SOURCES = {
    "URL-Based Sources": [
        r"""location\s*\.\s*(href|search|hash|pathname|origin|hostname|port|protocol)""",
        r"""document\s*\.\s*(URL|documentURI|baseURI|referrer)""",
        r"""window\s*\.\s*name""",
    ],
    "Storage Sources": [
        r"""localStorage\s*\.\s*getItem\s*\(""",
        r"""sessionStorage\s*\.\s*getItem\s*\(""",
        r"""document\s*\.\s*cookie""",
    ],
    "Message Sources": [
        r"""addEventListener\s*\(\s*['"`]message['"`]""",
        r"""onmessage\s*=""",
        r"""postMessage\s*\(""",
    ],
}

DOM_SINKS = {
    "HTML Injection Sinks": [
        r"""\.innerHTML\s*=""",
        r"""\.outerHTML\s*=""",
        r"""document\s*\.\s*write\s*\(""",
        r"""document\s*\.\s*writeln\s*\(""",
        r"""\.insertAdjacentHTML\s*\(""",
        r"""\.html\s*\(""",  # jQuery
        r"""\.append\s*\([^)]*['"<]""",  # jQuery with HTML
        r"""dangerouslySetInnerHTML""",  # React
        r"""v-html""",  # Vue
        r"""\[\s*innerHTML\s*\]""",  # Angular
    ],
    "JavaScript Execution Sinks": [
        r"""\beval\s*\(""",
        r"""setTimeout\s*\(\s*['"`]""",
        r"""setInterval\s*\(\s*['"`]""",
        r"""new\s+Function\s*\(""",
    ],
    "URL / Redirect Sinks": [
        r"""\.src\s*=""",
        r"""\.href\s*=""",
        r"""\.action\s*=""",
        r"""window\s*\.\s*open\s*\(""",
        r"""location\s*\.\s*(?:href|assign|replace)\s*=""",
        r"""location\s*=\s*""",
    ],
    "Prototype Pollution Sinks": [
        r"""__proto__""",
        r"""constructor\s*\[\s*['"`]prototype['"`]\s*\]""",
        r"""Object\s*\.\s*assign\s*\(""",
        r"""(?:\$\.extend|jQuery\.extend)\s*\(\s*true""",
        r"""\.merge\s*\(""",
        r"""\.deparam\s*\(""",
        r"""(?:qs|querystring)\.parse\s*\(""",
    ],
}

PII_PATTERNS = {
    "Email Patterns": [
        r"""[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+""",
    ],
    "Phone Patterns": [
        r"""(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}""",
    ],
    "SSN / National IDs": [
        r"""\b\d{3}[-]?\d{2}[-]?\d{4}\b""",
    ],
    "Credit Card Patterns": [
        r"""\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b""",
    ],
    "IP Addresses": [
        r"""\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b""",
    ],
    "PII Field Names": [
        r"""(?:ssn|social_security|passport|license_number|tax_id|national_id|aadhaar|pan_number)""",
    ],
}

AUTH_LOGIC_PATTERNS = {
    "Role / Permission Checks": [
        r"""(?:isAdmin|is_admin|isAuthenticated|isLoggedIn|hasPermission|hasRole|checkAuth)""",
        r"""(?:role|permission|privilege)\s*[=!]==?\s*['"`]""",
        r"""(?:admin|moderator|superuser|staff)\s*[=!]==?\s*true""",
    ],
    "Debug / Test Flags": [
        r"""(?:debug|DEBUG|test_mode|staging|development|devMode|isDev)\s*[=:]\s*(?:true|1|['"`])""",
        r"""(?:console\.log|console\.debug|console\.trace)\s*\(""",
    ],
    "Redirect / Callback": [
        r"""(?:redirect|returnUrl|return_url|next|callback|continue|goto|target|redir|destination)\s*=""",
    ],
    "Token Handling": [
        r"""(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem)\s*\(\s*['"`](?:token|auth|jwt|session|access_token)['"`]""",
        r"""(?:atob|btoa|jwt_decode|jwtDecode|JSON\.parse)\s*\(""",
    ],
}

INTERESTING_PATTERNS = {
    "Comments with TODO/FIXME/HACK": [
        r"""(?://|/\*)\s*(?:TODO|FIXME|HACK|BUG|XXX|SECURITY|VULN|TEMP|DEPRECATED)[:\s].*""",
    ],
    "Disabled Security": [
        r"""(?:csrf|xsrf|cors|csp|hsts)\s*[=:]\s*(?:false|disabled|off|none)""",
        r"""Access-Control-Allow-Origin\s*[=:]\s*['"`]\*['"`]""",
        r"""withCredentials\s*[=:]\s*true""",
    ],
    "File / Path Operations": [
        r"""(?:readFile|writeFile|appendFile|unlink|readdir|mkdir|rmdir)""",
        r"""(?:\.\.\/|\.\.\\)""",  # path traversal indicators
    ],
    "Crypto Operations": [
        r"""(?:CryptoJS|crypto\.subtle|createHash|createCipher|createSign)""",
        r"""(?:MD5|SHA1|SHA256|AES|RSA|HMAC)\b""",
    ],
    "WebSocket Endpoints": [
        r"""wss?://[a-zA-Z0-9\-\.]+[^\s'"`<>]*""",
    ],
    "Template Injection": [
        r"""(?:\{\{.*?\}\}|\$\{.*?\}|<%.*?%>)""",
    ],
}

COMMENT_PATTERNS = {
    "Credentials in Comments": [
        r"""(?:password|passwd|pwd)\s*[:=]\s*\S+""",
        r"""(?:username|user|login)\s*[:=]\s*['"`]?\w+""",
        r"""(?:email)\s*[:=]\s*[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.\w+""",
        r"""(?:secret|token|api[_-]?key|credential|cred)\s*[:=]\s*\S{4,}""",
        r"""(?:admin|root)\s*[:/@]\s*\S+""",
        r"""(?:test\s+(?:login|cred|account|user|password))""",
        r"""(?:default\s+(?:password|user|login|credential))""",
    ],
    "Internal URLs/IPs in Comments": [
        r"""https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s]*""",
        r"""https?://[a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|dev|staging|test)\.[a-zA-Z]+[^\s]*""",
    ],
    "Security-Related Comments": [
        r"""(?:TODO|FIXME|HACK|BUG|XXX)\s*[:!]?\s*.*(?:auth|secur|vuln|inject|xss|csrf|token|password|encrypt|bypass|workaround)""",
        r"""(?:disable|skip|remove|temporary|temp)\s+.*(?:auth|valid|check|verif|secur|csrf|cors)""",
    ],
    "Emails in Comments": [
        r"""[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}""",
    ],
    "API/Endpoint References in Comments": [
        r"""(?:endpoint|api|route|url)\s*[:=]?\s*['"`/]?(?:/[a-zA-Z0-9_/\-]+|https?://[^\s]+)""",
    ],
}

# ─────────────────────────────────────────────────────────────
# Known Libraries & CVEs
# ─────────────────────────────────────────────────────────────

KNOWN_LIBRARIES = [
    {"name": "jQuery", "patterns": [
        r"""jQuery\s+v?(\d+\.\d+\.\d+)""",
        r"""jquery[.\-](\d+\.\d+\.\d+)""",
        r"""\*\s*jQuery\s+JavaScript\s+Library\s+v(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Bootstrap", "patterns": [
        r"""Bootstrap\s+v?(\d+\.\d+\.\d+)""",
        r"""bootstrap[.\-](\d+\.\d+\.\d+)""",
    ]},
    {"name": "Popper.js", "patterns": [
        r"""Popper\.js\s+v?(\d+\.\d+\.\d+)""",
        r"""popper[.\-](\d+\.\d+\.\d+)""",
    ]},
    {"name": "Angular", "patterns": [
        r"""angular[.\-](\d+\.\d+\.\d+)""",
        r"""@angular/core.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "React", "patterns": [
        r"""react[.\-](\d+\.\d+\.\d+)""",
        r"""React\s+v?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Vue.js", "patterns": [
        r"""Vue\.js\s+v?(\d+\.\d+\.\d+)""",
        r"""vue[.\-](\d+\.\d+\.\d+)""",
    ]},
    {"name": "Lodash", "patterns": [
        r"""lodash[.\-](\d+\.\d+\.\d+)""",
        r"""Lodash\s+v?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Moment.js", "patterns": [
        r"""moment[.\-](\d+\.\d+\.\d+)""",
        r"""Moment\.js.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Underscore", "patterns": [
        r"""Underscore\.js\s+(\d+\.\d+\.\d+)""",
        r"""underscore[.\-](\d+\.\d+\.\d+)""",
    ]},
    {"name": "Axios", "patterns": [
        r"""axios[.\-](\d+\.\d+\.\d+)""",
    ]},
    {"name": "Owl Carousel", "patterns": [
        r"""Owl\s+Carousel.*?(\d+\.\d+\.\d+)""",
        r"""owl\.carousel.*?v?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Magnific Popup", "patterns": [
        r"""Magnific\s+Popup.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "noUiSlider", "patterns": [
        r"""noUiSlider.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "GMaps", "patterns": [
        r"""gmaps\.js\s+v?(\d+\.\d+\.\d+)""",
        r"""GMaps.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "Google Maps API", "patterns": [
        r"""maps\.googleapis\.com.*?v=(\d+\.?\d*)""",
        r"""Google\s+Maps\s+JavaScript\s+API.*?v(\d+\.\d+)""",
    ]},
    {"name": "Cloudflare Email Decode", "patterns": [
        r"""cloudflare.*?email.*?decode""",
    ]},
    {"name": "jQuery Nice Select", "patterns": [
        r"""jquery\.nice-select""",
        r"""Nice\s+Select.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "jQuery Sticky", "patterns": [
        r"""jquery\.sticky""",
        r"""Sticky.*?(\d+\.\d+\.\d+)""",
    ]},
    {"name": "jQuery AjaxChimp", "patterns": [
        r"""ajaxChimp""",
        r"""ajaxchimp.*?(\d+\.\d+\.\d+)""",
    ]},
]

def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)

KNOWN_CVES = [
    {"lib": "jQuery", "max_version": "1.12.0",
     "cves": ["CVE-2015-9251 (XSS via cross-domain ajax responses)"]},
    {"lib": "jQuery", "max_version": "3.4.99",
     "cves": ["CVE-2020-11022 (XSS in .html()/.append() with untrusted HTML)",
              "CVE-2020-11023 (XSS via option element injection)"]},
    {"lib": "jQuery", "max_version": "2.2.99",
     "cves": ["CVE-2019-11358 (Prototype pollution via $.extend)"]},
    {"lib": "Bootstrap", "max_version": "3.4.0",
     "cves": ["CVE-2019-8331 (XSS in tooltip/popover data-template)"]},
    {"lib": "Bootstrap", "max_version": "3.3.99",
     "cves": ["CVE-2018-14040 (XSS in collapse data-parent)",
              "CVE-2018-14042 (XSS in tooltip data-container)"]},
    {"lib": "Angular", "max_version": "1.5.99",
     "cves": ["CVE-2022-25869 (XSS via template injection)"]},
    {"lib": "Lodash", "max_version": "4.17.20",
     "cves": ["CVE-2021-23337 (Command injection via template)",
              "CVE-2020-28500 (ReDoS in _.trim)"]},
    {"lib": "Lodash", "max_version": "4.17.15",
     "cves": ["CVE-2019-10744 (Prototype pollution via defaultsDeep)"]},
    {"lib": "Moment.js", "max_version": "2.29.3",
     "cves": ["CVE-2022-31129 (ReDoS in date parsing)"]},
    {"lib": "Vue.js", "max_version": "2.6.13",
     "cves": ["CVE-2024-6783 (ReDoS in parseHTML)"]},
]

# Common JS paths for brute-forcing
JS_WORDLIST = [
    # Common JS directories
    "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js", "/js/chunk.js",
    "/js/common.js", "/js/config.js", "/js/api.js", "/js/auth.js", "/js/admin.js",
    "/js/utils.js", "/js/helpers.js", "/js/login.js", "/js/dashboard.js",
    "/js/custom.js", "/js/script.js", "/js/scripts.js", "/js/functions.js",
    # jQuery plugins
    "/js/jquery.min.js", "/js/jquery.js",
    "/js/jquery.ajaxchimp.min.js", "/js/jquery.nice-select.min.js",
    "/js/jquery.sticky.js", "/js/jquery.magnific-popup.min.js",
    # Common libraries
    "/js/bootstrap.min.js", "/js/bootstrap.js", "/js/bootstrap.bundle.min.js",
    "/js/owl.carousel.min.js", "/js/nouislider.min.js", "/js/countdown.js",
    "/js/gmaps.min.js", "/js/hidesections.js",
    "/js/vendor/jquery-2.2.4.min.js", "/js/vendor/jquery-3.6.0.min.js",
    "/js/vendor/bootstrap.min.js", "/js/vendor/modernizr-2.8.3.min.js",
    # Static paths
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/static/js/vendor.js", "/static/js/runtime.js",
    # Build/dist paths
    "/dist/app.js", "/dist/bundle.js", "/dist/main.js",
    "/build/static/js/main.js", "/build/static/js/bundle.js",
    # Assets paths
    "/assets/js/app.js", "/assets/js/main.js", "/assets/js/bundle.js",
    "/assets/application.js", "/assets/vendor.js",
    # Other common paths
    "/bundles/app.js", "/bundles/vendor.js",
    "/scripts/main.js", "/scripts/app.js",
    "/public/js/app.js", "/public/js/main.js",
    "/lib/jquery/jquery.min.js", "/lib/bootstrap/js/bootstrap.min.js",
    # Build manifests
    "/webpack-manifest.json", "/asset-manifest.json", "/manifest.json",
    "/stats.json", "/precache-manifest.js",
    # Service workers
    "/sw.js", "/service-worker.js", "/serviceworker.js",
    # Meta
    "/robots.txt", "/sitemap.xml",
]


# ─────────────────────────────────────────────────────────────
# Collector
# ─────────────────────────────────────────────────────────────

class JSCollector:
    def __init__(self, base_url, output_dir, cookies=None, headers=None, verify_ssl=True, max_pages=100):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.seen_hashes = set()
        self.collected = []
        self.visited_pages = set()
        self.discovered_pages = set()
        self.max_pages = max_pages

        if cookies:
            for cookie in cookies.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    self.session.cookies.set(name.strip(), value.strip())

        if headers:
            for header in headers:
                if ":" in header:
                    name, value = header.split(":", 1)
                    self.session.headers[name.strip()] = value.strip()

        self.session.headers.setdefault("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    def _save_js(self, url, content, source_type="crawl"):
        content_hash = hashlib.md5(content.encode(errors="replace")).hexdigest()
        if content_hash in self.seen_hashes:
            return None
        self.seen_hashes.add(content_hash)

        parsed = urlparse(url)
        filename = parsed.path.strip("/").replace("/", "_") or "index"
        if not filename.endswith(".js"):
            filename += ".js"
        filename = re.sub(r'[^\w.\-]', '_', filename)

        filepath = self.output_dir / filename
        counter = 1
        while filepath.exists():
            filepath = self.output_dir / f"{filepath.stem}_{counter}.js"
            counter += 1

        filepath.write_text(content, encoding="utf-8")
        entry = {"url": url, "file": str(filepath), "source": source_type, "size": len(content)}
        self.collected.append(entry)
        return filepath

    def _save_inline(self, page_url, script_content, index):
        content_hash = hashlib.md5(script_content.encode(errors="replace")).hexdigest()
        if content_hash in self.seen_hashes:
            return None
        self.seen_hashes.add(content_hash)

        parsed = urlparse(page_url)
        page_name = parsed.path.strip("/").replace("/", "_") or "index"
        filename = f"inline_{page_name}_{index}.js"
        filename = re.sub(r'[^\w.\-]', '_', filename)

        filepath = self.output_dir / filename
        filepath.write_text(script_content, encoding="utf-8")
        entry = {"url": f"{page_url}#inline_{index}", "file": str(filepath),
                 "source": "inline", "size": len(script_content)}
        self.collected.append(entry)
        return filepath

    def _fetch(self, url):
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            redirects = 0
            while resp.is_redirect and redirects < 5:
                redirect_url = resp.headers.get("Location", "")
                if redirect_url:
                    redirect_url = urljoin(url, redirect_url)
                    redirect_parsed = urlparse(redirect_url)
                    if redirect_parsed.netloc != self.parsed_base.netloc:
                        return None
                    resp = self.session.get(redirect_url, timeout=8, allow_redirects=False)
                    redirects += 1
                else:
                    break
            if resp.status_code == 200:
                return resp
        except requests.RequestException:
            pass
        return None

    def _is_same_origin(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.parsed_base.netloc or parsed.netloc == ""

    def _normalize_url(self, url):
        parsed = urlparse(url)
        clean = parsed._replace(fragment="", query="")
        return clean.geturl().rstrip("/")

    def _extract_links(self, soup, page_url):
        links = set()
        skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
                    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".mp3", ".webp"}
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(page_url, href)
            if not self._is_same_origin(full_url):
                continue
            ext = os.path.splitext(urlparse(full_url).path)[1].lower()
            if ext in skip_ext:
                continue
            links.add(self._normalize_url(full_url))

        for tag in soup.find_all("form", action=True):
            action = tag["action"].strip()
            if action and not action.startswith(("#", "javascript:")):
                full_url = urljoin(page_url, action)
                if self._is_same_origin(full_url):
                    links.add(self._normalize_url(full_url))

        for pattern in [r"""['"](/[a-zA-Z0-9_\-/]+)['"]""",
                        r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]"""]:
            for match in re.finditer(pattern, str(soup)):
                href = match.group(1)
                if href.startswith("/") and not any(href.endswith(e) for e in skip_ext):
                    full_url = urljoin(page_url, href)
                    if self._is_same_origin(full_url):
                        links.add(self._normalize_url(full_url))

        return links

    def crawl_page(self, url):
        normalized = self._normalize_url(url)
        if normalized in self.visited_pages:
            return []
        self.visited_pages.add(normalized)

        console.print(f"  [dim]Crawling:[/] {url}")
        resp = self._fetch(url)
        if not resp:
            return []

        ct = resp.headers.get("content-type", "")
        if "html" not in ct and "text" not in ct:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        js_urls = []

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                full_url = urljoin(url, src)
                js_urls.append(full_url)
            elif tag.string and len(tag.string.strip()) > 50:
                self._save_inline(url, tag.string.strip(),
                                  len([e for e in self.collected if e["source"] == "inline"]))

        for pattern in [r'import\s*\(?\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
                        r'from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]']:
            for match in re.finditer(pattern, resp.text):
                js_urls.append(urljoin(url, match.group(1)))

        for js_url in js_urls:
            js_resp = self._fetch(js_url)
            if js_resp and ("javascript" in js_resp.headers.get("content-type", "")
                           or js_url.endswith(".js")):
                self._save_js(js_url, js_resp.text, "crawl")

        new_links = self._extract_links(soup, url)
        self.discovered_pages.update(new_links)

        return js_urls

    def spider(self, seed_urls):
        console.print(f"[bold]Step 1: Auto-spidering the application[/]")
        console.print(f"  [dim]Max pages: {self.max_pages}[/]")

        normalized_seeds = [self._normalize_url(u) for u in seed_urls]
        queue = list(dict.fromkeys(normalized_seeds))
        self.discovered_pages.update(queue)

        while queue and len(self.visited_pages) < self.max_pages:
            url = queue.pop(0)
            self.crawl_page(url)

            for link in self.discovered_pages - self.visited_pages:
                if link not in queue:
                    queue.append(link)

        console.print(f"  [green]Spidered {len(self.visited_pages)} pages, "
                      f"discovered {len(self.discovered_pages)} total links[/]")

    def _bruteforce_one(self, path):
        url = self.base_url + path
        resp = self._fetch(url)
        if resp:
            ct = resp.headers.get("content-type", "")
            if any(t in ct for t in ["javascript", "json", "text/plain", "xml"]):
                return (path, url, resp.text)
        return None

    def bruteforce(self):
        console.print(f"  [dim]Brute-forcing {len(JS_WORDLIST)} common paths (10 threads)...[/]")
        found = 0
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(self._bruteforce_one, p): p for p in JS_WORDLIST}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, url, text = result
                    self._save_js(url, text, "bruteforce")
                    found += 1
                    console.print(f"    [green]+[/] {path}")
        console.print(f"  [dim]Brute-force found {found} files[/]")

    def check_source_maps(self):
        console.print("  [dim]Checking for source maps...[/]")
        found = 0
        for entry in list(self.collected):
            if entry["source"] == "inline":
                continue
            map_url = entry["url"] + ".map"
            resp = self._fetch(map_url)
            if resp:
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    continue
                try:
                    if "sources" in data:
                        map_path = self.output_dir / "sourcemaps"
                        map_path.mkdir(exist_ok=True)
                        filename = urlparse(entry["url"]).path.strip("/").replace("/", "_") + ".map"
                        (map_path / filename).write_text(resp.text, encoding="utf-8")
                        found += 1
                        console.print(f"    [green]+[/] Source map: {map_url}")
                        console.print(f"      Contains {len(data['sources'])} original sources")
                except (json.JSONDecodeError, KeyError):
                    pass
        console.print(f"  [dim]Found {found} source maps[/]")

    def enumerate_chunks(self):
        console.print("  [dim]Scanning for webpack/bundler chunk patterns...[/]")
        chunk_patterns = [
            r"""['"]((?:static/js|js|dist|build|assets/js|bundles)/\d+[\w\-\.]*\.(?:chunk\.)?js)['"]""",
            r"""['"]((?:static/js|js|dist|build)/[a-f0-9]{6,20}\.js)['"]""",
            r"""(?:chunkFilename|__webpack_require__\.p\s*\+\s*)['"](.*?)['"]""",
            r"""webpackJsonp""",
            r"""__webpack_require__""",
        ]

        chunk_base_paths = set()
        has_webpack = False
        for entry in list(self.collected):
            if entry["source"] == "inline":
                try:
                    content = Path(entry["file"]).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
            else:
                try:
                    content = Path(entry["file"]).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

            for pattern in chunk_patterns[-2:]:
                if re.search(pattern, content):
                    has_webpack = True
                    break

            for pattern in chunk_patterns[:3]:
                for match in re.finditer(pattern, content):
                    path = match.group(1) if match.lastindex else None
                    if path:
                        dir_part = "/".join(path.split("/")[:-1])
                        if dir_part:
                            chunk_base_paths.add(dir_part)

        if not has_webpack and not chunk_base_paths:
            console.print("  [dim]No bundler patterns detected[/]")
            return

        if not chunk_base_paths:
            chunk_base_paths = {"static/js", "js", "dist"}

        console.print(f"  [dim]Bundler detected. Probing chunk paths: {', '.join(chunk_base_paths)}[/]")
        found = 0

        def probe_chunk(url):
            resp = self._fetch(url)
            if resp and ("javascript" in resp.headers.get("content-type", "") or url.endswith(".js")):
                return (url, resp.text)
            return None

        urls_to_check = []
        for base in chunk_base_paths:
            for i in range(50):
                urls_to_check.append(f"{self.base_url}/{base}/{i}.js")
                urls_to_check.append(f"{self.base_url}/{base}/{i}.chunk.js")

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(probe_chunk, u): u for u in urls_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    url, text = result
                    saved = self._save_js(url, text, "chunk_enum")
                    if saved:
                        found += 1
                        console.print(f"    [green]+[/] {urlparse(url).path}")

        console.print(f"  [dim]Chunk enumeration found {found} files[/]")

    def check_build_artifacts(self):
        console.print("  [dim]Checking for build artifacts...[/]")
        artifacts = [
            "/webpack-manifest.json", "/asset-manifest.json", "/manifest.json",
            "/stats.json", "/build-manifest.json", "/chunk-manifest.json",
        ]
        for path in artifacts:
            url = self.base_url + path
            resp = self._fetch(url)
            if resp:
                ct = resp.headers.get("content-type", "")
                if "json" not in ct and "javascript" not in ct:
                    continue
                try:
                    data = resp.json()
                    artifact_path = self.output_dir / "build_artifacts"
                    artifact_path.mkdir(exist_ok=True)
                    filename = path.strip("/").replace("/", "_")
                    (artifact_path / filename).write_text(
                        json.dumps(data, indent=2), encoding="utf-8")
                    console.print(f"    [green]+[/] {path}")

                    for key, value in self._extract_js_from_manifest(data):
                        full_url = urljoin(url, value)
                        js_resp = self._fetch(full_url)
                        if js_resp:
                            self._save_js(full_url, js_resp.text, "manifest")
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass

    def _extract_js_from_manifest(self, data, prefix=""):
        if isinstance(data, dict):
            for k, v in data.items():
                yield from self._extract_js_from_manifest(v, f"{prefix}.{k}")
        elif isinstance(data, list):
            for item in data:
                yield from self._extract_js_from_manifest(item, prefix)
        elif isinstance(data, str) and data.endswith(".js"):
            yield (prefix, data)

    def collect_all(self, extra_pages=None):
        seed_urls = [self.base_url, self.base_url + "/"]
        if extra_pages:
            for p in extra_pages:
                if p.startswith("/"):
                    seed_urls.append(self.base_url + p)
                else:
                    seed_urls.append(p)

        console.print(Panel("[bold]Phase 1: Collection[/]", style="blue"))

        self.spider(seed_urls)

        console.print(f"\n[bold]Step 2: Brute-forcing JS paths[/]")
        self.bruteforce()

        console.print(f"\n[bold]Step 3: Webpack/Bundler chunk enumeration[/]")
        self.enumerate_chunks()

        console.print(f"\n[bold]Step 4: Source map check[/]")
        self.check_source_maps()

        console.print(f"\n[bold]Step 5: Build artifact check[/]")
        self.check_build_artifacts()

        manifest = self.output_dir / "collection_manifest.json"
        manifest.write_text(json.dumps({
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "files": self.collected,
            "total": len(self.collected),
        }, indent=2), encoding="utf-8")

        console.print(f"\n[green]Collected {len(self.collected)} unique JS files → {self.output_dir}[/]\n")
        return self.collected


# ─────────────────────────────────────────────────────────────
# Analyzer
# ─────────────────────────────────────────────────────────────

class JSAnalyzer:
    def __init__(self, js_dir):
        self.js_dir = Path(js_dir)
        self.findings = defaultdict(lambda: defaultdict(list))
        self.files_analyzed = 0
        self.total_lines = 0
        self.severity_counts = defaultdict(int)

    def _scan_file(self, filepath, patterns, category):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        lines = content.split("\n")
        for subcategory, regex_list in patterns.items():
            for regex in regex_list:
                for i, line in enumerate(lines, 1):
                    line_stripped = line.strip()
                    if len(line_stripped) > 500:
                        continue
                    for match in re.finditer(regex, line_stripped, re.IGNORECASE):
                        finding = {
                            "file": str(filepath.name),
                            "line": i,
                            "match": match.group(0)[:200],
                            "context": line_stripped[:300],
                        }
                        key = f"{filepath.name}:{i}:{match.group(0)[:80]}"
                        if not any(f["file"] == finding["file"] and f["line"] == finding["line"]
                                   and f["match"] == finding["match"]
                                   for f in self.findings[category][subcategory]):
                            self.findings[category][subcategory].append(finding)

    def _extract_comments(self, content):
        comments = []
        for match in re.finditer(r'//(.*)$', content, re.MULTILINE):
            text = match.group(1).strip()
            if len(text) > 3:
                line_num = content[:match.start()].count('\n') + 1
                comments.append((line_num, text))
        for match in re.finditer(r'/\*(.+?)\*/', content, re.DOTALL):
            text = match.group(1).strip()
            if len(text) > 3:
                line_num = content[:match.start()].count('\n') + 1
                comments.append((line_num, text))
        return comments

    def _scan_comments(self, filepath):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        comments = self._extract_comments(content)
        if not comments:
            return

        for subcategory, regex_list in COMMENT_PATTERNS.items():
            for regex in regex_list:
                for line_num, comment_text in comments:
                    for match in re.finditer(regex, comment_text, re.IGNORECASE):
                        finding = {
                            "file": str(filepath.name),
                            "line": line_num,
                            "match": match.group(0)[:200],
                            "context": f"// {comment_text[:300]}",
                        }
                        if not any(f["file"] == finding["file"] and f["line"] == finding["line"]
                                   and f["match"] == finding["match"]
                                   for f in self.findings["Comments & Developer Notes"][subcategory]):
                            self.findings["Comments & Developer Notes"][subcategory].append(finding)

    @staticmethod
    def _calculate_entropy(s):
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _scan_high_entropy_strings(self, filepath):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        skip_prefixes = ("http://", "https://", "data:", "//", "/", ".", "#", "rgb", "hsl",
                         "var(", "url(", "0x", "\\x", "function", "return", "undefined",
                         "object", "string", "number", "boolean", "the ", "this ", "a ",
                         "an ", "is ", "are ", "was ", "has ", "have ", "will ", "can ")
        skip_patterns = re.compile(
            r'^(?:'
            r'[a-fA-F0-9]{6}$|'              # hex colors
            r'[a-zA-Z_$][\w$.]*$|'             # identifiers
            r'.*[<>{}\[\]()]+.*$|'             # code/HTML fragments
            r'(?:\.[-\w]+)+$|'                 # CSS selectors / file paths
            r'[A-Za-z0-9]+(?:[=:;,][ A-Za-z0-9]+)+$|'  # key:value pairs / enums
            r'(?:src|href|class|id|style|type|name|value|placeholder|alt|title)$|'
            r'[0-9A-Za-z]{16,}$'               # pure alphanumeric charset strings
            r')')

        for match in re.finditer(r"""(['"`])(.{16,200}?)\1""", content):
            s = match.group(2)
            if any(s.lower().startswith(p) for p in skip_prefixes):
                continue
            if skip_patterns.match(s):
                continue
            if ' ' in s:
                continue
            if s.count('\\') > 3:
                continue
            entropy = self._calculate_entropy(s)
            if entropy > 4.5:
                line_num = content[:match.start()].count('\n') + 1
                finding = {
                    "file": str(filepath.name),
                    "line": line_num,
                    "match": f"[entropy={entropy:.2f}] {s[:120]}",
                    "context": content.split('\n')[line_num - 1].strip()[:300] if line_num <= content.count('\n') + 1 else "",
                }
                self.findings["Secrets & API Keys"]["High Entropy Strings"].append(finding)

    def _fingerprint_libraries(self, filepath):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        header = content[:5000]
        for lib in KNOWN_LIBRARIES:
            for pattern in lib["patterns"]:
                match = re.search(pattern, header, re.IGNORECASE)
                if match:
                    try:
                        version = match.group(1)
                    except IndexError:
                        version = "unknown"
                    lib_info = {"name": lib["name"], "version": version or "unknown",
                                "file": str(filepath.name), "cves": []}
                    if version and version != "unknown":
                        vt = _version_tuple(version)
                        for cve_entry in KNOWN_CVES:
                            if cve_entry["lib"] == lib["name"]:
                                if vt <= _version_tuple(cve_entry["max_version"]):
                                    lib_info["cves"].extend(cve_entry["cves"])
                    return lib_info
        return None

    def _scan_encoded_strings(self, filepath):
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        b64_pattern = re.compile(r"""['"`]([A-Za-z0-9+/]{20,}={0,2})['"`]""")
        for match in b64_pattern.finditer(content):
            encoded = match.group(1)
            if encoded.startswith(("data:", "http", "//")):
                continue
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="strict")
                if not all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    continue
                if len(decoded) < 8:
                    continue
                line_num = content[:match.start()].count('\n') + 1

                interesting = False
                check_patterns = [
                    (r'(?:password|secret|token|key|api|auth|admin|credential)', "Potential secret"),
                    (r'https?://', "Embedded URL"),
                    (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', "Embedded email"),
                    (r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\s', "Embedded SQL"),
                    (r'(?:\{.*?:.*?\}|\[.*?\])', "Embedded JSON/config"),
                ]
                for pat, desc in check_patterns:
                    if re.search(pat, decoded, re.IGNORECASE):
                        interesting = True
                        finding = {
                            "file": str(filepath.name),
                            "line": line_num,
                            "match": f"[b64→{desc}] {decoded[:120]}",
                            "context": f"Encoded: {encoded[:80]}...",
                        }
                        self.findings["Secrets & API Keys"]["Decoded Strings"].append(finding)
                        break

                if not interesting and self._calculate_entropy(decoded) > 4.0:
                    finding = {
                        "file": str(filepath.name),
                        "line": line_num,
                        "match": f"[b64→high-entropy] {decoded[:120]}",
                        "context": f"Encoded: {encoded[:80]}...",
                    }
                    self.findings["Secrets & API Keys"]["Decoded Strings"].append(finding)
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                continue

    @staticmethod
    def _beautify_js(content):
        try:
            import jsbeautifier
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            return jsbeautifier.beautify(content, opts)
        except ImportError:
            result = re.sub(r';(?!\s*\n)', ';\n', content)
            result = re.sub(r'\{(?!\s*\n)', '{\n', result)
            result = re.sub(r'\}(?!\s*\n)', '}\n', result)
            return result

    def analyze_all(self, skip_libs=False, beautify=False):
        js_files = list(self.js_dir.glob("**/*.js"))
        if not js_files:
            console.print("[red]No .js files found in the specified directory.[/]")
            return

        console.print(Panel("[bold]Phase 2: Analysis[/]", style="blue"))

        self.lib_results = []
        lib_files = set()
        for filepath in js_files:
            lib_info = self._fingerprint_libraries(filepath)
            if lib_info:
                self.lib_results.append(lib_info)
                lib_files.add(filepath.name)
                cve_text = f" — {len(lib_info['cves'])} known CVE(s)" if lib_info["cves"] else ""
                finding = {
                    "file": lib_info["file"],
                    "line": 1,
                    "match": f"{lib_info['name']} v{lib_info['version']}{cve_text}",
                    "context": "; ".join(lib_info["cves"][:3]) if lib_info["cves"] else "No known CVEs",
                }
                self.findings["Third-Party Libraries"]["Identified Libraries"].append(finding)
                for cve in lib_info["cves"]:
                    self.findings["Third-Party Libraries"]["Known CVEs"].append({
                        "file": lib_info["file"],
                        "line": 1,
                        "match": cve,
                        "context": f"{lib_info['name']} v{lib_info['version']}",
                    })

        if skip_libs and lib_files:
            console.print(f"[dim]--skip-libs: excluding {len(lib_files)} third-party files from pattern analysis[/]")

        analyze_files = [f for f in js_files if not (skip_libs and f.name in lib_files)]
        console.print(f"[dim]Analyzing {len(analyze_files)} JS files"
                      f"{f' (skipped {len(lib_files)} libraries)' if skip_libs and lib_files else ''}...[/]\n")

        beautified_dir = None
        if beautify:
            beautified_dir = self.js_dir / "_beautified"
            beautified_dir.mkdir(exist_ok=True)
            console.print("[dim]Beautifying JS files before analysis...[/]")

        for filepath in analyze_files:
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                self.total_lines += content.count("\n")
            except Exception:
                continue

            if beautify and beautified_dir:
                content = self._beautify_js(content)
                bf_path = beautified_dir / filepath.name
                bf_path.write_text(content, encoding="utf-8")

            self.files_analyzed += 1
            self._scan_file(filepath, ENDPOINT_PATTERNS, "Endpoints & API Surface")
            self._scan_file(filepath, SECRET_PATTERNS, "Secrets & API Keys")
            self._scan_file(filepath, DOM_SOURCES, "DOM Sources (Input)")
            self._scan_file(filepath, DOM_SINKS, "DOM Sinks (Execution)")
            self._scan_file(filepath, PII_PATTERNS, "PII & Sensitive Data")
            self._scan_file(filepath, AUTH_LOGIC_PATTERNS, "Auth & Business Logic")
            self._scan_file(filepath, INTERESTING_PATTERNS, "Interesting Patterns")
            self._scan_comments(filepath)
            self._scan_high_entropy_strings(filepath)
            self._scan_encoded_strings(filepath)

    def _severity_for_category(self, category):
        severity_map = {
            "Secrets & API Keys": "CRITICAL",
            "Comments & Developer Notes": "HIGH",
            "DOM Sinks (Execution)": "HIGH",
            "DOM Sources (Input)": "MEDIUM",
            "PII & Sensitive Data": "HIGH",
            "Auth & Business Logic": "MEDIUM",
            "Endpoints & API Surface": "INFO",
            "Third-Party Libraries": "MEDIUM",
            "Interesting Patterns": "LOW",
        }
        return severity_map.get(category, "INFO")

    def print_report(self):
        console.print(Panel("[bold]JS Recon Report[/]", style="green"))

        stats_table = Table(box=box.SIMPLE, show_header=False)
        stats_table.add_column("Key", style="bold")
        stats_table.add_column("Value")
        stats_table.add_row("Files Analyzed", str(self.files_analyzed))
        stats_table.add_row("Total Lines", f"{self.total_lines:,}")
        stats_table.add_row("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        console.print(stats_table)
        console.print()

        total_findings = 0
        for category, subcats in self.findings.items():
            severity = self._severity_for_category(category)
            color_map = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow",
                         "LOW": "cyan", "INFO": "blue"}
            sev_color = color_map.get(severity, "white")

            cat_count = sum(len(items) for items in subcats.values())
            if cat_count == 0:
                continue
            total_findings += cat_count
            self.severity_counts[severity] += cat_count

            console.print(f"\n[{sev_color}]{'━' * 60}[/]")
            console.print(f"[{sev_color}][{severity}] {category} ({cat_count} findings)[/]")
            console.print(f"[{sev_color}]{'━' * 60}[/]")

            for subcat, items in subcats.items():
                if not items:
                    continue
                console.print(f"\n  [bold]{subcat}[/] ({len(items)} hits)")
                displayed = items[:15]
                for f in displayed:
                    match_display = f["match"]
                    if len(match_display) > 100:
                        match_display = match_display[:100] + "..."
                    console.print(f"    [dim]{f['file']}:{f['line']}[/]  {match_display}")
                if len(items) > 15:
                    console.print(f"    [dim]... and {len(items) - 15} more[/]")

        console.print(f"\n{'═' * 60}")
        summary_table = Table(title="Summary", box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.severity_counts.get(sev, 0)
            if count > 0:
                color_map = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow",
                             "LOW": "cyan", "INFO": "blue"}
                summary_table.add_row(f"[{color_map[sev]}]{sev}[/]", str(count))
        summary_table.add_row("[bold]TOTAL[/]", f"[bold]{total_findings}[/]")
        console.print(summary_table)

    def get_unique_endpoints(self):
        endpoints = set()
        for subcat, items in self.findings.get("Endpoints & API Surface", {}).items():
            for item in items:
                match = item["match"]
                cleaned = re.sub(r"""^['"`]|['"`]$""", "", match)
                if cleaned.startswith("/") or cleaned.startswith("http"):
                    endpoints.add(cleaned)
        return sorted(endpoints)

    def get_unique_secrets(self):
        secrets = []
        for subcat, items in self.findings.get("Secrets & API Keys", {}).items():
            for item in items:
                secrets.append({
                    "type": subcat,
                    "file": item["file"],
                    "line": item["line"],
                    "match": item["match"][:80],
                })
        return secrets

    def get_dom_flows(self):
        sources = []
        sinks = []
        for subcat, items in self.findings.get("DOM Sources (Input)", {}).items():
            for item in items:
                sources.append({"type": subcat, "file": item["file"],
                                "line": item["line"], "code": item["match"]})
        for subcat, items in self.findings.get("DOM Sinks (Execution)", {}).items():
            for item in items:
                sinks.append({"type": subcat, "file": item["file"],
                              "line": item["line"], "code": item["match"]})

        flows = []
        for source in sources:
            for sink in sinks:
                if source["file"] == sink["file"]:
                    flows.append({
                        "file": source["file"],
                        "source": f"{source['type']} (line {source['line']}): {source['code'][:60]}",
                        "sink": f"{sink['type']} (line {sink['line']}): {sink['code'][:60]}",
                    })
        return flows

    def export_json(self, output_path):
        report = {
            "scan_info": {
                "directory": str(self.js_dir),
                "files_analyzed": self.files_analyzed,
                "total_lines": self.total_lines,
                "timestamp": datetime.now().isoformat(),
            },
            "summary": dict(self.severity_counts),
            "endpoints": self.get_unique_endpoints(),
            "secrets": self.get_unique_secrets(),
            "dom_flows": self.get_dom_flows(),
            "libraries": getattr(self, "lib_results", []),
            "findings": {
                cat: {
                    subcat: items
                    for subcat, items in subcats.items() if items
                }
                for cat, subcats in self.findings.items()
                if any(items for items in subcats.values())
            },
        }
        Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"\n[green]JSON report saved → {output_path}[/]")

    def export_html(self, output_path):
        endpoints = self.get_unique_endpoints()
        secrets = self.get_unique_secrets()
        dom_flows = self.get_dom_flows()

        def esc(text):
            return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        severity_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04", "LOW": "#0891b2", "INFO": "#2563eb",
        }

        findings_html = ""
        for category, subcats in self.findings.items():
            severity = self._severity_for_category(category)
            cat_count = sum(len(items) for items in subcats.values())
            if cat_count == 0:
                continue
            color = severity_colors.get(severity, "#666")
            findings_html += f"""
            <div class="category">
                <h2><span class="badge" style="background:{color}">{severity}</span> {esc(category)}
                    <span class="count">({cat_count})</span></h2>"""
            for subcat, items in subcats.items():
                if not items:
                    continue
                findings_html += f"""
                <div class="subcategory">
                    <h3>{esc(subcat)} ({len(items)})</h3>
                    <table>
                        <tr><th>File</th><th>Line</th><th>Match</th></tr>"""
                for f in items[:50]:
                    findings_html += f"""
                        <tr>
                            <td class="file">{esc(f['file'])}</td>
                            <td class="line">{f['line']}</td>
                            <td class="match"><code>{esc(f['match'][:150])}</code></td>
                        </tr>"""
                if len(items) > 50:
                    findings_html += f"""
                        <tr><td colspan="3" class="more">... and {len(items) - 50} more</td></tr>"""
                findings_html += "</table></div>"
            findings_html += "</div>"

        endpoints_html = ""
        if endpoints:
            endpoints_html = "<h2>Discovered Endpoints</h2><ul class='endpoints'>"
            for ep in endpoints:
                endpoints_html += f"<li><code>{esc(ep)}</code></li>"
            endpoints_html += "</ul>"

        secrets_html = ""
        if secrets:
            secrets_html = """<h2>Potential Secrets</h2>
            <table><tr><th>Type</th><th>File</th><th>Line</th><th>Match</th></tr>"""
            for s in secrets:
                secrets_html += f"""<tr>
                    <td>{esc(s['type'])}</td><td class="file">{esc(s['file'])}</td>
                    <td class="line">{s['line']}</td>
                    <td class="match"><code>{esc(s['match'])}</code></td></tr>"""
            secrets_html += "</table>"

        dom_html = ""
        if dom_flows:
            dom_html = """<h2>Potential DOM-Based Flows (Same File)</h2>
            <table><tr><th>File</th><th>Source</th><th>Sink</th></tr>"""
            for flow in dom_flows[:100]:
                dom_html += f"""<tr>
                    <td class="file">{esc(flow['file'])}</td>
                    <td><code>{esc(flow['source'])}</code></td>
                    <td><code>{esc(flow['sink'])}</code></td></tr>"""
            dom_html += "</table>"

        libs_html = ""
        lib_results = getattr(self, "lib_results", [])
        if lib_results:
            libs_html = """<h2>Identified Third-Party Libraries</h2>
            <table><tr><th>Library</th><th>Version</th><th>File</th><th>Known CVEs</th></tr>"""
            for lib in lib_results:
                cve_text = "<br>".join(esc(c) for c in lib["cves"]) if lib["cves"] else '<span style="color:#4ade80">None known</span>'
                row_style = ' style="background:#3b1111"' if lib["cves"] else ""
                libs_html += f"""<tr{row_style}>
                    <td><strong>{esc(lib['name'])}</strong></td>
                    <td>{esc(lib['version'])}</td>
                    <td class="file">{esc(lib['file'])}</td>
                    <td>{cve_text}</td></tr>"""
            libs_html += "</table>"

        total = sum(self.severity_counts.values())
        summary_items = "".join(
            f'<div class="stat"><span class="stat-num" style="color:{severity_colors.get(s,"#666")}">'
            f'{self.severity_counts.get(s,0)}</span><span class="stat-label">{s}</span></div>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if self.severity_counts.get(s, 0) > 0
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JS Recon Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }}
  h1 {{ color: #f1f5f9; margin-bottom: .5rem; font-size: 1.8rem; }}
  h2 {{ color: #94a3b8; margin: 1.5rem 0 .75rem; font-size: 1.2rem; border-bottom: 1px solid #334155; padding-bottom: .5rem; }}
  h3 {{ color: #cbd5e1; font-size: 1rem; margin: .75rem 0 .5rem; }}
  .meta {{ color: #64748b; font-size: .85rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1.5rem; margin: 1.5rem 0; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; min-width: 100px; text-align: center; }}
  .stat-num {{ display: block; font-size: 2rem; font-weight: 700; }}
  .stat-label {{ display: block; font-size: .75rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }}
  .category {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: .75rem;
            font-weight: 600; vertical-align: middle; margin-right: .5rem; }}
  .count {{ color: #64748b; font-weight: 400; font-size: .9rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; margin: .5rem 0; }}
  th {{ text-align: left; background: #0f172a; color: #94a3b8; padding: 8px 12px; font-weight: 600; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #1e293b; }}
  .file {{ color: #38bdf8; white-space: nowrap; }}
  .line {{ color: #a78bfa; text-align: center; }}
  .match code {{ color: #fbbf24; font-size: .8rem; word-break: break-all; }}
  .more {{ color: #64748b; font-style: italic; text-align: center; }}
  .endpoints {{ list-style: none; columns: 2; }}
  .endpoints li {{ padding: 3px 0; }}
  .endpoints code {{ color: #34d399; font-size: .85rem; }}
  .subcategory {{ margin-left: 1rem; }}
  code {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; }}
</style>
</head>
<body>
  <h1>JS Recon Report</h1>
  <div class="meta">
    Directory: {esc(str(self.js_dir))} |
    Files: {self.files_analyzed} |
    Lines: {self.total_lines:,} |
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  </div>
  <div class="stats">
    <div class="stat"><span class="stat-num" style="color:#f1f5f9">{total}</span><span class="stat-label">Total Findings</span></div>
    {summary_items}
  </div>
  {libs_html}
  {secrets_html}
  {dom_html}
  {endpoints_html}
  {findings_html}
</body>
</html>"""
        Path(output_path).write_text(html, encoding="utf-8")
        console.print(f"[green]HTML report saved → {output_path}[/]")


# ─────────────────────────────────────────────────────────────
# Diff Mode
# ─────────────────────────────────────────────────────────────

def diff_collections(dir_a, dir_b):
    console.print(Panel("[bold]JS Diff — Pre-Auth vs Post-Auth Comparison[/]", style="magenta"))
    path_a, path_b = Path(dir_a), Path(dir_b)

    def hash_files(directory):
        result = {}
        for f in directory.glob("**/*.js"):
            if f.name.startswith("_") or "beautified" in str(f):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                result[f.name] = hashlib.md5(content.encode(errors="replace")).hexdigest()
            except Exception:
                continue
        return result

    hashes_a = hash_files(path_a)
    hashes_b = hash_files(path_b)

    only_a = set(hashes_a.keys()) - set(hashes_b.keys())
    only_b = set(hashes_b.keys()) - set(hashes_a.keys())
    common = set(hashes_a.keys()) & set(hashes_b.keys())
    modified = {f for f in common if hashes_a[f] != hashes_b[f]}
    unchanged = common - modified

    label_a = path_a.name
    label_b = path_b.name

    console.print(f"\n[bold]Comparison:[/] {label_a} (A) vs {label_b} (B)")
    console.print(f"  Files in A: {len(hashes_a)}")
    console.print(f"  Files in B: {len(hashes_b)}")

    if only_b:
        console.print(f"\n[green bold]Files only in B (auth-gated / new JS):[/]")
        for f in sorted(only_b):
            size = (path_b / f).stat().st_size
            console.print(f"  [green]+[/] {f}  ({size:,} bytes)")

    if only_a:
        console.print(f"\n[red bold]Files only in A (removed after auth):[/]")
        for f in sorted(only_a):
            console.print(f"  [red]-[/] {f}")

    if modified:
        console.print(f"\n[yellow bold]Files in both but modified:[/]")
        for f in sorted(modified):
            console.print(f"  [yellow]~[/] {f}")

    console.print(f"\n[dim]Unchanged: {len(unchanged)} files[/]")
    console.print(f"\n[bold]Summary:[/] +{len(only_b)} new | -{len(only_a)} removed | ~{len(modified)} modified | ={len(unchanged)} unchanged")

    return {"only_a": sorted(only_a), "only_b": sorted(only_b),
            "modified": sorted(modified), "unchanged": sorted(unchanged)}


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JS Recon — JavaScript Enumeration & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python3 js_recon.py collect -u https://target.com -o ./js_loot
          python3 js_recon.py collect -u https://target.com -c "session=abc; token=xyz" -o ./js_loot
          python3 js_recon.py collect -u https://target.com -m 200 -o ./js_loot   (spider 200 pages)
          python3 js_recon.py analyze -d ./js_loot --html report.html --json report.json
          python3 js_recon.py full -u https://target.com -o ./js_loot --html report.html
        """))

    sub = parser.add_subparsers(dest="command", required=True)

    # collect
    collect_p = sub.add_parser("collect", help="Collect JS files from a target")
    collect_p.add_argument("-u", "--url", required=True, help="Target base URL")
    collect_p.add_argument("-o", "--output", required=True, help="Output directory for JS files")
    collect_p.add_argument("-c", "--cookies", help="Cookies string (name=value; name2=value2)")
    collect_p.add_argument("-H", "--header", action="append", help="Custom header (Name: Value), repeatable")
    collect_p.add_argument("-p", "--pages", nargs="+", help="Extra seed pages to start spidering from (optional)")
    collect_p.add_argument("-m", "--max-pages", type=int, default=100, help="Max pages to spider (default: 100)")
    collect_p.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")

    # analyze
    analyze_p = sub.add_parser("analyze", help="Analyze collected JS files")
    analyze_p.add_argument("-d", "--dir", required=True, help="Directory containing JS files")
    analyze_p.add_argument("--json", dest="json_out", help="Export JSON report")
    analyze_p.add_argument("--html", dest="html_out", help="Export HTML report")
    analyze_p.add_argument("--skip-libs", action="store_true", help="Skip third-party libraries in pattern analysis")
    analyze_p.add_argument("--beautify", action="store_true", help="Beautify minified JS before analysis")

    # full
    full_p = sub.add_parser("full", help="Collect + Analyze in one shot")
    full_p.add_argument("-u", "--url", required=True, help="Target base URL")
    full_p.add_argument("-o", "--output", required=True, help="Output directory")
    full_p.add_argument("-c", "--cookies", help="Cookies string")
    full_p.add_argument("-H", "--header", action="append", help="Custom header, repeatable")
    full_p.add_argument("-p", "--pages", nargs="+", help="Extra seed pages to start spidering from (optional)")
    full_p.add_argument("-m", "--max-pages", type=int, default=100, help="Max pages to spider (default: 100)")
    full_p.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")
    full_p.add_argument("--json", dest="json_out", help="Export JSON report")
    full_p.add_argument("--html", dest="html_out", help="Export HTML report")
    full_p.add_argument("--skip-libs", action="store_true", help="Skip third-party libraries in pattern analysis")
    full_p.add_argument("--beautify", action="store_true", help="Beautify minified JS before analysis")

    # diff
    diff_p = sub.add_parser("diff", help="Compare two collection directories (e.g., pre-auth vs post-auth)")
    diff_p.add_argument("-a", "--dir-a", required=True, help="First directory (e.g., pre-auth collection)")
    diff_p.add_argument("-b", "--dir-b", required=True, help="Second directory (e.g., post-auth collection)")
    diff_p.add_argument("--json", dest="json_out", help="Export diff results as JSON")

    args = parser.parse_args()

    console.print(Panel(
        "[bold green]JS Recon[/] — JavaScript Enumeration & Analysis Tool\n"
        "[dim]For authorized security testing only[/]",
        border_style="green"))

    if args.command in ("collect", "full"):
        collector = JSCollector(
            base_url=args.url,
            output_dir=args.output,
            cookies=args.cookies,
            headers=args.header,
            verify_ssl=not args.insecure,
            max_pages=args.max_pages,
        )
        collector.collect_all(extra_pages=args.pages)

    if args.command == "diff":
        result = diff_collections(args.dir_a, args.dir_b)
        if hasattr(args, "json_out") and args.json_out:
            Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
            console.print(f"[green]Diff JSON saved → {args.json_out}[/]")
        return

    if args.command in ("analyze", "full"):
        js_dir = args.dir if args.command == "analyze" else args.output
        skip_libs = getattr(args, "skip_libs", False)
        beautify = getattr(args, "beautify", False)

        analyzer = JSAnalyzer(js_dir)
        analyzer.analyze_all(skip_libs=skip_libs, beautify=beautify)
        analyzer.print_report()

        if hasattr(args, "json_out") and args.json_out:
            analyzer.export_json(args.json_out)
        if hasattr(args, "html_out") and args.html_out:
            analyzer.export_html(args.html_out)

        unique_endpoints = analyzer.get_unique_endpoints()
        if unique_endpoints:
            ep_file = Path(js_dir) / "endpoints.txt"
            ep_file.write_text("\n".join(unique_endpoints), encoding="utf-8")
            console.print(f"[dim]Endpoint list saved → {ep_file}[/]")

        dom_flows = analyzer.get_dom_flows()
        if dom_flows:
            console.print(f"\n[yellow bold]Potential DOM-based flows detected ({len(dom_flows)} source→sink pairs in same file)[/]")
            console.print("[dim]These need manual verification — same file doesn't guarantee data flow.[/]")


if __name__ == "__main__":
    main()
