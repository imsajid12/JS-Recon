# JS Recon

**JavaScript Enumeration & Analysis Tool for Penetration Testers**

JS Recon automates the collection and security analysis of JavaScript files from web applications. It spiders the target, downloads all external and inline JS, then runs pattern-based analysis to surface secrets, API endpoints, DOM-based vulnerabilities, hardcoded credentials, outdated libraries with known CVEs, and more.

Built for pentesters who want to extract maximum signal from JS during web app assessments.

## Features

- **Auto-Spidering** — Crawls the target application to discover pages, following same-origin links up to a configurable depth
- **JS Collection** — Downloads external scripts, extracts inline `<script>` blocks, and deduplicates by content hash
- **Path Brute-Forcing** — Probes common JS paths (`/static/js/`, `/assets/js/`, `/dist/`, etc.) to find files not linked in HTML
- **Webpack Chunk Enumeration** — Detects webpack bundles and probes numbered chunk files (0-49)
- **10-Category Pattern Analysis** — Regex-based scanning across secrets, endpoints, DOM sources/sinks, PII, auth logic, and more
- **Comment Parser** — Extracts `//` and `/* */` comments and runs targeted credential/email/URL patterns against them
- **Entropy-Based Secret Detection** — Flags high-entropy string literals (Shannon entropy > 4.5) that may be unknown-format secrets
- **Third-Party Library Fingerprinting** — Identifies 13+ library families with version detection and CVE cross-referencing
- **Base64 Decoder** — Finds base64-encoded strings, decodes them, and re-analyzes for secrets/URLs/config
- **JS Beautification** — Optionally de-minifies JS before analysis (uses `jsbeautifier` or built-in fallback)
- **Pre-Auth vs Post-Auth Diff** — Compares two collection directories to identify auth-gated or modified JS files
- **DOM Flow Detection** — Identifies source-to-sink pairs within the same file for manual DOM XSS verification
- **Multi-Format Export** — Terminal output with color-coded severity, plus HTML and JSON report export
- **Authenticated Collection** — Supports cookies and custom headers for testing behind authentication
- **Cloudflare Access Support** — Handles `CF_Authorization` and redirect-based auth flows
- **Parallel Downloads** — Multi-threaded JS file fetching for speed

## Installation

### Requirements

- Python 3.7+
- pip

### Dependencies

```bash
pip3 install requests beautifulsoup4 rich
```

Optional (for better JS beautification):

```bash
pip3 install jsbeautifier
```

### Setup

No installation required. Clone the repo and run directly:

```bash
git clone https://github.com/YOUR_USERNAME/js-recon.git
cd js-recon
python3 js_recon.py -h
```

## Usage

JS Recon has four subcommands: `collect`, `analyze`, `full`, and `diff`.

### Collect — Download JS files from a target

```bash
# Basic collection (spiders up to 100 pages)
python3 js_recon.py collect -u https://target.com -o ./js_loot

# With authentication cookies
python3 js_recon.py collect -u https://target.com -c "session=abc123; token=xyz" -o ./js_loot

# With custom headers
python3 js_recon.py collect -u https://target.com -H "Authorization: Bearer TOKEN" -o ./js_loot

# Spider more pages
python3 js_recon.py collect -u https://target.com -m 200 -o ./js_loot

# Add extra seed pages to start spidering from
python3 js_recon.py collect -u https://target.com -p /admin /api/docs -o ./js_loot

# Disable SSL verification
python3 js_recon.py collect -u https://target.com -k -o ./js_loot
```

**What it does:**
1. Spiders the target starting from the base URL (and any `-p` seed pages)
2. Extracts all `<script src="...">` references and inline `<script>` blocks
3. Brute-forces common JS paths (`/static/js/app.js`, `/dist/bundle.js`, etc.)
4. Enumerates webpack chunks if webpack patterns are detected
5. Downloads and deduplicates everything into the output directory

| Flag | Description |
|------|-------------|
| `-u, --url` | Target base URL (required) |
| `-o, --output` | Output directory for JS files (required) |
| `-c, --cookies` | Cookie string (`name=value; name2=value2`) |
| `-H, --header` | Custom header (`Name: Value`), repeatable |
| `-p, --pages` | Extra seed pages to spider from |
| `-m, --max-pages` | Max pages to spider (default: 100) |
| `-k, --insecure` | Disable SSL certificate verification |

### Analyze — Scan collected JS files

```bash
# Basic analysis
python3 js_recon.py analyze -d ./js_loot

# Skip third-party libraries in pattern scan (recommended)
python3 js_recon.py analyze -d ./js_loot --skip-libs

# Export HTML report
python3 js_recon.py analyze -d ./js_loot --skip-libs --html report.html

# Export JSON report
python3 js_recon.py analyze -d ./js_loot --json report.json

# Beautify minified JS before analysis
python3 js_recon.py analyze -d ./js_loot --beautify --skip-libs

# All options combined
python3 js_recon.py analyze -d ./js_loot --skip-libs --beautify --html report.html --json report.json
```

| Flag | Description |
|------|-------------|
| `-d, --dir` | Directory containing collected JS files (required) |
| `--skip-libs` | Exclude fingerprinted third-party libraries from pattern analysis |
| `--beautify` | De-minify JS before analysis |
| `--html` | Export findings as an HTML report |
| `--json` | Export findings as a JSON report |

### Full — Collect + Analyze in one shot

```bash
# Complete pipeline
python3 js_recon.py full -u https://target.com -o ./js_loot --html report.html

# With auth and noise reduction
python3 js_recon.py full -u https://target.com -c "session=abc" -o ./js_loot --skip-libs --html report.html
```

Accepts all flags from both `collect` and `analyze`.

### Diff — Compare two collections

```bash
# Compare pre-auth vs post-auth JS
python3 js_recon.py diff -a ./preauth_loot -b ./postauth_loot

# Export diff as JSON
python3 js_recon.py diff -a ./preauth_loot -b ./postauth_loot --json diff_results.json
```

| Flag | Description |
|------|-------------|
| `-a, --dir-a` | First directory (e.g., pre-auth collection) (required) |
| `-b, --dir-b` | Second directory (e.g., post-auth collection) (required) |
| `--json` | Export diff results as JSON |

**Use case:** Run `collect` without cookies (pre-auth), then again with cookies (post-auth), and diff to find JS files only served to authenticated users — these often contain admin endpoints, internal APIs, or business logic.

## Analysis Categories

JS Recon scans across 10 categories, each with a severity rating:

| Severity | Category | What it finds |
|----------|----------|---------------|
| CRITICAL | Secrets & API Keys | API keys, tokens, passwords in code, high-entropy strings |
| HIGH | Comments & Developer Notes | Credentials in comments, internal URLs, security notes, emails |
| HIGH | DOM Sinks (Execution) | `innerHTML`, `eval()`, `document.write()`, `.src =` assignments |
| HIGH | PII & Sensitive Data | Email patterns, SSN/phone fields, PII-related variable names |
| MEDIUM | Auth & Business Logic | Debug flags, `console.log`, redirects, role checks, token handling |
| MEDIUM | DOM Sources (Input) | `location.search`, `document.URL`, `window.name`, `postMessage` |
| MEDIUM | Third-Party Libraries | Library identification, version detection, known CVE matching |
| INFO | Endpoints & API Surface | API routes, HTTP methods, full URLs, WebSocket endpoints |
| LOW | Interesting Patterns | Eval usage, dynamic imports, storage access, regex patterns |

### Library CVE Database

The built-in CVE database covers:

- **jQuery** — CVE-2020-11022, CVE-2020-11023, CVE-2019-11358
- **Bootstrap** — CVE-2019-8331, CVE-2018-14040, CVE-2018-14042
- **Angular** — CVE-2022-25869
- **Lodash** — CVE-2021-23337, CVE-2020-28500, CVE-2019-10744
- **Moment.js** — CVE-2022-31129
- **Vue.js** — CVE-2024-6783

## Output

### Terminal

Color-coded findings grouped by severity and category, with a summary table at the end. DOM source-to-sink flow pairs are highlighted for manual XSS verification.

### HTML Report

Self-contained HTML file with:
- Summary statistics
- Findings grouped by severity with file:line references
- Library fingerprinting table with CVE highlighting (red background)
- Endpoint list extraction

### JSON Report

Machine-readable output with all findings, library data, and metadata — useful for integration with other tools or CI pipelines.

### Endpoint List

Automatically extracts all discovered API routes and URLs into an `endpoints.txt` file in the output directory, ready for further testing with tools like Burp Suite or ffuf.

## Recommended Workflow

```
# 1. Collect JS (unauthenticated)
python3 js_recon.py collect -u https://target.com -o ./preauth_js

# 2. Collect JS (authenticated)
python3 js_recon.py collect -u https://target.com -c "session=COOKIE_HERE" -o ./postauth_js

# 3. Diff to find auth-gated JS
python3 js_recon.py diff -a ./preauth_js -b ./postauth_js

# 4. Analyze with noise reduction
python3 js_recon.py analyze -d ./postauth_js --skip-libs --html report.html

# 5. Review endpoints.txt for API testing
# 6. Investigate HIGH/CRITICAL findings manually
# 7. Trace DOM source→sink pairs for XSS verification
```

## Example Output

```
╭──────────────────────────────────────────────────────────────────╮
│ JS Recon Report                                                  │
╰──────────────────────────────────────────────────────────────────╯

  Files Analyzed   23
  Total Lines      1,330

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[HIGH] Comments & Developer Notes (8 findings)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Credentials in Comments (3 hits)
    main.js:354  Password: test
    main.js:353  Email: test@email.com
    main.js:351  Test login

════════════════════════════════════════════════════════════
      Summary
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     1 │
│ HIGH     │    54 │
│ MEDIUM   │    65 │
│ INFO     │    35 │
│ TOTAL    │   155 │
╰──────────┴───────╯
```

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper written authorization before testing any application you do not own. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## License

MIT
