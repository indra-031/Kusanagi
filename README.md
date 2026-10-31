<div align="center">

 █████   ████                                                             ███ 
░░███   ███░                                                             ░░░  
 ░███  ███    █████ ████  █████   ██████   ████████    ██████    ███████ ████ 
 ░███████    ░░███ ░███  ███░░   ░░░░░███ ░░███░░███  ░░░░░███  ███░░███░░███ 
 ░███░░███    ░███ ░███ ░░█████   ███████  ░███ ░███   ███████ ░███ ░███ ░███ 
 ░███ ░░███   ░███ ░███  ░░░░███ ███░░███  ░███ ░███  ███░░███ ░███ ░███ ░███ 
 █████ ░░████ ░░████████ ██████ ░░████████ ████ █████░░████████░░███████ █████
░░░░░   ░░░░   ░░░░░░░░ ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░  ░░░░░░░░  ░░░░░███░░░░░ 
                                                                ███ ░███      
                                                               ░░██████       
                                                                ░░░░░░        
                401 / 403 Bypass Testing Tool

*Named after the legendary Japanese sword — Kusanagi no Tsurugi*

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

</div>

---

## ⚡ Features

- **Fully self-contained** — no third-party bash scripts required (bypass-403, 4-ZERO-3, etc. are built-in).
- **High Performance** — Multi-threaded (`-t`) with HTTP keep-alive connection pooling (3.7x faster).
- **WAF/CDN Detection** — Automatically detects Cloudflare, Cloudfront, etc., and adjusts thread count to avoid rate-limiting (Uses `wafw00f` if installed).
- **Rate Limiting** — Configurable delay between requests (`-d`) to evade strict WAFs.
- **50+ header injection payloads** — IP spoofing, proxy headers, path override, host variations.
- **HTTP verb tampering** — GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, WebDAV methods.
- **Path manipulation** — 290+ payloads (slashes, dots, semicolons, encoding, traversal, IIS tricks).
- **Advanced Encoding** — Double/triple URL encoding, sliding single/double-char encoding.
- **Targeted parameter tampering** — HPP, array syntax, value tampering, case variation.
- **Host header bypass** — Auto-detects Host-based access control.
- **Method override headers** — `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`.
- **Resume Support** — Skip already-tested targets if a run crashes (`--resume`).
- **JSON Output** — Save structured results for easy parsing (`--json`).
- **Screenshots** — Take headless-browser screenshots of actual bypasses (not 403 pages) using Playwright (`--screenshot`).
- **Status code filtering** — Hide noise like 404, 405, 500 from the terminal (`-fc`).
- **Telegram Notifications** — Grouped by category, includes 4xx low-confidence hits, supports forum topics.
- **Multi-target** — Single URL or file-based target list.

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- `wafw00f` (Optional, but **highly recommended** for accurate WAF detection)
- `playwright` (Optional, required only for the `--screenshot` feature)

### Install dependencies

```bash
# Update system
sudo apt update
sudo apt install -y python3 python3-pip

# Install Kusanagi requirements (from requirement.txt)
pip install -r requirement.txt

# Install optional tools for advanced features
pip install wafw00f
playwright install chromium
```

### Clone the repository

```bash
git clone https://github.com/<your-username>/kusanagi.git
cd kusanagi
```

---

## ⚙️ Configuration (`config.json`)

Kusanagi uses a `config.json` file to store settings. If you don't need Telegram notifications, you can leave it disabled.

```json
{
  "telegram": {
    "enabled": true,
    "bot_token": "BOT_TOKEN",
    "chat_id": "CHAT_ID",
    "thread_id": ""
  }
}
```

### 📨 Telegram Setup Guide

To receive bypass notifications directly on your phone, follow these steps:

1. **Create a Bot:**
   - Open Telegram and search for [@BotFather](https://t.me/BotFather).
   - Send `/newbot` and follow the instructions.
   - Copy the **HTTP API Token** (e.g., `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`).
   - Paste this into `"bot_token"` in `config.json`.

2. **Get your Chat ID:**
   - Search for [@userinfobot](https://t.me/userinfobot) on Telegram.
   - Send `/start`. It will reply with your **Id** (e.g., `123456789`).
   - Paste this into `"chat_id"` in `config.json`.
   - *(Note: If you are sending to a Group, the ID usually starts with `-100...`)*

3. **Get your Topic ID (Optional):**
   - If you are sending to a specific topic in a Group with "Topics" enabled:
   - Right-click on the topic message -> **Copy Link**.
   - The link looks like `https://t.me/c/1234567890/457`.
   - The last number (`457`) is your `"thread_id"`. Paste it into `config.json`.
   - If you don't use topics, leave it as `""`.

4. **Enable Notifications:**
   - Set `"enabled": true` in `config.json`.

---

## 🚀 Usage

### Basic

```bash
python3 kusanagi.py -u https://example.com/admin
```

### Custom path & Threads

```bash
python3 kusanagi.py -u https://example.com -p secret-panel -t 20
```

### With cookie & follow redirects

```bash
python3 kusanagi.py -u https://example.com/admin -c "session=abc123" -L
```

### Delay between requests (WAF bypass)

```bash
python3 kusanagi.py -u https://example.com/admin -d 1.5
```

### Filter status codes (Hide 404s)

```bash
python3 kusanagi.py -u https://example.com/admin -fc 404
```

### Multi-target from file

```bash
python3 kusanagi.py -f urls.txt -t 15
```

### Save results to JSON

```bash
python3 kusanagi.py -f urls.txt --json results.json
```

### Resume from a crashed run

```bash
python3 kusanagi.py -f urls.txt --resume
```

### Take screenshots of bypasses

```bash
python3 kusanagi.py -u https://example.com/admin --screenshot ./evidence --screenshot-max 5
```

### Full automation combo (Watchtower workflow)

```bash
python3 kusanagi.py -f urls.txt -fc 404 -t 10 --resume --json report.json --screenshot --telegram
```

---

## 📋 CLI Options

```
  -u, --url URL              Single target URL
  -f, --file FILE            File with target URLs (one per line)
  -p, --path PATH            Default target path (default: kusanagi)
  -c, --cookie COOKIE        Cookie header value
  -t, --threads INT          Number of concurrent workers (default: 10)
  -T, --timeout FLOAT        Per-request timeout (default: 10.0)
  -d, --delay FLOAT          Delay in seconds between requests (default: 0)
  -L, --follow               Follow redirects
  -a, --all                  Show every test, not only interesting ones
  -v, --verbose              Show every test as '<test> | status: <code>'
  -fc, --filter-code CODES   Hide status codes (e.g. 404 or 404,405)

  --resume                   Skip targets already recorded in resume file
  --reset-resume             Clear the resume file before starting
  --json FILE                Save results as structured JSON
  --screenshot [DIR]         Take screenshots of bypasses (default: screenshots)
  --screenshot-max INT       Max screenshots per target (default: 5)
  --wayback                  Look up cached versions in the Wayback Machine

  --no-waf00w                Skip WAF/CDN detection
  --waf-threads INT          Override auto-reduced threads for WAFs

  --telegram / --no-telegram Force or disable Telegram notifications
  --thread-id ID             Telegram forum topic ID

  -h, --help                 Show help
```

---

## 📁 Project Structure

```
kusanagi/
├── kusanagi.py                  # Entry point
├── config.json                  # Configuration (Telegram)
├── requirement.txt              # Python dependencies
├── kusanagi_core/
│   ├── __init__.py
│   ├── analyzer.py              # Response classification
│   ├── banner.py                # ASCII banner
│   ├── baseline.py              # Baseline probing
│   ├── cli.py                   # Argument parsing
│   ├── colors.py                # ANSI colors
│   ├── config_loader.py         # Config file loader
│   ├── extended_tests.py        # IP variants, sliding encode, wayback
│   ├── http_client.py           # Raw HTTP with keep-alive
│   ├── json_writer.py           # Structured JSON output
│   ├── param_tamper.py          # Targeted parameter tampering
│   ├── path_slash_bypass.py     # Path confusion payloads
│   ├── payload_loader.py        # Payload file loader
│   ├── rate_limiter.py          # Thread-safe delay
│   ├── reporter.py              # Output + summary (thread-safe)
│   ├── resume_manager.py        # Resume state tracking
│   ├── screenshot.py            # Playwright screenshot engine
│   ├── target_loader.py         # Target file loader
│   ├── task.py                  # Task object wrapper
│   ├── telegram_notifier.py     # Telegram notifications
│   └── waf00w.py                # WAF/CDN detection
├── payloads/
│   ├── headers.txt              # Header injection payloads
│   ├── header_case.txt          # Case-varied header payloads
│   ├── host_headers.txt         # Host header variations
│   ├── methods.txt              # HTTP methods
│   ├── override_headers.txt     # Path override headers
│   ├── params.txt               # Generic parameter tampering
│   └── paths.txt                # Path manipulation payloads
```

---

## 🧠 How It Works

### Analyzer Logic

By default, any status code **other than 401 or 403** is treated as a potential bypass candidate:

| Status Range | Tag | Confidence |
|---|---|---|
| 200–299 | `BYPASS-2xx` | High |
| 300–399 | `BYPASS-3xx` | High |
| 400–499 | `BYPASS-4xx?` | Low (verify manually) |
| 500–599 | `BYPASS-5xx` | Medium |

> A 4xx code is not automatically a vulnerability. Always verify the response body and content.

### Host Header Auto-Detection

Before running Host variations, Kusanagi probes with a bogus Host (`probe.invalid.example`). If the probe returns 401/403, Host-based access control is detected and used as the effective baseline.

### Raw HTTP Client

Kusanagi uses Python's `http.client` directly (not `requests` or `urllib`) so that payloads like `/admin/..;/` are sent **without normalization** — this is critical for path confusion testing.

---

## 🎯 Payload Categories

### Header Injection (`payloads/headers.txt`)

```http
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
Client-IP: 127.0.0.1
X-HTTP-Method-Override: GET
Content-Type: application/json
```

### Path Manipulation (`payloads/paths.txt`)

```http
/admin/
/admin/.
/admin/..
/admin/..;/
/admin%00
/admin%2f
/admin%252f
//admin
/./admin
/;/admin
/admin.json
/admin.bak
```

### Parameter Tampering (dynamic)

For a target like `?id=123`, Kusanagi generates:

```http
?id=123&id=0
?id=0&id=123
?id[]=123
?id[0]=123
?id=0
?id=admin
?ID=123
?id=123&admin=1
```

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.**

Use it only against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions.

The authors assume no liability for misuse or damage caused by this tool. Always follow responsible disclosure practices.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Credits

- **Kusanagi** — main tool, analysis engine, integrations
- **@iamj0ker** — Original bypass-403 concept
- **@Dheerajmadhukar** — Original 4-ZERO-3 concept
- **@nexovir** — Original Forbira concept
- **@zack0x01** — 403-Bypass-lab (reference practice lab)

---

<div align="center">

**🗡️ Learn. Hack. Grow.**

</div>