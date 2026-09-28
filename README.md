```
 █     █░ ██▓███     ▒██   ██▒ ██▀███   ▄▄▄     ▓██   ██▓
▓█░ █ ░█░▓██░  ██▒   ▒▒ █ █ ▒░▓██ ▒ ██▒▒████▄    ▒██  ██▒
▒█░ █ ░█ ▓██░ ██▓▒   ░░  █   ░▓██ ░▄█ ▒▒██  ▀█▄   ▒██ ██░
░█░ █ ░█ ▒██▄█▓▒ ▒    ░ █ █ ▒ ▒██▀▀█▄  ░██▄▄▄▄██  ░ ▐██▓░
░░██▒██▓ ▒██▒ ░  ░   ▒██▒ ▒██▒░██▓ ▒██▒ ▓█   ▓██▒ ░ ██▒▓░
░ ▓░▒ ▒  ▒▓▒░ ░  ░   ▒▒ ░ ░▓ ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░  ██▒▒▒
  ▒ ░ ░  ░▒ ░        ░░   ░▒ ░  ░▒ ░ ▒░  ▒   ▒▒ ░▓██ ░▒░
  ░   ░  ░░           ░    ░    ░░   ░   ░   ▒   ▒ ▒ ░░
    ░                 ░    ░     ░           ░  ░░ ░
                                                 ░ ░

  WPX — WordPress X-Ray Scanner | WAF Bypass
```

WPX (WordPress X-Ray) is a security scanner that uses Camoufox to solve Cloudflare and WAF challenges. It mirrors those sessions to perform fast, asynchronous plugin and theme discovery, user enumeration, and multisite detection.

**Note**: WPX downloads necessary scan metadata (fingerprints, detection rules) from `data.wpscan.org`.

## Features

*   **WAF bypass**: Uses Camoufox headless browser to solve challenges and extract session tokens.
*   **Asynchronous scanning**: Built with `asyncio` and `curl_cffi` for fast enumeration.
*   **Fingerprinting**: Mimics browser fingerprints and TLS handshakes to avoid detection.
*   **User enumeration**: Discovers WordPress usernames via REST API, author archives, oEmbed, and RSS feed.
*   **Multisite detection**: Identifies WordPress Multisite/Network installations.
*   **WPScan API**: Integrates with the WPScan Vulnerability Database for vulnerability lookups.
*   **Offline-replayable scans**: Collection never contacts the WPScan API. Save a scan artifact once, then enrich and report from it as many times as you like — fully offline with respect to the target.
*   **Massive Plugin Catalog**: Tracks ~110,000 historical and ~55,000 current plugins.
*   **Plugin cataloging**: Includes a script to fetch and rank plugin slugs from WordPress.org.
*   **CLI output**: Structured terminal output similar to `wpscan`.
*   **Stealth mode**: High-fidelity browser impersonation and TLS session mirroring.

## Docker

The easiest way to run WPX — no Python or dependencies needed.

### Pull and run
```bash
docker run ghcr.io/greg-randall/wpx -u https://example.com
```

### Save results to your machine
```bash
docker run -v $(pwd):/output ghcr.io/greg-randall/wpx -u https://example.com -o /output/results.txt
```

### Persist WPScan metadata between runs (recommended)
Without a volume, WPX re-downloads metadata on every run. Mount a named volume to avoid this:
```bash
docker run -v wpx-data:/app/.wpx_data ghcr.io/greg-randall/wpx -u https://example.com
```

Refresh the metadata manually when needed:
```bash
docker run -v wpx-data:/app/.wpx_data ghcr.io/greg-randall/wpx --update
```

## Installation

### 1. Clone and Install
```bash
git clone https://github.com/greg-randall/wpx.git
cd wpx
pip install .
```

### 2. Setup Camoufox
```bash
python3 -m camoufox fetch
```

## Usage

### Basic scan
```bash
python3 wpx.py -u https://example.com
```

**[View Example Output](example-output.txt)**

### Vulnerability scan (requires API key)
```bash
python3 wpx.py -u https://example.com --api-key YOUR_API_KEY
```

### Flexible plugin enumeration
Scan a specific number of top-ranked plugins (e.g., top 500):
```bash
python3 wpx.py -u https://example.com --plugins-limit 500
```

### Full plugin brute-force
Scan every plugin ever created. WPX can traverse the entire historical library of ~110,000 plugins (including ~55,000 currently active ones) to find every trace of software on the target.
**Warning**: This performs a massive number of requests and can take several hours to complete depending on your thread count and the target's responsiveness.
```bash
python3 wpx.py -u https://example.com --full-scan
```

### User enumeration
User enumeration runs automatically. To limit the author ID probe range, or disable it entirely
by leaving `u` out of `-e/--enumerate` (default is all of `p,u,cb,t`):
```bash
python3 wpx.py -u https://example.com --users-limit 20
python3 wpx.py -u https://example.com -e p,cb,t
```

### Silent output and logging
Run a scan silently and save results to a file without ANSI color codes:
```bash
python3 wpx.py -u https://example.com --quiet --output results.txt
```

### Refresh plugin data
To update the plugin lists and rank by popularity:
```bash
python3 data/wpx_fetch_plugins.py --sort-by score
```

Outputs `data/plugins_active.txt` (default top 5000) and `data/plugins_dead.txt` (default top 2500).
To change the limits:
```bash
python3 data/wpx_fetch_plugins.py --active-limit 10000 --dead-limit 5000
```

## Collection, Enrichment & Reporting (offline replay)

WPX separates scanning into three independent steps: **collect** the target, **enrich** the
findings against the WPScan Vulnerability Database, and **report** the result. Collection
*never* calls the WPScan API — no key is required, none is contacted, and it works fully
offline once the scan artifact is saved. Enrichment and reporting only ever read that saved
artifact; neither one re-contacts the target.

A default `wpx.py -u URL` run still does all three steps in sequence, exactly as before. The
steps below just let you run them independently, or replay enrichment/reporting later without
rescanning.

### Collection artifact

Every scan (unless `--no-artifact` is passed) writes a scan directory:

```
scans/<timestamp>-<host>/
├── scan.json           # run metadata: target, timestamp, options used
├── inventory.json       # normalized findings: WordPress/theme/plugin versions,
│                         # each with a confidence score and its evidence — an
│                         # unknown version is recorded as such, never guessed
└── vulnerability.json   # WPScan enrichment result, written by `enrich` (absent
                          # until enrichment has run at least once)
```

Choose where it's written with `--scan-dir DIR` (default: an auto-generated
`scans/<timestamp>-<host>/`), or skip it with `--no-artifact`.

### Collect only — never touch the WPScan API

```bash
python3 wpx.py -u https://example.com --collect-only
```

Builds `scan.json` + `inventory.json` and stops there. `WPXVulnerability`/`WPScanEnricher` is
never even constructed in this mode — if `--api-key` is also passed by mistake, WPX warns and
ignores it rather than making a request.

### Enrich a saved scan — never touch the target

```bash
python3 wpx.py enrich scans/<scan-id>/ --api-key YOUR_API_KEY
```

Loads only `inventory.json`, queries WPScan once per distinct plugin slug already in it (never
per detection source, never re-discovering anything), and writes `vulnerability.json`. A
WPScan failure (bad key, quota, outage) is recorded in `vulnerability.json` as a failed status
rather than raised — `scan.json`/`inventory.json` are never touched, and you can re-run
`enrich` later once the issue is resolved. Running it again on the same scan directory simply
overwrites `vulnerability.json` with a fresh result.

**Note**: `enrich` still depends on the WPScan Vulnerability Database's own availability,
rate limits, and terms of service. It never bypasses your API key's quota or caches WPScan
vulnerability data as a substitute for a valid subscription — it only lets you decide *when*
to spend a query against inventory you already collected.

### Report a saved scan — no network access at all

```bash
python3 wpx.py report scans/<scan-id>/
```

Prints the same rich terminal report as a full scan, reading only `scan.json` + `inventory.json`
(+ `vulnerability.json` if `enrich` has been run). Works with or without enrichment — a scan
that was never enriched (or whose enrichment failed) still gets a complete report of what was
*observed*; it's just missing the WPScan-known-vulnerabilities section. The report always
separates the two explicitly: an **observation** is something collection actually saw on the
target, with its own confidence and evidence, independent of WPScan; an **enrichment** is a
known WPScan CVE for the plugin *slug* queried, which may or may not apply to the exact version
observed — WPX never presents a WPScan hit as confirmed exploitation.

## Data management

The `data/` directory contains the processed plugin datasets and maintenance tools:

*   **`data/plugins_active.txt`**: Top active plugin slugs ranked by popularity score (geometric mean of installs × downloads).
*   **`data/plugins_dead.txt`**: Top closed/removed plugin slugs ranked by historical install count (sourced from previous catalog runs or Archive.org snapshots).
*   **`data/plugins_catalog.json`**: Cached metadata for active plugins.
*   **`data/plugins_dead.jsonl`**: Append-only cache of dead plugin metadata including last-known install counts. New entries override old ones on load (last-write-wins).
*   **`data/archive.org-cache/`**: Raw HTML snapshots from the Wayback Machine, used to recover historical install counts for plugins closed before the first catalog run.
*   **`data/wpx_fetch_plugins.py`**: Fetcher that combines the WordPress.org API, SVN repository, and Archive.org to build and enrich the plugin lists.

## Advanced Options

### Main Scanner (`wpx.py`)

| Flag | Description |
|------|-------------|
| `-u, --url` | Target WordPress URL (required). |
| `--api-key` | WPScan Vulnerability Database API Key. Ignored (with a warning) if `--collect-only` is also set. |
| `-e, --enumerate OPTS` | Comma-separated scan selection: `p` (plugins), `u` (users), `cb` (config backups), `t` (theme). Default: all. |
| `-t, --threads` | Concurrent threads for scanning (Default: 20). |
| `--plugins-limit` | Limit the number of plugins to scan (e.g. 500, 5000). |
| `--full-scan` | Scans all available plugin slugs (up to 50k+). |
| `--update` | Force update of WPScan metadata files. |
| `--no-browser` | Skip Camoufox WAF bypass and connect directly. |
| `--users-limit N` | Number of author IDs to probe via ?author=N (default: 10). |
| `--stealth [N]` | Add random delays between requests. Floor is 1s, ceiling is 2×N seconds (default when flag is set: 1.5 → 1–3s). Also caps threads to 3. |
| `--idle-timeout N` | Abort if no server response received for N seconds (default: 60, 0 = disabled). |
| `--nav-timeout MS` | Camoufox page navigation timeout in milliseconds (default: 60000). On timeout, WPX checks whether the page is usable anyway before giving up. |
| `-q, --quiet` | Suppress banner, status, and progress — show findings only. |
| `-o, --output FILE` | Write output to FILE (plain text, no ANSI codes). |
| `--scan-dir DIR` | Save the collection artifact to DIR instead of an auto-generated `scans/<timestamp>-<host>/`. |
| `--no-artifact` | Skip writing the collection artifact. |
| `--collect-only` | Collection only — never contact the WPScan API, regardless of `--api-key`. See [Collection, Enrichment & Reporting](#collection-enrichment--reporting-offline-replay). |

### Subcommands

| Command | Description |
|---------|-------------|
| `wpx.py enrich SCAN_DIR --api-key KEY` | Offline WPScan enrichment of a prior scan. Reads only `SCAN_DIR/inventory.json`, never contacts the target. Writes `vulnerability.json`. |
| `wpx.py report SCAN_DIR` | Print a report from a saved scan — with enrichment if `vulnerability.json` exists, without it otherwise. No network access at all. |

### Plugin Fetcher (`data/wpx_fetch_plugins.py`)

| Flag | Description |
|------|-------------|
| `--sort-by` | How to rank active plugins: `score` (default), `active_installs`, `downloaded`. |
| `--active-limit N` | Number of active slugs to write to `plugins_active.txt` (default: 5000, 0 = all). |
| `--dead-limit N` | Number of dead slugs to write to `plugins_dead.txt` (default: 2500, 0 = all). |
| `--force` | Re-fetch everything even if catalog already exists. |
| `--fetch-limit N` | Stop after fetching N active plugins from API (0 = all). |
| `--max-age HOURS` | Skip API fetch if catalog is fresher than N hours (default: 24). |

## Disclaimer

This tool is for authorized security testing only. The developers are not responsible for misuse or damage.
