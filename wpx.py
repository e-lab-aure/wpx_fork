#!/usr/bin/env python3
import argparse
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from wpx_data import WPXData
from wpx_core import WPXCore, DEFAULT_NAV_TIMEOUT_MS
from wpx_finder import WPXFinder, ScanIdleTimeout
from wpx_artifact import (
    new_scan_dir, save_scan_artifact, load_inventory, load_scan_meta,
    save_vulnerability_report, load_vulnerability_report,
)
from wpx_enricher import WPScanEnricher
from wpx_report import print_report, _is_version_affected
from wpx_output import (
    init_output,
    print_banner, print_finding, print_info, print_warn, print_status, print_plain,
    GREEN, YELLOW, RED, RESET, BOLD,
)


def _ver_status(plugin_info, api_result):
    """Return a human-readable version status string comparing detected vs latest."""
    version = plugin_info.get("version", "Unknown")
    if version == "Unknown":
        return version

    latest = None
    if api_result:
        latest = api_result.get("latest_version")

    if not latest:
        return version

    if version == latest:
        status = f"{GREEN}up to date{RESET}"
    else:
        status = f"{YELLOW}outdated, latest: {latest}{RESET}"
    return f"{version} ({status})"


def _show_help():
    print("  Usage: python3 wpx.py -u <URL> [options]\n")
    print(f"  {BOLD}Target:{RESET}")
    print(f"    {GREEN}-u, --url URL{RESET}           Target WordPress URL (required)")
    print(f"    {GREEN}--api-key KEY{RESET}           WPScan Vulnerability Database API key")
    print()
    print(f"  {BOLD}Enumeration:{RESET}")
    print(f"    {GREEN}-e, --enumerate OPTS{RESET}    Comma-separated list of what to scan (default: all)")
    print(f"                            {GREEN}p{RESET}   Plugin brute-force + version detection")
    print(f"                            {GREEN}u{RESET}   User enumeration")
    print(f"                            {GREEN}cb{RESET}  Config backup files")
    print(f"                            {GREEN}t{RESET}   Theme version detection")
    print()
    print(f"  {BOLD}Scan Options:{RESET}")
    print(f"    {GREEN}-t, --threads N{RESET}         Concurrent threads (default: 20)")
    print(f"    {GREEN}--plugins-limit N{RESET}       Scan top N plugins (default: 200)")
    print(f"    {GREEN}--full-scan{RESET}             Scan all available plugin slugs (50k+)")
    print(f"    {GREEN}--users-limit N{RESET}         Author IDs to probe via ?author=N (default: 10)")
    print(f"    {GREEN}--no-browser{RESET}            Skip WAF bypass, connect directly")
    print(f"    {GREEN}--nav-timeout MS{RESET}        Camoufox page navigation timeout (default: {DEFAULT_NAV_TIMEOUT_MS})")
    print()
    print(f"  {BOLD}Output:{RESET}")
    print(f"    {GREEN}-q, --quiet{RESET}             Findings only — suppress banner, status, progress")
    print(f"    {GREEN}-o, --output FILE{RESET}       Save plain-text output to FILE")
    print(f"    {GREEN}--scan-dir DIR{RESET}          Save the collection artifact to DIR (default: scans/<id>/)")
    print(f"    {GREEN}--no-artifact{RESET}           Skip writing the collection artifact")
    print(f"    {GREEN}--collect-only{RESET}          Never contact the WPScan API (ignores --api-key)")
    print()
    print(f"  {BOLD}Misc:{RESET}")
    print(f"    {GREEN}--update{RESET}                Force refresh of WPScan metadata files")
    print(f"    {GREEN}-h, --help{RESET}              Show this help")
    print()
    print(f"  {BOLD}Commands:{RESET}")
    print(f"    {GREEN}enrich SCAN_DIR --api-key KEY{RESET}")
    print("        Offline WPScan enrichment of a prior --collect-only scan. Reads only")
    print("        SCAN_DIR/inventory.json, never contacts the target. Writes vulnerability.json.")
    print(f"    {GREEN}report SCAN_DIR{RESET}")
    print("        Print a report from a saved scan (with enrichment if vulnerability.json")
    print("        exists, without it otherwise). No network access at all.")
    print()
    print(f"  {BOLD}Examples:{RESET}")
    print("    python3 wpx.py -u https://example.com")
    print("    python3 wpx.py -u https://example.com -e u")
    print("    python3 wpx.py -u https://example.com -e p,u --plugins-limit 500")
    print("    python3 wpx.py -u https://example.com -e p,cb --api-key KEY --quiet")
    print("    python3 wpx.py -u https://example.com -e p --full-scan --threads 50")
    print("    python3 wpx.py -u https://example.com --collect-only")
    print("    python3 wpx.py enrich scans/20260101T000000Z-example.com --api-key KEY")
    print("    python3 wpx.py report scans/20260101T000000Z-example.com")
    print()


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        _show_help()
        print(f"  {YELLOW}[!]{RESET} {message}\n")
        sys.exit(2)


def main():
    if len(sys.argv) == 1:
        init_output()
        _show_help()
        sys.exit(0)

    if sys.argv[1] == "enrich":
        _run_enrich(sys.argv[2:])
        return

    if sys.argv[1] == "report":
        _run_report(sys.argv[2:])
        return

    parser = _Parser(add_help=False)
    parser.add_argument("--url", "-u")
    parser.add_argument("--api-key")
    parser.add_argument("--threads", "-t", type=int, default=20)
    parser.add_argument("--plugins-limit", type=int)
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--enumerate", "-e", metavar="OPTS", default=None)
    parser.add_argument("--users-limit", type=int, default=10)
    parser.add_argument("--stealth", type=float, nargs='?', const=1.5, default=None,
                        metavar='N',
                        help="Add random delays (default 1.5 = 1–3s, --stealth 5 = 1–10s).")
    parser.add_argument("--idle-timeout", type=int, default=60, metavar='N',
                        help="Abort if no server response for N seconds (default: 60, 0 = off).")
    parser.add_argument("--nav-timeout", type=int, default=DEFAULT_NAV_TIMEOUT_MS, metavar='MS',
                        help="Camoufox page navigation timeout in ms (default: "
                             f"{DEFAULT_NAV_TIMEOUT_MS}).")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--output", "-o", metavar="FILE")
    parser.add_argument("--scan-dir", metavar="DIR",
                        help="Save the collection artifact (scan.json + inventory.json) to DIR "
                             "instead of an auto-generated scans/<timestamp>-<host>/ directory.")
    parser.add_argument("--collect-only", action="store_true",
                        help="Collection only: never contact the WPScan API, regardless of "
                             "--api-key. Produces scan.json + inventory.json, enrich/report later.")
    parser.add_argument("--no-artifact", action="store_true",
                        help="Skip writing the collection artifact.")
    parser.add_argument("--help", "-h", action="store_true")

    args = parser.parse_args()

    if args.help:
        init_output()
        _show_help()
        sys.exit(0)

    if not args.url and not args.update:
        init_output()
        _show_help()
        print(f"  {YELLOW}[!]{RESET} --url / -u is required\n")
        sys.exit(2)

    out_file = open(args.output, 'w', encoding='utf-8') if args.output else None
    try:
        init_output(quiet=args.quiet, output_file=out_file)
        _run(args)
    finally:
        if out_file:
            out_file.close()


_ALL_TOKENS = {"p", "u", "cb", "t"}


def _parse_enumerate(value):
    """Parse -e token string. Returns set of tokens, or exits on invalid input."""
    if not value:
        return set(_ALL_TOKENS)
    raw = {tok.strip().lower() for tok in value.split(",")}
    invalid = raw - _ALL_TOKENS
    if invalid:
        print_warn(
            f"Unknown enumerate option(s): {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(_ALL_TOKENS))}"
        )
        sys.exit(2)
    return raw


def _run_enrich(argv):
    """`wpx.py enrich <scan-dir>` — offline WPScan enrichment of an existing scan.

    Loads only inventory.json from scan_dir and never contacts the target: every
    request this makes goes to the WPScan API, keyed on slugs already present in
    the saved inventory. Replayable — running it again just overwrites
    vulnerability.json with a fresh result, the collection artifact is never
    touched.
    """
    parser = argparse.ArgumentParser(prog="wpx.py enrich", add_help=True)
    parser.add_argument("scan_dir", help="Path to a scan directory produced by a prior collection "
                                          "(must contain inventory.json).")
    parser.add_argument("--api-key", required=True, help="WPScan Vulnerability Database API key.")
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args(argv)

    init_output(quiet=args.quiet)
    print_status(f"Enriching {args.scan_dir} from WPScan (offline w.r.t. the target)...")

    inventory = load_inventory(args.scan_dir)
    enricher = WPScanEnricher(api_key=args.api_key)
    report = enricher.enrich_inventory(inventory)
    path = save_vulnerability_report(args.scan_dir, report)

    if report["status"] == "failed":
        print_warn(f"Enrichment failed: {report.get('error')}")
        print_warn(f"Result saved to {path} — the scan artifact was not modified, retry later.")
        sys.exit(1)

    queried = len(report["plugins"])
    errors = sum(1 for v in report["plugins"].values() if isinstance(v, dict) and v.get("status") == "error")
    print_status(f"Queried {queried} plugin slug(s), {errors} error(s).")
    print_status(f"Saved: {path}")


def _run_report(argv):
    """`wpx.py report <scan-dir>` — print a report from a saved scan, with or without enrichment.

    Reads scan.json + inventory.json (required) and vulnerability.json (optional —
    the report degrades gracefully if `enrich` was never run, or failed). Makes no
    network request at all, to the target or to WPScan.
    """
    parser = argparse.ArgumentParser(prog="wpx.py report", add_help=True)
    parser.add_argument("scan_dir", help="Path to a scan directory produced by a prior collection "
                                          "(must contain scan.json + inventory.json).")
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args(argv)

    init_output(quiet=args.quiet)

    scan_meta = load_scan_meta(args.scan_dir)
    inventory = load_inventory(args.scan_dir)
    vulnerability_report = load_vulnerability_report(args.scan_dir)

    print_report(scan_meta["target"], inventory, vulnerability_report, meta=scan_meta)


def _run(args):
    if args.update:
        print_banner()
        data = WPXData(force_update=True)
        data.download_metadata()
        print_info("Metadata update complete.")
        print_info("To update the full plugin catalog, run: python3 data/wpx_fetch_plugins.py")
        sys.exit(0)

    tokens = _parse_enumerate(args.enumerate)
    do_plugins = "p" in tokens
    do_users = "u" in tokens
    do_backups = "cb" in tokens
    do_theme = "t" in tokens

    target_url = args.url
    if "://" not in target_url:
        target_url = "https://" + target_url
    start_time = time.time()

    print_banner()
    print_status(f"Scanning: {target_url}")
    print_status(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_plain()

    # 1. Initialize Data
    data = WPXData()
    stale = data.get_stale_files()
    if stale:
        print_warn(f"Some data files are older than 30 days or missing: {', '.join(stale[:3])}...")
        print_warn("It is recommended to run: python3 wpx.py --update")
        print_plain()

    data.download_metadata()
    data.load_dynamic_finders()
    data.load_slugs()
    data.load_wp_metadata()
    data.load_user_enum_techniques()

    # 2. WAF Bypass
    core = WPXCore(target_url, nav_timeout_ms=args.nav_timeout)
    if args.no_browser:
        print_warn("--no-browser: skipping WAF bypass, using direct session.")
    else:
        bypassed = core.bypass_waf()
        if not bypassed:
            print_warn("WAF bypass failed. See diagnostic output above.")
            print_warn("  Skip bypass  : python3 wpx.py --no-browser -u " + target_url)
            sys.exit(1)

    if not core.setup_mirror_session():
        print_warn("Could not establish a session (WAF may be blocking). Aborting.")
        sys.exit(1)

    # 3. Discovery Engine
    if args.stealth is not None and args.threads == 20:
        args.threads = 1
        print_status(f"Stealth mode: threads capped at 1, delays 1.0–{args.stealth * 2:.1f}s")
    if args.stealth is not None and args.idle_timeout:
        min_idle = int(args.stealth * 2) + 20
        if args.idle_timeout < min_idle:
            args.idle_timeout = min_idle
            print_status(f"Idle timeout raised to {min_idle}s to accommodate stealth delays.")
    finder = WPXFinder(core, data, stealth=args.stealth, idle_timeout=args.idle_timeout,
                       threads=args.threads)

    try:
        # Homepage
        homepage_res = core.session.get(target_url, impersonate="firefox")

        # Headers
        finder.check_headers(homepage_res)

        # WP version
        finder.detect_wp_version(homepage_res.text, target_url)

        # Core files (robots.txt, xmlrpc, wp-cron, readme) + multisite
        finder.check_core_files()
        finder.detect_multisite()

        # Passive plugin/theme discovery
        finder.find_passive_items(homepage_res.text)

        # Theme details (active fetch — only when t token active)
        if do_theme:
            finder.detect_theme_details()

        # Plugin brute-force + version detection (only when p token active)
        if do_plugins:
            best_source = None
            for candidate in [
                Path("data/plugins_full.txt"), Path("plugins_full.txt"), Path(".wpx_data/plugins_full.txt")
            ]:
                if candidate.exists():
                    best_source = candidate
                    break

            if best_source:
                with open(best_source) as f:
                    all_slugs = [line.strip() for line in f if line.strip()]
                source_name = str(best_source)
            else:
                all_slugs = data.plugins
                source_name = "WPScan default list"

            if not all_slugs:
                print_warn("No plugin slugs found. Skipping active enumeration.")
                slugs = []
            elif args.full_scan:
                slugs = all_slugs
                print_status(f"Full scan: {len(slugs):,} slugs from {source_name}")
            elif args.plugins_limit:
                slugs = all_slugs[:args.plugins_limit]
                print_status(
                    f"Limited scan: {len(slugs):,} slugs (top {args.plugins_limit}) from {source_name}"
                )
            else:
                slugs = all_slugs[:200]
                print_status(f"Default scan: {len(slugs):,} slugs (top 200) from {source_name}")

            if slugs:
                finder.scan_plugins(slugs, threads=args.threads)
            finder.detect_versions()

        # User enumeration
        if do_users:
            finder.enumerate_users(
                techniques=data.user_enum_techniques,
                users_limit=args.users_limit,
            )

        # Config backups (low hit rate — run last to preserve requests for high-value checks)
        if do_backups and data.backups:
            finder.check_config_backups()

    except KeyboardInterrupt:
        print_plain()
        print_warn("Scan interrupted by user (Ctrl+C). Showing partial results...")
    except ScanIdleTimeout as e:
        print_plain()
        print_warn(f"Scan aborted: {e}")
        print_warn("Showing partial results...")

    # 4. Save collection artifact — strictly before any WPScan call, so the
    #    collection stays re-enrichable/re-reportable offline afterwards.
    inventory = finder.to_inventory()
    scan_meta = {
        "enumerate": sorted(tokens),
        "threads": args.threads,
        "collect_only": args.collect_only,
    }
    if not args.no_artifact:
        scan_dir = Path(args.scan_dir) if args.scan_dir else new_scan_dir(target_url)
        scan_path, inventory_path = save_scan_artifact(scan_dir, target_url, inventory, meta=scan_meta)
        print_status(f"Collection artifact saved: {scan_path.parent}/")

    # 5. Vulnerability enrichment — never reached in --collect-only: WPScanEnricher is not
    #    even constructed, so no WPScan request can happen regardless of --api-key.
    vulnerability_report = None
    if args.collect_only:
        if args.api_key:
            print_warn("--collect-only: ignoring --api-key, no WPScan request will be made.")
        else:
            print_status("Collect-only mode: skipping WPScan enrichment.")
    elif args.api_key:
        enricher = WPScanEnricher(api_key=args.api_key)
        vulnerability_report = enricher.enrich_inventory(inventory)
        if not args.no_artifact:
            save_vulnerability_report(scan_dir, vulnerability_report)

    # ------------------------------------------------------------------
    # 5. Report (observation + enrichment, read back from the artifact we
    #    just wrote — matches exactly what `wpx report <scan-dir>` would print)
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    elapsed_str = str(timedelta(seconds=int(elapsed)))
    print_report(target_url, inventory, vulnerability_report, meta=scan_meta, elapsed_str=elapsed_str)
    print_finding(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_plain()


if __name__ == "__main__":
    main()
