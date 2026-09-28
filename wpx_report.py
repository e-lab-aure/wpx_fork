"""Terminal report generation — reads a collection artifact (inventory.json) and,
if present, a WPScan enrichment result (vulnerability.json). Never touches the
target or the WPScan API itself.

Every finding printed here is either:
  - an OBSERVATION: something the collection actually saw on the target, with
    its own evidence and confidence, independent of WPScan; or
  - an ENRICHMENT: a known WPScan CVE for the plugin *slug* queried, which may
    or may not apply to the exact version observed. A WPScan hit is never
    printed as confirmed exploitation — only as a known vulnerability to check
    against the observed version.

Degrades gracefully with no `vulnerability_report` at all (never enriched) and
with a "failed"/"skipped_no_api_key" one (enrichment attempted or skipped) —
the observation half of the report is always complete regardless.
"""

from packaging.version import Version, InvalidVersion

from wpx_output import print_finding, print_info, print_plain, print_status, GREEN, YELLOW, RED, RESET


def _is_version_affected(detected, fixed_in):
    """Return True if the detected version is still affected by this vulnerability."""
    if not fixed_in or fixed_in == "N/A":
        return True
    if not detected or detected == "Unknown":
        return True
    try:
        return Version(detected) < Version(str(fixed_in))
    except InvalidVersion:
        return True


def print_report(target, inventory, vulnerability_report=None, meta=None, elapsed_str=None):
    meta = meta or {}
    tokens = set(meta.get("enumerate") or [])
    do_plugins = "p" in tokens if tokens else True
    do_backups = "cb" in tokens if tokens else True

    plugin_results = (vulnerability_report or {}).get("plugins", {})

    print_plain()
    print_plain("=" * 60)
    print_status(f"WPX Scan Results for: {target}")
    print_plain("=" * 60)
    print_plain()

    _print_enrichment_status(vulnerability_report)

    # --- Headers ---
    headers = inventory.get("headers")
    if headers and headers.get("entries"):
        subitems = ["Interesting Entries:"]
        for entry in headers["entries"]:
            subitems.append(f" - {entry}")
        subitems.append(f"Found By: {headers['found_by']}")
        subitems.append(f"Confidence: {headers['confidence']}%")
        print_finding("Headers", subitems)
        print_plain()

    core_files = inventory.get("core_files") or {}

    # --- robots.txt ---
    if "robots_txt" in core_files:
        rt = core_files["robots_txt"]
        subitems = []
        if rt["entries"]:
            subitems.append("Interesting Entries:")
            for e in rt["entries"]:
                subitems.append(f" - {e}")
        subitems.append(f"Found By: {rt['found_by']}")
        subitems.append(f"Confidence: {rt['confidence']}%")
        print_finding(f"robots.txt found: {rt['url']}", subitems)
        print_plain()

    # --- XML-RPC ---
    if "xmlrpc" in core_files:
        xi = core_files["xmlrpc"]
        subitems = [f"Found By: {xi['found_by']}", f"Confidence: {xi['confidence']}%", "References:"]
        for ref in xi["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"XML-RPC seems to be enabled: {xi['url']}", subitems)
        print_plain()

    # --- WP-Cron ---
    if "wp_cron" in core_files:
        wc = core_files["wp_cron"]
        subitems = [f"Found By: {wc['found_by']}", f"Confidence: {wc['confidence']}%", "References:"]
        for ref in wc["references"]:
            subitems.append(f" - {ref}")
        print_finding(f"The external WP-Cron seems to be enabled: {wc['url']}", subitems)
        print_plain()

    # --- Multisite ---
    multisite = inventory.get("multisite")
    if multisite:
        subitems = [
            f"Found By: {multisite['found_by']}",
            f"Confidence: {multisite['confidence']}%",
            f"Reference: {multisite['reference']}",
        ]
        if multisite.get("confirmed_by"):
            cb = multisite["confirmed_by"]
            subitems.append(f"Confirmed By: {cb['found_by']}")
            subitems.append(f" - {cb['url']}")
        print_finding(f"This site appears to be a WordPress Multisite: {multisite['url']}", subitems)
        print_plain()

    # --- WordPress readme.html ---
    if "readme" in core_files:
        rd = core_files["readme"]
        print_finding(
            f"WordPress readme found: {rd['url']}",
            [f"Found By: {rd['found_by']}", f"Confidence: {rd['confidence']}%"],
        )
        print_plain()

    # --- WP Version (observation) ---
    wordpress = inventory.get("wordpress")
    if wordpress:
        version = wordpress["version"]
        evidence = wordpress.get("evidence") or []

        if wordpress.get("is_latest") is True:
            rd = wordpress.get("release_date")
            rd_str = f", released on {rd}" if rd else ""
            ver_label = f"{version} identified ({GREEN}Latest{rd_str}{RESET})"
        elif wordpress.get("is_latest") is False:
            latest = wordpress.get("latest_version", "?")
            ver_label = f"{version} identified ({YELLOW}Outdated, latest: {latest}{RESET})"
        else:
            ver_label = f"{version} identified"

        subitems = [f"Confidence: {wordpress.get('confidence', 0)}%"]
        if evidence:
            primary = evidence[0]
            subitems.append(f"Found By: {primary['found_by']}")
            subitems.append(f" - {primary.get('url')}, Match: '{primary.get('match')}'")
        for confirmation in evidence[1:]:
            subitems.append(f"Confirmed By: {confirmation['found_by']}")
            match_str = f", Match: '{confirmation['match']}'" if confirmation.get("match") else ""
            subitems.append(f" - {confirmation.get('url')}{match_str}")

        print_finding(f"WordPress version {ver_label}", subitems)
        print_plain()

    # --- Theme (observation) ---
    theme = inventory.get("theme")
    if theme:
        subitems = [f"Location: {theme.get('location')}"]
        if theme.get("readme_url"):
            subitems.append(f"Readme: {theme['readme_url']}")
        if theme.get("style_url"):
            subitems.append(f"Style URL: {theme['style_url']}")
        if theme.get("name"):
            subitems.append(f"Style Name: {theme['name']}")
        if theme.get("description"):
            subitems.append(f"Description: {theme['description']}")
        if theme.get("author"):
            subitems.append(f"Author: {theme['author']}")
        evidence = theme.get("evidence") or []
        if evidence:
            subitems.append(f"Found By: {evidence[0]['found_by']}")
        if theme.get("version"):
            subitems.append(f"Version: {theme['version']} ({theme.get('version_confidence', 0)}% confidence)")
            for e in evidence[1:]:
                subitems.append(f"Found By: {e['found_by']}")
        print_finding(f"WordPress theme in use: {theme.get('slug')}", subitems)
        print_plain()

    # --- Config Backups (observation) ---
    config_backups = inventory.get("config_backups") or []
    if do_backups and config_backups:
        for bu in config_backups:
            print_finding(f"A Config Backup file has been found: {bu['url']}")
        print_plain()

    # --- Plugins (observation + enrichment) ---
    plugins = inventory.get("plugins") or []
    if do_plugins and not plugins:
        print_info("No plugins detected.")
    else:
        for plugin in plugins:
            _print_plugin(plugin, plugin_results.get(plugin["slug"]))

    # --- Users (observation) ---
    users = inventory.get("users") or {}
    if users.get("ran"):
        _print_users(users)

    # --- Summary ---
    print_plain("=" * 60)
    if elapsed_str:
        print_finding(f"Elapsed time: {elapsed_str}")
    print_plain()


def _print_enrichment_status(vulnerability_report):
    if vulnerability_report is None:
        print_info("WPScan enrichment: not run (no vulnerability.json — collect-only scan, or "
                    "`wpx enrich <scan-dir> --api-key KEY` has not been run yet).")
        print_plain()
        return
    status = vulnerability_report.get("status")
    if status == "skipped_no_api_key":
        print_info("WPScan enrichment: skipped (no API key was provided to `wpx enrich`).")
        print_plain()
    elif status == "failed":
        print_info(f"WPScan enrichment: unavailable ({vulnerability_report.get('error', 'unknown error')}).")
        print_plain()
    elif status == "ok":
        queried_at = vulnerability_report.get("queried_at", "?")
        print_info(f"WPScan enrichment: available (queried {queried_at}).")
        print_plain()


def _print_plugin(plugin, ar):
    slug = plugin["slug"]
    version = plugin.get("version") or "Unknown"
    version_confidence = plugin.get("version_confidence") or 0
    evidence = plugin.get("evidence") or []
    primary = evidence[0] if evidence else {}
    version_evidence = evidence[-1] if len(evidence) > 1 else None

    subitems = [f"Location: {plugin.get('location', '')}"]

    if ar and isinstance(ar, dict) and ar.get("latest_version"):
        latest = ar["latest_version"]
        if version != "Unknown" and version == latest:
            status_str = f"{GREEN}up to date{RESET}"
        elif version != "Unknown":
            status_str = f"{YELLOW}outdated{RESET}"
        else:
            status_str = ""
        label = f"{latest} ({status_str})" if status_str else latest
        subitems.append(f"Latest Version: {label}")
    if ar and isinstance(ar, dict) and ar.get("last_updated"):
        subitems.append(f"Last Updated: {ar['last_updated']}")

    subitems.append(f"Found By: {primary.get('found_by', 'Unknown')}")

    if version != "Unknown" and version_confidence:
        subitems.append(f"Version: {version} ({version_confidence}% confidence)")
        if version_evidence:
            subitems.append(f"Found By: {version_evidence.get('found_by')}")
            if version_evidence.get("url"):
                subitems.append(f" - {version_evidence['url']}")
    elif version != "Unknown":
        subitems.append(f"Version: {version}")

    # --- Enrichment: known WPScan vulnerabilities for this slug ---
    if ar and isinstance(ar, dict) and ar.get("status") == "error":
        subitems.append(f"WPScan enrichment error for this plugin: {ar.get('error')}")
        print_finding(slug, subitems)
    elif ar and ar.get("vulns"):
        all_vulns = ar["vulns"]
        vulns = [v for v in all_vulns if _is_version_affected(version, v.get("fixed_in"))]
        skipped = len(all_vulns) - len(vulns)
        if vulns:
            title_str = f"{RED}[KNOWN VULNERABILITIES]{RESET} {slug}"
            count_note = (
                f"{len(vulns)} known CVE(s) for this slug may affect the observed version "
                "(WPScan enrichment — not confirmed exploitation)"
            )
            if skipped:
                count_note += f" ({len(all_vulns)} total, {skipped} fixed in the observed version)"
            subitems.append(count_note + ":")
            for vuln in vulns:
                subitems.append(f" | Title: {vuln['title']}")
                subitems.append(f" | Fixed In: {vuln.get('fixed_in', 'N/A')}")
                refs = vuln.get("references", {}).get("url", [])
                if refs:
                    subitems.append(f" | References: {refs[0]}")
            print_finding(title_str, subitems)
        else:
            if skipped:
                subitems.append(f"No active vulnerabilities ({skipped} historical, all fixed)")
            print_finding(slug, subitems)
    else:
        print_finding(slug, subitems)
    print_plain()


def _print_users(users):
    found_users = users.get("found") or []
    blocked = users.get("blocked_techniques") or []
    has_found = bool(found_users)
    has_blocked = bool(blocked)

    if has_found and has_blocked:
        status = f"{YELLOW}Partially Protected{RESET}"
    elif has_found:
        status = f"{RED}Vulnerable{RESET}"
    elif has_blocked:
        status = f"{GREEN}Fully Protected{RESET}"
    else:
        status = "Unknown"

    _high_risk = {"REST API User Enumeration", "Author Archive (?author=N)", "Passive HTML Scan"}
    _med_risk = {"oEmbed Author Leak"}
    if has_found:
        leaked_via = {u["found_by"] for u in found_users}
        if leaked_via & _high_risk:
            risk = f"{RED}High{RESET}"
        elif leaked_via & _med_risk:
            risk = f"{YELLOW}Medium{RESET}"
        else:
            risk = f"{YELLOW}Low{RESET}"
    else:
        risk = f"{GREEN}None{RESET}"

    subitems = [f"Status: {status}"]
    if has_found:
        subitems.append(f"{len(found_users)} user(s) found via leakage")
    else:
        subitems.append("No users found")

    if has_found:
        subitems.append("")
        subitems.append("Users Discovered:")
        for u in found_users:
            label = u.get("login") or u.get("name") or "unknown"
            uid_str = f" (ID: {u['id']})" if u.get("id") else ""
            subitems.append(f"  • {label}{uid_str}")
            subitems.append(f"    Found By: {u['found_by']}")
            subitems.append(f"    Confidence: {u['confidence']}%")

    if has_blocked:
        subitems.append("")
        subitems.append("Blocked Methods:")
        for m in blocked:
            subitems.append(f"  {GREEN}✓{RESET} {m:<42}(Good)")

    subitems.append("")
    subitems.append(f"Risk Level: {risk}")

    if has_found:
        leaked_via = {u["found_by"] for u in found_users}
        recs = []
        if "REST API User Enumeration" in leaked_via:
            recs.append("Restrict the /wp/v2/users REST API endpoint to authenticated users only.")
        if leaked_via & {"Author Archive (?author=N)", "Passive HTML Scan"}:
            recs.append(
                "Block ?author= redirects and disable author archive pages via your security plugin."
            )
        if "RSS Feed Author Leak" in leaked_via:
            recs.append(
                "Apply the `the_author` and `the_content_feed` filters to hide author info from feeds."
            )
        if "oEmbed Author Leak" in leaked_via:
            recs.append("Restrict or disable the oEmbed endpoint.")
        if recs:
            subitems.append(f"Recommendation: {recs[0]}")
            for r in recs[1:]:
                subitems.append(f"  {r}")

    print_finding("User Enumeration", subitems)
    print_plain()
