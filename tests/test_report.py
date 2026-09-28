import pytest

from wpx_report import _is_version_affected, print_report


# --- _is_version_affected (moved here from wpx.py, still re-exported by wpx) ---

def test_affected_when_older():
    assert _is_version_affected("1.2.0", "1.3.0") is True


def test_not_affected_when_equal():
    assert _is_version_affected("1.3.0", "1.3.0") is False


def test_not_affected_when_newer():
    assert _is_version_affected("2.0.0", "1.3.0") is False


def test_affected_when_no_fix():
    assert _is_version_affected("1.0.0", None) is True


def test_affected_when_unknown_installed_version():
    assert _is_version_affected("Unknown", "1.3.0") is True


# --- print_report: degrades gracefully without any enrichment ---

def _inventory(**overrides):
    base = {
        "target": "https://example.com",
        "wordpress": None,
        "theme": None,
        "plugins": [],
        "users": {"found": [], "ran": False, "blocked_techniques": []},
        "multisite": None,
        "core_files": {},
        "headers": None,
        "config_backups": [],
    }
    base.update(overrides)
    return base


def test_print_report_with_no_vulnerability_report_does_not_crash(capsys):
    print_report("https://example.com", _inventory(), vulnerability_report=None)
    out = capsys.readouterr().out
    assert "not run" in out


def test_print_report_shows_plugin_without_enrichment(capsys):
    inv = _inventory(plugins=[{
        "slug": "elementor", "status": "passive", "location": "https://example.com/wp-content/plugins/elementor/",
        "version": None, "version_confidence": 0,
        "evidence": [{"found_by": "Urls In Homepage (Passive Detection)", "url": None}],
    }])
    print_report("https://example.com", inv, vulnerability_report=None)
    out = capsys.readouterr().out
    assert "elementor" in out


def test_print_report_never_labels_a_finding_as_confirmed_exploitation(capsys):
    inv = _inventory(plugins=[{
        "slug": "elementor", "status": 200, "location": "https://example.com/wp-content/plugins/elementor/",
        "version": "1.0.0", "version_confidence": 100,
        "evidence": [{"found_by": "Known Locations (Aggressive Detection)", "url": None}],
    }])
    vuln_report = {
        "status": "ok",
        "queried_at": "2026-01-01T00:00:00+00:00",
        "plugins": {"elementor": {"vulns": [
            {"title": "Some CVE", "fixed_in": "1.5.0", "references": {"url": ["https://example.com/cve"]}}
        ], "latest_version": "1.5.0", "last_updated": None}},
    }
    print_report("https://example.com", inv, vulnerability_report=vuln_report)
    out = capsys.readouterr().out
    assert "elementor" in out
    assert "Some CVE" in out
    assert "exploited" not in out.lower()
    assert "confirmed exploitation" not in out.lower() or "not confirmed exploitation" in out.lower()


def test_print_report_hides_vulns_fixed_in_observed_version(capsys):
    inv = _inventory(plugins=[{
        "slug": "elementor", "status": 200, "location": "",
        "version": "2.0.0", "version_confidence": 100,
        "evidence": [{"found_by": "Known Locations (Aggressive Detection)", "url": None}],
    }])
    vuln_report = {
        "status": "ok", "queried_at": "x",
        "plugins": {"elementor": {"vulns": [
            {"title": "Old fixed CVE", "fixed_in": "1.5.0", "references": {}}
        ], "latest_version": "2.0.0"}},
    }
    print_report("https://example.com", inv, vulnerability_report=vuln_report)
    out = capsys.readouterr().out
    assert "Old fixed CVE" not in out
    assert "fixed" in out.lower()


def test_print_report_shows_enrichment_error_for_plugin_without_crashing(capsys):
    inv = _inventory(plugins=[{
        "slug": "broken-plugin", "status": "passive", "location": "",
        "version": None, "version_confidence": 0,
        "evidence": [{"found_by": "Urls In Homepage (Passive Detection)", "url": None}],
    }])
    vuln_report = {
        "status": "ok", "queried_at": "x",
        "plugins": {"broken-plugin": {"status": "error", "error": "timeout"}},
    }
    print_report("https://example.com", inv, vulnerability_report=vuln_report)
    out = capsys.readouterr().out
    assert "broken-plugin" in out
    assert "timeout" in out


def test_print_report_skipped_no_api_key_status_is_reported(capsys):
    print_report("https://example.com", _inventory(),
                  vulnerability_report={"status": "skipped_no_api_key", "plugins": {}})
    out = capsys.readouterr().out
    assert "skipped" in out.lower()


def test_print_report_failed_status_is_reported_not_raised(capsys):
    print_report("https://example.com", _inventory(),
                  vulnerability_report={"status": "failed", "error": "quota exceeded", "plugins": {}})
    out = capsys.readouterr().out
    assert "quota exceeded" in out


def test_print_report_wordpress_and_theme_sections(capsys):
    inv = _inventory(
        wordpress={
            "version": "6.4.1", "confidence": 100,
            "evidence": [
                {"found_by": "Meta Generator (Passive Detection)", "url": "https://example.com/", "match": "WordPress 6.4.1"},
                {"found_by": "Rss Generator (Aggressive Detection)", "url": "https://example.com/feed/", "match": None},
            ],
            "is_latest": True, "latest_version": "6.4.1", "release_date": "2023-11-07",
        },
        theme={
            "slug": "twentytwentyfour", "name": "Twenty Twenty-Four", "author": None,
            "description": None, "location": "https://example.com/wp-content/themes/twentytwentyfour/",
            "style_url": None, "readme_url": None, "version": "1.0", "version_confidence": 80,
            "evidence": [{"found_by": "Urls In Homepage (Passive Detection)", "url": None}],
        },
    )
    print_report("https://example.com", inv, vulnerability_report=None)
    out = capsys.readouterr().out
    assert "6.4.1" in out
    assert "twentytwentyfour" in out


def test_print_report_users_section_only_when_ran(capsys):
    inv = _inventory(users={"found": [], "ran": False, "blocked_techniques": []})
    print_report("https://example.com", inv, vulnerability_report=None)
    out = capsys.readouterr().out
    assert "User Enumeration" not in out

    inv2 = _inventory(users={"found": [], "ran": True, "blocked_techniques": ["REST API User Enumeration"]})
    print_report("https://example.com", inv2, vulnerability_report=None)
    out2 = capsys.readouterr().out
    assert "User Enumeration" in out2
