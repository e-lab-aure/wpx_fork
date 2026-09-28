"""Étape 7 — the 7 tests required by docs/plan-architecture-phases.md.

Each test below is a direct, explicitly-labeled check for one plan requirement.
Several of these properties are already exercised elsewhere (test_collect_only.py,
test_enricher.py, test_inventory_artifact.py, test_core.py) from different
angles; this file is the single place that maps each plan requirement to a
concrete, minimal test so the mapping itself is auditable.
"""

import argparse

import wpx
from wpx_artifact import save_scan_artifact, save_vulnerability_report, load_inventory
from wpx_enricher import WPScanEnricher


def _make_scan_args(**overrides):
    defaults = dict(
        url="https://example.com", api_key=None, threads=20, plugins_limit=None,
        full_scan=False, update=False, no_browser=True, enumerate="t", users_limit=10,
        stealth=None, idle_timeout=60, nav_timeout=wpx.DEFAULT_NAV_TIMEOUT_MS, quiet=True,
        output=None, scan_dir=None, no_artifact=True, collect_only=False, help=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_1_collect_only_makes_no_wpscan_call(mocker):
    """« collect-only ne fait aucun appel WPScan. »"""
    dummy_data = mocker.MagicMock(get_stale_files=lambda: [], backups=[], plugins=[],
                                   user_enum_techniques={})
    mocker.patch("wpx.WPXData", return_value=dummy_data)
    dummy_core = mocker.MagicMock(target_url="https://example.com")
    dummy_core.session.get.return_value = mocker.MagicMock(text="<html></html>", status_code=200)
    dummy_core.setup_mirror_session.return_value = True
    mocker.patch("wpx.WPXCore", return_value=dummy_core)
    enricher_spy = mocker.patch("wpx.WPScanEnricher")

    wpx._run(_make_scan_args(collect_only=True, api_key="fake-key"))

    enricher_spy.assert_not_called()


def test_2_enrich_makes_no_request_to_the_target(mocker, tmp_path):
    """« enrich ne fait aucune requête réseau vers la cible. »"""
    mocker.patch("wpx.load_inventory", return_value={"target": "https://example.com", "plugins": []})
    mocker.patch.object(WPScanEnricher, "enrich_inventory", return_value={"status": "ok", "plugins": {}})
    mocker.patch("wpx.save_vulnerability_report", return_value=tmp_path / "vulnerability.json")
    core_spy = mocker.patch("wpx.WPXCore")

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])

    core_spy.assert_not_called()


def test_3_enrichment_uses_only_the_saved_inventory(mocker, tmp_path):
    """« L'enrichissement utilise uniquement l'inventaire sauvegardé. »"""
    inventory = {"target": "https://example.com", "plugins": [
        {"slug": "elementor", "version": None, "evidence": []},
    ]}
    save_scan_artifact(tmp_path, "https://example.com", inventory)
    # No network stub is installed at all for the target — if enrich tried to
    # collect anything beyond what load_inventory() returns, this would either
    # raise (no WPXCore/WPXFinder imported into the enrich path) or diverge
    # from the saved inventory below.
    enrich_spy = mocker.patch.object(
        WPScanEnricher, "enrich_inventory", return_value={"status": "ok", "plugins": {}}
    )
    mocker.patch("wpx.save_vulnerability_report", return_value=tmp_path / "vulnerability.json")

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])

    enrich_spy.assert_called_once_with(load_inventory(tmp_path))


def test_4_duplicate_slugs_generate_a_single_wpscan_request(mocker):
    """« Les doublons ne génèrent pas de requêtes WPScan inutiles. »"""
    instance = mocker.MagicMock()
    instance.get_vulnerabilities.return_value = None
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = {"plugins": [
        {"slug": "elementor", "evidence": []},
        {"slug": "elementor", "evidence": []},
        {"slug": "contact-form-7", "evidence": []},
    ]}
    enricher.enrich_inventory(inventory)

    assert instance.get_vulnerabilities.call_count == 2


def test_5_a_wpscan_error_never_destroys_the_scan_artifact(tmp_path):
    """« Une erreur WPScan ne détruit pas l'artefact de scan. »"""
    inventory = {"target": "https://example.com", "plugins": []}
    save_scan_artifact(tmp_path, "https://example.com", inventory)

    save_vulnerability_report(tmp_path, {"status": "failed", "error": "quota exceeded", "plugins": {}})

    assert load_inventory(tmp_path) == inventory


def test_6_an_existing_scan_can_be_enriched_more_than_once(mocker, tmp_path):
    """« Un scan existant peut être enrichi plusieurs fois. »"""
    inventory = {"target": "https://example.com", "plugins": [{"slug": "elementor", "evidence": []}]}
    save_scan_artifact(tmp_path, "https://example.com", inventory)

    first = {"status": "ok", "plugins": {"elementor": {"vulns": []}}}
    second = {"status": "ok", "plugins": {"elementor": {"vulns": [], "latest_version": "2.0"}}}
    mocker.patch.object(WPScanEnricher, "enrich_inventory", side_effect=[first, second])

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])
    from wpx_artifact import load_vulnerability_report
    assert load_vulnerability_report(tmp_path) == first

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])
    assert load_vulnerability_report(tmp_path) == second


def test_7_networkidle_to_domcontentloaded_change_works(mocker):
    """« Le changement networkidle → domcontentloaded fonctionne. » (Étape 2)"""
    from wpx_core import WPXCore

    page = mocker.MagicMock()
    page.url = "https://example.com/"
    page.evaluate.side_effect = lambda expr: (
        "complete" if expr == "document.readyState" else "TestUA/1.0"
    )
    page.content.return_value = "<html>" + "x" * 300 + "</html>"
    page.context.cookies.return_value = [{"name": "a", "value": "b"}]

    browser = mocker.MagicMock()
    browser.new_page.return_value = page
    ctx = mocker.MagicMock()
    ctx.__enter__.return_value = browser
    ctx.__exit__.return_value = False
    mocker.patch("wpx_core.Camoufox", return_value=ctx)
    mocker.patch("wpx_core.time.sleep")

    core = WPXCore("https://example.com")
    assert core.bypass_waf() is True
    assert page.goto.call_args.kwargs["wait_until"] == "domcontentloaded"
