import pytest

from wpx_enricher import WPScanEnricher


def _inventory(plugins):
    return {"target": "https://example.com", "wordpress": None, "theme": None, "plugins": plugins}


def _plugin(slug, version=None):
    return {"slug": slug, "status": "passive", "location": "", "version": version,
            "version_confidence": 0, "evidence": []}


def test_enrich_without_api_key_is_skipped_and_makes_no_requests(mocker):
    spy = mocker.patch("wpx_enricher.WPXVulnerability")
    enricher = WPScanEnricher(api_key=None)

    report = enricher.enrich_inventory(_inventory([_plugin("elementor")]))

    assert report["status"] == "skipped_no_api_key"
    assert report["plugins"] == {}
    spy.assert_not_called()


def test_enrich_queries_each_distinct_slug_once(mocker):
    instance = mocker.MagicMock()
    instance.get_vulnerabilities.return_value = {"vulns": [], "latest_version": "1.0", "last_updated": None}
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = _inventory([_plugin("elementor"), _plugin("contact-form-7")])
    report = enricher.enrich_inventory(inventory)

    assert report["status"] == "ok"
    assert instance.get_vulnerabilities.call_count == 2
    assert set(report["plugins"].keys()) == {"elementor", "contact-form-7"}


def test_enrich_does_not_duplicate_requests_for_repeated_slug(mocker):
    # inventory should already be deduplicated by slug, but the enricher itself
    # must not issue more than one WPScan request per distinct slug either way.
    instance = mocker.MagicMock()
    instance.get_vulnerabilities.return_value = None
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = _inventory([_plugin("elementor"), _plugin("elementor")])
    enricher.enrich_inventory(inventory)

    assert instance.get_vulnerabilities.call_count == 1


def test_enrich_queries_plugins_with_unknown_version_too(mocker):
    # Version is only used for filtering at report time — WPScan is queried by
    # slug regardless of whether the collected version is known.
    instance = mocker.MagicMock()
    instance.get_vulnerabilities.return_value = None
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = _inventory([_plugin("elementor", version=None)])
    enricher.enrich_inventory(inventory)

    instance.get_vulnerabilities.assert_called_once_with("plugins", "elementor")


def test_enrich_survives_wpscan_client_construction_failure(mocker):
    mocker.patch("wpx_enricher.WPXVulnerability", side_effect=RuntimeError("boom"))
    enricher = WPScanEnricher(api_key="key")

    report = enricher.enrich_inventory(_inventory([_plugin("elementor")]))

    assert report["status"] == "failed"
    assert "boom" in report["error"]


def test_enrich_survives_per_slug_exception_without_aborting_batch(mocker):
    instance = mocker.MagicMock()
    instance.get_vulnerabilities.side_effect = [RuntimeError("network blip"), {"vulns": []}]
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = _inventory([_plugin("bad-plugin"), _plugin("good-plugin")])
    report = enricher.enrich_inventory(inventory)

    assert report["status"] == "ok"
    assert report["plugins"]["bad-plugin"]["status"] == "error"
    assert report["plugins"]["good-plugin"] == {"vulns": []}


def test_enrich_ignores_plugins_without_slug(mocker):
    instance = mocker.MagicMock()
    mocker.patch("wpx_enricher.WPXVulnerability", return_value=instance)

    enricher = WPScanEnricher(api_key="key")
    inventory = _inventory([{"slug": None, "version": None}])
    report = enricher.enrich_inventory(inventory)

    assert report["plugins"] == {}
    instance.get_vulnerabilities.assert_not_called()
