import argparse

import pytest

import wpx


def _make_args(**overrides):
    defaults = dict(
        url="https://example.com",
        api_key=None,
        threads=20,
        plugins_limit=None,
        full_scan=False,
        update=False,
        no_browser=True,
        enumerate="t",
        users_limit=10,
        stealth=None,
        idle_timeout=60,
        nav_timeout=wpx.DEFAULT_NAV_TIMEOUT_MS,
        quiet=True,
        output=None,
        scan_dir=None,
        no_artifact=True,
        collect_only=False,
        help=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class _DummyResponse:
    def __init__(self, text="<html></html>", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}
        self.content = text.encode()

    def json(self):
        return {}


@pytest.fixture(autouse=True)
def stub_collection(mocker):
    """Stub out everything network-facing so _run() executes deterministically."""
    dummy_data = mocker.MagicMock()
    dummy_data.get_stale_files.return_value = []
    dummy_data.backups = []
    dummy_data.plugins = []
    dummy_data.user_enum_techniques = {}
    mocker.patch("wpx.WPXData", return_value=dummy_data)

    dummy_core = mocker.MagicMock()
    dummy_core.target_url = "https://example.com"
    dummy_core.session.get.return_value = _DummyResponse()
    dummy_core.setup_mirror_session.return_value = True
    mocker.patch("wpx.WPXCore", return_value=dummy_core)

    mocker.patch("wpx.save_scan_artifact", return_value=(mocker.MagicMock(), mocker.MagicMock()))
    return dummy_core, dummy_data


def test_collect_only_never_constructs_enricher_even_with_api_key(mocker):
    enricher_spy = mocker.patch("wpx.WPScanEnricher")
    args = _make_args(collect_only=True, api_key="fake-api-key")

    wpx._run(args)

    enricher_spy.assert_not_called()


def test_collect_only_without_api_key_also_skips_wpscan(mocker):
    enricher_spy = mocker.patch("wpx.WPScanEnricher")
    args = _make_args(collect_only=True, api_key=None)

    wpx._run(args)

    enricher_spy.assert_not_called()


def test_non_collect_only_with_api_key_still_calls_wpscan(mocker):
    enricher_instance = mocker.MagicMock()
    enricher_instance.enrich_inventory.return_value = {"status": "ok", "plugins": {}}
    enricher_spy = mocker.patch("wpx.WPScanEnricher", return_value=enricher_instance)
    args = _make_args(collect_only=False, api_key="fake-api-key")

    wpx._run(args)

    enricher_spy.assert_called_once_with(api_key="fake-api-key")
    enricher_instance.enrich_inventory.assert_called_once()


def test_non_collect_only_without_api_key_skips_wpscan_as_before(mocker):
    # Pre-existing behavior, unchanged: no key means no WPScanEnricher construction either.
    enricher_spy = mocker.patch("wpx.WPScanEnricher")
    args = _make_args(collect_only=False, api_key=None)

    wpx._run(args)

    enricher_spy.assert_not_called()


def test_collect_only_saves_artifact_with_collect_only_flag_in_meta(mocker):
    save_spy = mocker.patch(
        "wpx.save_scan_artifact", return_value=(mocker.MagicMock(), mocker.MagicMock())
    )
    args = _make_args(collect_only=True, no_artifact=False)

    wpx._run(args)

    assert save_spy.call_count == 1
    _, kwargs = save_spy.call_args
    assert kwargs["meta"]["collect_only"] is True


# ------------------------------------------------------------------
# `wpx.py enrich <scan-dir>` — offline enrichment subcommand
# ------------------------------------------------------------------

def test_run_enrich_loads_inventory_and_saves_report(mocker, tmp_path):
    inventory = {"target": "https://example.com", "plugins": []}
    mocker.patch("wpx.load_inventory", return_value=inventory)
    enrich_spy = mocker.patch.object(
        wpx.WPScanEnricher, "enrich_inventory",
        return_value={"status": "ok", "plugins": {}},
    )
    save_spy = mocker.patch("wpx.save_vulnerability_report", return_value=tmp_path / "vulnerability.json")

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])

    enrich_spy.assert_called_once_with(inventory)
    save_spy.assert_called_once()


def test_run_enrich_never_touches_the_target(mocker, tmp_path):
    # No WPXCore/WPXFinder/network-to-target machinery is even imported into
    # the enrich path — it only loads inventory.json and calls the enricher.
    inventory = {"target": "https://example.com", "plugins": []}
    mocker.patch("wpx.load_inventory", return_value=inventory)
    core_spy = mocker.patch("wpx.WPXCore")
    mocker.patch.object(wpx.WPScanEnricher, "enrich_inventory", return_value={"status": "ok", "plugins": {}})
    mocker.patch("wpx.save_vulnerability_report", return_value=tmp_path / "vulnerability.json")

    wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])

    core_spy.assert_not_called()


def test_run_enrich_requires_api_key():
    with pytest.raises(SystemExit):
        wpx._run_enrich(["some/scan/dir"])


def test_run_enrich_exits_nonzero_on_failed_status(mocker, tmp_path):
    mocker.patch("wpx.load_inventory", return_value={"target": "x", "plugins": []})
    mocker.patch.object(
        wpx.WPScanEnricher, "enrich_inventory",
        return_value={"status": "failed", "error": "boom", "plugins": {}},
    )
    mocker.patch("wpx.save_vulnerability_report", return_value=tmp_path / "vulnerability.json")

    with pytest.raises(SystemExit) as exc_info:
        wpx._run_enrich([str(tmp_path), "--api-key", "fake-key", "-q"])
    assert exc_info.value.code == 1


# ------------------------------------------------------------------
# `wpx.py report <scan-dir>` — offline report subcommand
# ------------------------------------------------------------------

def test_run_report_loads_all_three_files_and_prints(mocker, tmp_path, capsys):
    mocker.patch("wpx.load_scan_meta", return_value={"target": "https://example.com"})
    mocker.patch("wpx.load_inventory", return_value={
        "target": "https://example.com", "wordpress": None, "theme": None, "plugins": [],
        "users": {"found": [], "ran": False, "blocked_techniques": []},
        "multisite": None, "core_files": {}, "headers": None, "config_backups": [],
    })
    mocker.patch("wpx.load_vulnerability_report", return_value=None)

    wpx._run_report([str(tmp_path)])

    out = capsys.readouterr().out
    assert "https://example.com" in out


def test_run_report_never_touches_network(mocker, tmp_path):
    # No WPXCore, no WPScanEnricher — report is a pure read of local files.
    mocker.patch("wpx.load_scan_meta", return_value={"target": "https://example.com"})
    mocker.patch("wpx.load_inventory", return_value={
        "target": "https://example.com", "wordpress": None, "theme": None, "plugins": [],
        "users": {"found": [], "ran": False, "blocked_techniques": []},
        "multisite": None, "core_files": {}, "headers": None, "config_backups": [],
    })
    mocker.patch("wpx.load_vulnerability_report", return_value=None)
    core_spy = mocker.patch("wpx.WPXCore")
    enricher_spy = mocker.patch("wpx.WPScanEnricher")

    wpx._run_report([str(tmp_path)])

    core_spy.assert_not_called()
    enricher_spy.assert_not_called()


def test_run_report_uses_vulnerability_report_when_present(mocker, tmp_path, capsys):
    mocker.patch("wpx.load_scan_meta", return_value={"target": "https://example.com"})
    mocker.patch("wpx.load_inventory", return_value={
        "target": "https://example.com", "wordpress": None, "theme": None,
        "plugins": [{"slug": "elementor", "status": "passive", "location": "", "version": None,
                     "version_confidence": 0, "evidence": []}],
        "users": {"found": [], "ran": False, "blocked_techniques": []},
        "multisite": None, "core_files": {}, "headers": None, "config_backups": [],
    })
    mocker.patch("wpx.load_vulnerability_report", return_value={
        "status": "ok", "queried_at": "x", "plugins": {"elementor": {"vulns": []}},
    })

    wpx._run_report([str(tmp_path)])

    out = capsys.readouterr().out
    assert "elementor" in out
