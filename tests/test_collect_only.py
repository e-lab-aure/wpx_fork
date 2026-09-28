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


def test_collect_only_never_constructs_wpxvulnerability_even_with_api_key(mocker):
    vuln_spy = mocker.patch("wpx.WPXVulnerability")
    args = _make_args(collect_only=True, api_key="fake-api-key")

    wpx._run(args)

    vuln_spy.assert_not_called()


def test_collect_only_without_api_key_also_skips_wpscan(mocker):
    vuln_spy = mocker.patch("wpx.WPXVulnerability")
    args = _make_args(collect_only=True, api_key=None)

    wpx._run(args)

    vuln_spy.assert_not_called()


def test_non_collect_only_with_api_key_still_calls_wpscan(mocker):
    vuln_instance = mocker.MagicMock()
    vuln_instance.get_vulnerabilities.return_value = None
    vuln_spy = mocker.patch("wpx.WPXVulnerability", return_value=vuln_instance)
    args = _make_args(collect_only=False, api_key="fake-api-key")

    wpx._run(args)

    vuln_spy.assert_called_once_with(api_key="fake-api-key")


def test_non_collect_only_without_api_key_skips_wpscan_as_before(mocker):
    # Pre-existing behavior, unchanged: no key means no WPXVulnerability construction either.
    vuln_spy = mocker.patch("wpx.WPXVulnerability")
    args = _make_args(collect_only=False, api_key=None)

    wpx._run(args)

    vuln_spy.assert_not_called()


def test_collect_only_saves_artifact_with_collect_only_flag_in_meta(mocker):
    save_spy = mocker.patch(
        "wpx.save_scan_artifact", return_value=(mocker.MagicMock(), mocker.MagicMock())
    )
    args = _make_args(collect_only=True, no_artifact=False)

    wpx._run(args)

    assert save_spy.call_count == 1
    _, kwargs = save_spy.call_args
    assert kwargs["meta"]["collect_only"] is True
