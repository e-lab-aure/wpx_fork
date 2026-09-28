import pytest


@pytest.fixture(autouse=True)
def reset_output_state():
    """wpx_output keeps `_quiet`/`_output_file` as module globals set by init_output().

    Tests that exercise CLI entry points (_run_enrich, _run_report, ...) call
    init_output(quiet=True) as a side effect, which otherwise leaks into later
    tests in the same process and silently suppresses their print_info/print_status
    output. Reset to the module's own defaults before and after every test.
    """
    import wpx_output
    wpx_output.init_output(quiet=False, output_file=None)
    yield
    wpx_output.init_output(quiet=False, output_file=None)


@pytest.fixture
def mock_core(mocker):
    """Minimal WPXCore stub with a session and target_url."""
    core = mocker.MagicMock()
    core.target_url = "https://example.com"
    return core


@pytest.fixture
def mock_data(mocker):
    """Minimal WPXData stub."""
    return mocker.MagicMock()


@pytest.fixture
def finder(mock_core, mock_data):
    from wpx_finder import WPXFinder
    return WPXFinder(mock_core, mock_data)
