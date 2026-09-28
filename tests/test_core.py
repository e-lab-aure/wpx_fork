import pytest
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from wpx_core import WPXCore, DEFAULT_NAV_TIMEOUT_MS


class _FakeCookieJar:
    def __init__(self, cookies):
        self._cookies = cookies

    def cookies(self):
        return self._cookies


class _FakePage:
    """Stand-in for a Playwright page, configurable per test."""

    def __init__(self, goto_raises=None, url="https://example.com/",
                 ready_state="complete", content="<html>" + "x" * 300 + "</html>",
                 user_agent="TestUA/1.0", cookies=None):
        self._goto_raises = goto_raises
        self.url = url
        self._ready_state = ready_state
        self._content = content
        self._user_agent = user_agent
        self.context = _FakeCookieJar(cookies or [{"name": "a", "value": "b"}])
        self.goto_calls = []

    def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append({"url": url, "wait_until": wait_until, "timeout": timeout})
        if self._goto_raises:
            raise self._goto_raises

    def evaluate(self, expr):
        if expr == "document.readyState":
            return self._ready_state
        if expr == "navigator.userAgent":
            return self._user_agent
        raise ValueError(f"unexpected evaluate: {expr}")

    def content(self):
        return self._content


class _FakeBrowser:
    def __init__(self, page):
        self._page = page

    def new_page(self):
        return self._page


class _FakeCamoufoxCtx:
    """Mimics `with Camoufox(...) as browser:`."""

    def __init__(self, page):
        self._browser = _FakeBrowser(page)

    def __enter__(self):
        return self._browser

    def __exit__(self, *exc_info):
        return False


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    mocker.patch("wpx_core.time.sleep")


def test_bypass_waf_uses_domcontentloaded_and_configured_timeout(mocker):
    page = _FakePage()
    mocker.patch("wpx_core.Camoufox", return_value=_FakeCamoufoxCtx(page))

    core = WPXCore("https://example.com", nav_timeout_ms=12345)
    assert core.bypass_waf() is True

    assert page.goto_calls == [
        {"url": "https://example.com", "wait_until": "domcontentloaded", "timeout": 12345}
    ]


def test_default_nav_timeout_is_used_when_not_specified(mocker):
    page = _FakePage()
    mocker.patch("wpx_core.Camoufox", return_value=_FakeCamoufoxCtx(page))

    core = WPXCore("https://example.com")
    assert core.bypass_waf() is True

    assert page.goto_calls[0]["timeout"] == DEFAULT_NAV_TIMEOUT_MS


def test_bypass_waf_recovers_from_timeout_when_page_is_usable(mocker):
    page = _FakePage(goto_raises=PlaywrightTimeoutError("Timeout 60000ms exceeded"))
    mocker.patch("wpx_core.Camoufox", return_value=_FakeCamoufoxCtx(page))

    core = WPXCore("https://example.com")
    result = core.bypass_waf()

    assert result is True
    assert core.user_agent == "TestUA/1.0"
    assert core.cookies == {"a": "b"}


def test_bypass_waf_aborts_when_page_unusable_after_timeout(mocker):
    page = _FakePage(
        goto_raises=PlaywrightTimeoutError("Timeout 60000ms exceeded"),
        url="about:blank",
        ready_state=None,
        content="",
    )
    mocker.patch("wpx_core.Camoufox", return_value=_FakeCamoufoxCtx(page))

    core = WPXCore("https://example.com")
    assert core.bypass_waf() is False


def test_page_seems_usable_true_on_ready_state_even_with_short_content():
    core = WPXCore("https://example.com")
    page = _FakePage(ready_state="interactive", content="short")
    assert core._page_seems_usable(page) is True


def test_page_seems_usable_true_on_content_length_even_without_ready_state():
    core = WPXCore("https://example.com")
    page = _FakePage(ready_state=None, content="x" * 500)
    assert core._page_seems_usable(page) is True


def test_page_seems_usable_false_on_blank_url():
    core = WPXCore("https://example.com")
    page = _FakePage(url="about:blank")
    assert core._page_seems_usable(page) is False


def test_page_seems_usable_false_when_both_signals_weak():
    core = WPXCore("https://example.com")
    page = _FakePage(ready_state="loading", content="tiny")
    assert core._page_seems_usable(page) is False
