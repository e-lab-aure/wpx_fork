from browserforge.fingerprints import Screen
from camoufox import Camoufox
from curl_cffi import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
import importlib.metadata
import time
import traceback
from wpx_output import print_status, print_warn

# Défaut généreux : "networkidle" attendait que le réseau soit silencieux, ce qui n'arrive
# jamais sur un site avec des scripts d'analytics/chat en polling continu — d'où les
# TimeoutError observées même sur des pages qui avaient déjà fini de charger.
# "domcontentloaded" ne dépend plus de ce silence réseau ; le timeout reste généreux car un
# défi WAF/JS peut prendre plusieurs secondes avant de rediriger.
DEFAULT_NAV_TIMEOUT_MS = 60000


class WPXCore:
    def __init__(self, target_url, nav_timeout_ms=DEFAULT_NAV_TIMEOUT_MS):
        self.target_url = target_url
        self.cookies = {}
        self.user_agent = ""
        self.session = None
        self.nav_timeout_ms = nav_timeout_ms

    def _page_seems_usable(self, page):
        """Après un timeout de navigation, la page est-elle malgré tout exploitable ?

        `bypass_waf()` n'a besoin que des cookies et de l'UA — pas d'un rendu complet. Une
        page de défi WAF/JS a souvent déjà servi assez de DOM (title, scripts du challenge)
        pour ça, même si `domcontentloaded` n'a jamais officiellement été signalé côté
        Playwright. On vérifie plusieurs indices plutôt que de se fier à un seul, aucun n'est
        déterminant seul :
        - URL courante : navigation au moins entamée (pas restée sur about:blank) ;
        - readyState du DOM : "interactive"/"complete" signale un DOM utilisable ;
        - taille du contenu : une page de défi vide indique généralement un blocage réel.
        """
        try:
            url = page.url
        except Exception:
            url = ""
        if not url or url == "about:blank":
            print_status("  Page toujours sur about:blank — navigation jamais entamée.")
            return False

        try:
            ready_state = page.evaluate("document.readyState")
        except Exception:
            ready_state = None

        try:
            content = page.content()
        except Exception:
            content = ""
        content_len = len(content)

        print_status(f"  URL courante        : {url}")
        print_status(f"  document.readyState : {ready_state}")
        print_status(f"  Taille du contenu    : {content_len} octets")

        return content_len > 200 or ready_state in ("interactive", "complete")

    def bypass_waf(self):
        print_status(f"Launching Camoufox to bypass WAF for {self.target_url}...")
        try:
            # Pass a realistic screen size — WSL's virtual display is 640x480
            # which is below the minimum resolution in browserforge's training data,
            # causing fingerprint generation to fail. A standard 1920x1080 works.
            screen = Screen(min_width=1280, min_height=720, max_width=1920, max_height=1080)
            with Camoufox(headless=True, screen=screen) as browser:
                page = browser.new_page()

                # Navigate and solve challenge. "domcontentloaded" plutôt que "networkidle" :
                # ce dernier attend un silence réseau qui n'arrive jamais sur beaucoup de
                # sites (widgets de chat, analytics en polling), causant des TimeoutError
                # même quand la page a déjà fini de charger pour de vrai.
                try:
                    page.goto(self.target_url, wait_until="domcontentloaded",
                             timeout=self.nav_timeout_ms)
                except PlaywrightTimeoutError:
                    print_warn(f"Navigation timed out after {self.nav_timeout_ms}ms — "
                              "checking whether the page is usable anyway...")
                    if not self._page_seems_usable(page):
                        print_warn("Page does not appear usable after the timeout — "
                                  "aborting WAF bypass.")
                        return False
                    print_status("Page appears usable despite the timeout — continuing.")

                # Allow extra time for WAF JS challenge redirect to complete
                time.sleep(5)

                print_status("Page loaded. Extracting session tokens...")

                # Extract cookies
                self.cookies = {c['name']: c['value'] for c in page.context.cookies()}

                # Extract the exact User-Agent used by Camoufox
                self.user_agent = page.evaluate("navigator.userAgent")

                print_status(f"Extracted User-Agent: {self.user_agent[:60]}...")
                print_status(f"Extracted {len(self.cookies)} cookies.")

                return True
        except Exception as e:
            print_warn("── Camoufox launch failed ─────────────────────────────────────")
            print_warn(f" Error type : {type(e).__name__}")
            print_warn(f" Message    : {e}")
            print_warn("")
            print_warn(" Traceback:")
            for line in traceback.format_exc().splitlines():
                print_warn(f"   {line}")
            print_warn("")
            print_warn(" Installed versions:")
            for pkg in ("camoufox", "browserforge", "playwright"):
                try:
                    ver = importlib.metadata.version(pkg)
                except importlib.metadata.PackageNotFoundError:
                    ver = "NOT INSTALLED"
                print_warn(f"   {pkg}: {ver}")
            if "No headers based on this input" in str(e):
                print_warn("")
                print_warn(" Diagnosis: browserforge could not find a fingerprint matching the")
                print_warn("            screen size detected by camoufox. This commonly happens")
                print_warn("            on WSL/headless Linux where the virtual display is very")
                print_warn("            small (e.g. 640x480), below the minimum in the training")
                print_warn("            data. WPX passes an explicit screen size to work around")
                print_warn("            this — if you see this error, please report it.")
            print_warn("──────────────────────────────────────────────────────────────")
            return False

    _DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    )

    def setup_mirror_session(self):
        bypassed = bool(self.user_agent)
        if bypassed:
            print_status("Initializing mirrored curl_cffi session (WAF bypass active)...")
        else:
            print_status("Initializing direct curl_cffi session (no WAF bypass)...")

        self.session = requests.Session()
        ua = self.user_agent or self._DEFAULT_UA

        # Mirror the browser headers precisely
        self.session.headers.update({
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })

        print_status("Testing session...")
        try:
            res = self.session.get(
                self.target_url,
                cookies=self.cookies,
                impersonate="firefox",
                timeout=30
            )
            print_status(f"Session test status: {res.status_code}")

            if res.status_code == 200:
                if bypassed:
                    print_status("Mirror session validated! We are through the WAF.")
                else:
                    print_status("Direct session OK (site does not appear to require WAF bypass).")
                return True
            else:
                if bypassed:
                    print_warn(f"Mirror session failed with status {res.status_code} — WAF may still be blocking.")
                else:
                    print_warn(f"Direct session returned status {res.status_code} — site may require WAF bypass.")
                return False
        except Exception as e:
            print_warn(f"Session test failed: {e}")
            return False


if __name__ == "__main__":
    # Test core bypass
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://247defensivedriving.com"
    core = WPXCore(url)
    if core.bypass_waf():
        core.setup_mirror_session()
