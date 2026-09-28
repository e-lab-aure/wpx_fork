import json

import pytest

from wpx_artifact import new_scan_dir, save_scan_artifact, load_inventory, load_scan_meta


# ------------------------------------------------------------------
# WPXFinder.to_inventory()
# ------------------------------------------------------------------

def test_to_inventory_empty_state(finder):
    inv = finder.to_inventory()
    assert inv["target"] == "https://example.com"
    assert inv["wordpress"] is None
    assert inv["theme"] is None
    assert inv["plugins"] == []
    assert inv["users"] == {"found": [], "ran": False, "blocked_techniques": []}
    assert inv["multisite"] is None
    assert inv["core_files"] == {}
    assert inv["headers"] is None
    assert inv["config_backups"] == []


def test_to_inventory_wp_version_unconfirmed(finder):
    finder.wp_version = {
        "version": "6.4.1",
        "found_by": "Meta Generator (Passive Detection)",
        "found_url": "https://example.com/",
        "found_match": "WordPress 6.4.1",
        "confirmed_by": None,
        "is_latest": True,
        "latest_version": "6.4.1",
        "release_date": "2023-11-07",
    }
    wv = finder.to_inventory()["wordpress"]
    assert wv["version"] == "6.4.1"
    assert wv["confidence"] == 80
    assert len(wv["evidence"]) == 1
    assert wv["is_latest"] is True


def test_to_inventory_wp_version_confirmed_raises_confidence(finder):
    finder.wp_version = {
        "version": "6.4.1",
        "found_by": "Meta Generator (Passive Detection)",
        "found_url": "https://example.com/",
        "found_match": "WordPress 6.4.1",
        "confirmed_by": {
            "method": "Rss Generator (Aggressive Detection)",
            "url": "https://example.com/feed/",
            "match": "<generator>https://wordpress.org/?v=6.4.1</generator>",
        },
        "is_latest": None,
        "latest_version": None,
        "release_date": None,
    }
    wv = finder.to_inventory()["wordpress"]
    assert wv["confidence"] == 100
    assert len(wv["evidence"]) == 2


def test_to_inventory_theme(finder):
    finder.theme = {
        "slug": "twentytwentyfour",
        "location": "https://example.com/wp-content/themes/twentytwentyfour/",
        "style_url": "https://example.com/wp-content/themes/twentytwentyfour/style.css",
        "found_by": "Urls In Homepage (Passive Detection)",
        "confirmed_by": None,
        "name": "Twenty Twenty-Four",
        "description": "A theme",
        "author": "WordPress team",
        "version": "1.0",
        "version_confidence": 80,
        "version_found_by": "Style (Passive Detection)",
        "readme_url": None,
    }
    th = finder.to_inventory()["theme"]
    assert th["slug"] == "twentytwentyfour"
    assert th["version"] == "1.0"
    assert th["version_confidence"] == 80


def test_to_inventory_theme_string_only_not_serialized_as_dict(finder):
    # Before detect_theme_details() runs, self.theme is just a slug string.
    finder.theme = "twentytwentyfour"
    assert finder.to_inventory()["theme"] is None


def test_to_inventory_plugin_unknown_version_stays_unknown_not_invented(finder):
    finder.found_plugins = {
        "contact-form-7": {
            "status": "passive",
            "version": "Unknown",
            "version_confidence": 0,
            "version_found_by": None,
            "version_url": None,
            "found_by": "Urls In Homepage (Passive Detection)",
            "confirmed_by": None,
            "location": "https://example.com/wp-content/plugins/contact-form-7/",
        }
    }
    plugins = finder.to_inventory()["plugins"]
    assert len(plugins) == 1
    assert plugins[0]["slug"] == "contact-form-7"
    assert plugins[0]["version"] is None
    assert plugins[0]["version_confidence"] == 0


def test_to_inventory_plugin_with_known_version(finder):
    finder.found_plugins = {
        "elementor": {
            "status": 200,
            "version": "3.18.0",
            "version_confidence": 100,
            "version_found_by": "Readme - Stable Tag (Aggressive Detection)",
            "version_url": "https://example.com/wp-content/plugins/elementor/readme.txt",
            "found_by": "Known Locations (Aggressive Detection)",
            "confirmed_by": None,
            "location": "https://example.com/wp-content/plugins/elementor/",
        }
    }
    plugin = finder.to_inventory()["plugins"][0]
    assert plugin["version"] == "3.18.0"
    assert plugin["version_confidence"] == 100
    assert any("Readme" in e["found_by"] for e in plugin["evidence"])


def test_to_inventory_config_backups_wrapped_with_evidence(finder):
    finder.config_backups = ["https://example.com/wp-config.php.bak"]
    backups = finder.to_inventory()["config_backups"]
    assert backups == [{
        "url": "https://example.com/wp-config.php.bak",
        "confidence": 100,
        "found_by": "Config Backup (Aggressive Detection)",
    }]


def test_to_inventory_does_not_hit_network(finder, mocker):
    # to_inventory() must be a pure read of already-collected state.
    finder.found_plugins = {"x": {
        "status": "passive", "version": "Unknown", "version_confidence": 0,
        "version_found_by": None, "version_url": None,
        "found_by": "Urls In Homepage (Passive Detection)",
        "confirmed_by": None, "location": "https://example.com/wp-content/plugins/x/",
    }}
    spy = mocker.patch.object(finder.core, "session")
    finder.to_inventory()
    spy.get.assert_not_called()


# ------------------------------------------------------------------
# wpx_artifact.py — collection artifact persistence
# ------------------------------------------------------------------

def test_new_scan_dir_creates_directory(tmp_path):
    scan_dir = new_scan_dir("https://example.com", base_dir=tmp_path)
    assert scan_dir.exists()
    assert "example.com" in scan_dir.name


def test_save_and_load_scan_artifact_roundtrip(tmp_path):
    inventory = {"target": "https://example.com", "wordpress": None, "plugins": []}
    scan_path, inventory_path = save_scan_artifact(
        tmp_path, "https://example.com", inventory, meta={"threads": 20}
    )

    assert scan_path.exists()
    assert inventory_path.exists()

    loaded_inventory = load_inventory(tmp_path)
    assert loaded_inventory == inventory

    meta = load_scan_meta(tmp_path)
    assert meta["target"] == "https://example.com"
    assert meta["threads"] == 20
    assert meta["schema_version"] == 1


def test_artifact_module_never_imports_wpscan_client():
    # The collection artifact must be independently writable without any
    # WPScan dependency — enforces the "no WPScan during collection" rule
    # at the module level, not just by convention.
    import wpx_artifact
    assert "wpx_vulnerability" not in vars(wpx_artifact)


def test_save_scan_artifact_is_valid_json(tmp_path):
    inventory = {"target": "https://example.com", "plugins": [{"slug": "x", "version": None}]}
    scan_path, inventory_path = save_scan_artifact(tmp_path, "https://example.com", inventory)
    with open(inventory_path) as f:
        assert json.load(f) == inventory
    with open(scan_path) as f:
        json.load(f)  # must not raise
