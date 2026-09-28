"""Collection artifact persistence.

Writes `scan.json` (run metadata) + `inventory.json` (normalized findings from
`WPXFinder.to_inventory()`) to a scan directory. Written once collection
completes, strictly before any WPScan enrichment — the artifact must be
re-enrichable and re-reportable later, fully offline with respect to the
target, from these two files alone.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCAN_JSON = "scan.json"
INVENTORY_JSON = "inventory.json"


def _slugify_host(target_url):
    host = re.sub(r'^https?://', '', target_url).split('/')[0]
    return re.sub(r'[^a-z0-9.-]+', '-', host.lower()).strip('-') or "target"


def new_scan_dir(target_url, base_dir="scans", when=None):
    """Allocate a fresh timestamped scan directory under base_dir."""
    when = when or datetime.now(timezone.utc)
    scan_id = f"{when.strftime('%Y%m%dT%H%M%SZ')}-{_slugify_host(target_url)}"
    scan_dir = Path(base_dir) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


def save_scan_artifact(scan_dir, target_url, inventory, meta=None):
    """Persist scan.json + inventory.json into scan_dir. Returns (scan_path, inventory_path)."""
    scan_dir = Path(scan_dir)
    scan_dir.mkdir(parents=True, exist_ok=True)

    scan_meta = {
        "target": target_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": 1,
        **(meta or {}),
    }

    scan_path = scan_dir / SCAN_JSON
    inventory_path = scan_dir / INVENTORY_JSON
    scan_path.write_text(json.dumps(scan_meta, indent=2, sort_keys=True), encoding="utf-8")
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True), encoding="utf-8")
    return scan_path, inventory_path


def load_inventory(scan_dir):
    scan_dir = Path(scan_dir)
    return json.loads((scan_dir / INVENTORY_JSON).read_text(encoding="utf-8"))


def load_scan_meta(scan_dir):
    scan_dir = Path(scan_dir)
    return json.loads((scan_dir / SCAN_JSON).read_text(encoding="utf-8"))
