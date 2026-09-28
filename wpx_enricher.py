"""Offline WPScan enrichment.

`WPScanEnricher` takes an already-collected inventory (as produced by
`WPXFinder.to_inventory()` / persisted by `wpx_artifact.save_scan_artifact()`)
and queries the WPScan vulnerability database for each plugin slug it
contains. It never talks to the scanned target — only to the WPScan API —
and it discovers nothing itself: everything it queries came from the
inventory it was handed.

A WPScan failure (network error, bad key, quota, API outage) never raises
out of `enrich_inventory()` — the enrichment result records the failure so
the caller can persist it and retry `enrich` later without ever touching or
corrupting the collection artifact.
"""

from datetime import datetime, timezone

from wpx_vulnerability import WPXVulnerability


class WPScanEnricher:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def enrich_inventory(self, inventory):
        """Query WPScan for every plugin slug in `inventory`. Read-only, offline w.r.t. target.

        Returns a dict ready to be persisted as vulnerability.json:
            {"status": "skipped_no_api_key" | "ok" | "failed",
             "queried_at": <iso timestamp>,
             "plugins": {slug: <api result dict> | {"status": "error", "error": str} | None}}

        `status` is "failed" only if enrichment could not run at all (e.g. the
        WPScan client failed to construct); per-slug failures stay inside
        `plugins` and never abort the rest of the batch.
        """
        result = {
            "status": "ok",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "plugins": {},
        }

        if not self.api_key:
            result["status"] = "skipped_no_api_key"
            return result

        try:
            vuln_api = WPXVulnerability(api_key=self.api_key)
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            return result

        # Plugins are already deduplicated by slug in the inventory (one entry
        # per slug) — one WPScan request per slug, never per detection source.
        slugs = sorted({p["slug"] for p in inventory.get("plugins", []) if p.get("slug")})

        for slug in slugs:
            try:
                result["plugins"][slug] = vuln_api.get_vulnerabilities("plugins", slug)
            except Exception as e:
                # get_vulnerabilities() already catches its own exceptions and
                # returns None on failure — this is a last-resort guard so one
                # bad slug can never abort the batch or corrupt the artifact.
                result["plugins"][slug] = {"status": "error", "error": str(e)}

        return result
