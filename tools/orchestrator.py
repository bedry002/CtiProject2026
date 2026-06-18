"""
Testbed-only SBOM generator. NOT part of the runtime engine.

This script pulls SBOMs from a Dependency-Track instance running on the
project's testbed network. In production, organisations provide their own
SBOM via the /sbom upload page (form_api.py), the file drop at
Assets/SBOM.json, or the ORG_SBOM_PATH environment variable.
"""

"""SBOM ingestion orchestrator — uploads per-target SBOMs to Dependency-Track,
fetches enriched component and vulnerability data, and writes a merged CycloneDX
SBOM to Assets/SBOM.json for the curation pipeline to consume.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys
import time
import uuid
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

REPO_ROOT = pathlib.Path(__file__).resolve().parent
TARGETS_PATH = REPO_ROOT / "config" / "targets.json"
OUTPUT_PATH = REPO_ROOT / "Assets" / "SBOM.json"
ENV_PATH = REPO_ROOT / ".env"

POLL_INTERVAL_SECONDS = 5
POLL_TIMEOUT_SECONDS = 300
COMPONENT_PAGE_SIZE = 1000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("orchestrator")

_DT_TO_CDX_TYPE: dict[str, str] = {
    "APPLICATION":      "application",
    "FRAMEWORK":        "framework",
    "LIBRARY":          "library",
    "CONTAINER":        "container",
    "OPERATING_SYSTEM": "operating-system",
    "DEVICE":           "device",
    "FIRMWARE":         "firmware",
    "FILE":             "file",
}


class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-Api-Key": api_key}

    def upload_sbom(self, project_uuid: str, sbom_path: pathlib.Path) -> str:
        log.info("Uploading %s to project %s", sbom_path.name, project_uuid)
        with open(sbom_path, "rb") as f:
            response = requests.post(
                f"{self.base_url}/api/v1/bom",
                headers=self.headers,
                files={"bom": (sbom_path.name, f, "application/json")},
                data={"project": project_uuid},
                timeout=120,
            )
        response.raise_for_status()
        token = response.json().get("token")
        if not token:
            raise RuntimeError(f"DT did not return a token: {response.text}")
        log.info("Upload accepted, token=%s", token)
        return token

    def wait_for_processing(self, token: str) -> None:
        """Poll until DT finishes processing the BOM or timeout is reached."""
        url = f"{self.base_url}/api/v1/bom/token/{token}"
        deadline = time.time() + POLL_TIMEOUT_SECONDS
        while time.time() < deadline:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            if not response.json().get("processing", True):
                log.info("Processing complete for token %s", token)
                return
            log.info("Still processing... (token=%s)", token)
            time.sleep(POLL_INTERVAL_SECONDS)
        raise TimeoutError(
            f"DT did not finish processing within {POLL_TIMEOUT_SECONDS}s (token={token})"
        )

    def fetch_components(self, project_uuid: str) -> list[dict]:
        """Page through /api/v1/component for the project and return all components."""
        components: list[dict] = []
        page = 1
        while True:
            response = requests.get(
                f"{self.base_url}/api/v1/component/project/{project_uuid}",
                headers=self.headers,
                params={"pageSize": COMPONENT_PAGE_SIZE, "pageNumber": page},
                timeout=60,
            )
            response.raise_for_status()
            batch = response.json()
            if not batch:
                break
            components.extend(batch)
            log.info("Fetched %d components (page %d)", len(batch), page)
            if len(batch) < COMPONENT_PAGE_SIZE:
                break
            page += 1
        return components

    def fetch_vulnerabilities(self, component_uuid: str) -> list[dict]:
        url = f"{self.base_url}/api/v1/vulnerability/component/{component_uuid}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json() or []
        except requests.HTTPError:
            return []


def assign_criticality(component: dict, has_vulnerabilities: bool) -> str:
    """Assign criticality: OS → high; vulnerable → high; library → medium; else → low."""
    classifier = (component.get("classifier") or "").upper()
    if classifier == "OPERATING_SYSTEM":
        return "high"
    if has_vulnerabilities:
        return "high"
    if classifier == "LIBRARY":
        return "medium"
    return "low"


def dt_classifier_to_cyclonedx_type(classifier: str | None) -> str:
    return _DT_TO_CDX_TYPE.get((classifier or "").upper(), "library")


def build_cyclonedx_component(dt_component: dict, has_vulnerabilities: bool, source_project: str) -> dict:
    name = dt_component.get("name", "unknown")
    version = dt_component.get("version", "")

    # best-effort supplier extraction
    supplier_name = (
        (dt_component.get("supplier") or {}).get("name")
        or dt_component.get("group")
        or "Unknown"
    )

    properties: list[dict] = [
        {"name": "criticality",    "value": assign_criticality(dt_component, has_vulnerabilities)},
        {"name": "source_project", "value": source_project},
    ]
    if has_vulnerabilities:
        properties.append({"name": "has_vulnerabilities", "value": "true"})

    component: dict = {
        "type":      dt_classifier_to_cyclonedx_type(dt_component.get("classifier")),
        "bom-ref":   dt_component.get("uuid") or f"{name}@{version}",
        "name":      name,
        "version":   version,
        "supplier":  {"name": supplier_name},
        "properties": properties,
    }
    if cpe := dt_component.get("cpe"):
        component["cpe"] = cpe
    if purl := dt_component.get("purl"):
        component["purl"] = purl
    return component


def dedupe_components(components: list[dict]) -> list[dict]:
    """Deduplicate by (cpe, version) or (name, version) — first occurrence wins."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for c in components:
        key = (c.get("cpe") or c.get("name"), c.get("version"))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def build_final_sbom(all_components: list[dict]) -> dict:
    return {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {"vendor": "Anchore", "name": "Syft",              "version": "1.39.0"},
                {"vendor": "OWASP",   "name": "Dependency-Track",  "version": "4.14"},
            ],
            "authors": [{"name": "SBOM Orchestrator"}],
            "component": {
                "type":        "application",
                "bom-ref":     "testbed-environment",
                "name":        "Test-Bed Environment - Aggregated SBOM",
                "version":     datetime.now(timezone.utc).strftime("%Y.%m"),
                "description": (
                    "Aggregated CycloneDX SBOM produced by scanning OpenCTI and "
                    "MISP container images with Syft and enriching component "
                    "metadata via Dependency-Track."
                ),
                "supplier": {"name": "Internal Research Environment"},
            },
        },
        "components": all_components,
    }


def load_targets(filter_names: list[str] | None) -> list[dict]:
    if not TARGETS_PATH.exists():
        log.error("targets.json not found at %s", TARGETS_PATH)
        sys.exit(1)
    with open(TARGETS_PATH) as f:
        data = json.load(f)
    targets = data.get("targets", [])
    if filter_names:
        wanted = {n.lower() for n in filter_names}
        targets = [t for t in targets if t["container_name"].lower() in wanted]
    if not targets:
        log.error("No targets matched filter %s", filter_names)
        sys.exit(1)
    return targets


def process_target(target: dict, client: DependencyTrackClient) -> list[dict]:
    """Upload, wait, fetch, and transform one target's SBOM. Returns CycloneDX components."""
    name = target["container_name"]
    sbom_path = pathlib.Path(target["sbom_file"])
    project_uuid = target["dt_project_uuid"]

    if not sbom_path.exists():
        log.warning("Skipping %s — SBOM file not found at %s", name, sbom_path)
        return []
    try:
        token = client.upload_sbom(project_uuid, sbom_path)
        client.wait_for_processing(token)
        dt_components = client.fetch_components(project_uuid)
    except (requests.HTTPError, TimeoutError) as e:
        log.error("Failed to process %s: %s", name, e)
        return []

    log.info("Transforming %d components from %s", len(dt_components), name)
    return [
        build_cyclonedx_component(c, bool(client.fetch_vulnerabilities(c.get("uuid", ""))), name)
        for c in dt_components
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="SBOM ingestion orchestrator")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run the full pipeline but skip writing Assets/SBOM.json")
    parser.add_argument("--targets", nargs="+",
                        help="Only process specific targets by container_name (default: all)")
    args = parser.parse_args()

    load_dotenv(ENV_PATH)
    api_key  = os.getenv("DT_API_KEY")
    base_url = os.getenv("DT_BASE_URL")

    if not api_key:
        log.error("DT_API_KEY not set — check your .env file at %s", ENV_PATH)
        sys.exit(1)

    client  = DependencyTrackClient(base_url, api_key)
    targets = load_targets(args.targets)
    log.info("Processing %d target(s): %s", len(targets), [t["container_name"] for t in targets])

    all_components: list[dict] = []
    for target in targets:
        all_components.extend(process_target(target, client))

    all_components = dedupe_components(all_components)
    vuln_count = sum(
        1 for c in all_components
        if any(p["name"] == "has_vulnerabilities" for p in c.get("properties", []))
    )
    log.info("Merged %d components (%d with vulnerabilities)", len(all_components), vuln_count)

    sbom = build_final_sbom(all_components)

    if args.dry_run:
        log.info("Dry run — not writing %s", OUTPUT_PATH)
    else:
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)
        log.info("Wrote %s", OUTPUT_PATH)


if __name__ == "__main__":
    main()
