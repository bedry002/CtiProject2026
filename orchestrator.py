import argparse
import json
import os
import logging
import pathlib
import sys
import time
import uuid
from datetime import datetime, timezone

import requests # for HTTP calls 
from dotenv import load_dotenv # loading .env file

REPO_ROOT = pathlib.Path(__file__).resolve().parent 
TARGETS_PATH = REPO_ROOT / "config" / "targets.json"
OUTPUT_PATH = REPO_ROOT / "Assets" / "SBOM.json"
ENV_PATH = REPO_ROOT / ".env"

POLL_INTERVAL_SECONDS = 5 # 5sec checks for the upload
POLL_TIMEOUT_SECONDS = 300 # 5mins per target
COMPONENT_PAGE_SIZE = 1000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("orchestrator")

class DependencyTrackClient:
    #Class for all the DT interactions
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-Api-Key": api_key}

    # curl -X POST address/api/v1/bom -F "project=uuid" -F "bom=file.json"
    def upload_sbom(self, project_uuid, sbom_path):
        
        url = f"{self.base_url}/api/v1/bom"
        log.info("Uploading %s to project %s", sbom_path.name, project_uuid)

        with open(sbom_path, "rb") as f:
            response = requests.post(
                url,
                headers=self.headers,
                files={"bom": (sbom_path.name, f, "application/json")},
                data={"project": project_uuid},
                timeout=120,
            )

        response.raise_for_status() # ask for the token
        token = response.json().get("token") # token for checking
        if not token:
            raise RuntimeError(f"DT did not return a token: {response.text}")
        log.info("Upload accepted, token=%s", token)
        return token

    def wait_for_processing(self, token):
        # Poll the token endpoint until DT finishes processing the BOM.
        url = f"{self.base_url}/api/v1/bom/token/{token}"
        deadline = time.time() + POLL_TIMEOUT_SECONDS

        #if the time is less than 5mins i.e., not hung
        while time.time() < deadline:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status() # ask if the processing is done
            processing = response.json().get("processing", True)

            if not processing: # if ({"processing" = false}) meaning the upload is done
                log.info("Processing complete for token %s", token)
                return

            log.info("Still processing... (token=%s)", token) # if its true, meaning still processing
            time.sleep(POLL_INTERVAL_SECONDS) # wait a bit and try again

        raise TimeoutError(
            f"DT did not finish processing within {POLL_TIMEOUT_SECONDS}s "
            f"(token={token})"
        )

    def fetch_components(self, project_uuid):
        # Page through /api/v1/component for the project and return them all in batches of a 1000
        components: list[dict] = []
        page = 1

        while True:
            url = f"{self.base_url}/api/v1/component/project/{project_uuid}" # project api access
            params = {"pageSize": COMPONENT_PAGE_SIZE, "pageNumber": page}
            response = requests.get(
                url, headers=self.headers, params=params, timeout=60
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

    def fetch_vulnerabilities(self, component_uuid):
        #Get vulnerabilities for a single component
        url = f"{self.base_url}/api/v1/vulnerability/component/{component_uuid}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json() or []
        except requests.HTTPError:
            return []

# Each component gets a special weight to fit the parser
def assign_criticality(component, has_vulnerabilities):
    """Rules:
       - Operating systems -> high
       - Components with known vulnerabilities -> high
       - Libraries with no vulns -> medium
       - Everything else -> low
    """
    classifier = (component.get("classifier") or "").upper()

    if classifier == "OPERATING_SYSTEM":
        return "high"
    if has_vulnerabilities:
        return "high"
    if classifier == "LIBRARY":
        return "medium"
    return "low"


def dt_classifier_to_cyclonedx_type(classifier):
    # Translates the DT language to CycloneDX format
    mapping = {
        "APPLICATION": "application",
        "FRAMEWORK": "framework",
        "LIBRARY": "library",
        "CONTAINER": "container",
        "OPERATING_SYSTEM": "operating-system",
        "DEVICE": "device",
        "FIRMWARE": "firmware",
        "FILE": "file",
    }
    return mapping.get((classifier or "").upper(), "library")

# Func to pull name, version, CPE, purl, and supplier
def build_cyclonedx_component(dt_component, has_vulnerabilities, source_project):
    
    name = dt_component.get("name", "unknown")
    version = dt_component.get("version", "")
    cpe = dt_component.get("cpe")
    purl = dt_component.get("purl")
    classifier = dt_component.get("classifier")

    # best-effort supplier extraction
    supplier_name = (
        (dt_component.get("supplier") or {}).get("name")
        or dt_component.get("group")
        or "Unknown"
    )

    properties = [
        {
            "name": "criticality",
            "value": assign_criticality(dt_component, has_vulnerabilities),
        },
        {
            "name": "source_project",
            "value": source_project,
        },
    ]

    if has_vulnerabilities:
        properties.append({"name": "has_vulnerabilities", "value": "true"})

    # vulnerable components
    component = {
        "type": dt_classifier_to_cyclonedx_type(classifier), # vulnerability type
        "bom-ref": dt_component.get("uuid") or f"{name}@{version}", # source project uuid and name
        "name": name, # component name
        "version": version,
        "supplier": {"name": supplier_name},
        "properties": properties,
    }

    if cpe:
        component["cpe"] = cpe
    if purl:
        component["purl"] = purl

    return component


def dedupe_components(components):
    # Drop duplicates that share the same (cpe + version) or (name + version).
    seen: set[tuple] = set()
    unique: list[dict] = []

    # check every component for duplicates
    for c in components:
        key = (c.get("cpe") or c.get("name"), c.get("version"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    return unique


def build_final_sbom(all_components: list[dict]) -> dict:
    #Wrap merged components in a CycloneDX envelope matching the existing Assets/SBOM.json structure
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "Anchore",
                    "name": "Syft",
                    "version": "1.39.0",
                },
                {
                    "vendor": "OWASP",
                    "name": "Dependency-Track",
                    "version": "4.14",
                },
            ],
            "authors": [{"name": "SBOM Orchestrator"}],
            "component": {
                "type": "application",
                "bom-ref": "testbed-environment",
                "name": "Test-Bed Environment - Aggregated SBOM",
                "version": datetime.now(timezone.utc).strftime("%Y.%m"),
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

# for putting in the target json files componenets in the script so syft knows what to scan
def load_targets(filter_names):
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


def process_target(target, client):
    # Run the full pipeline for one target — upload, wait, fetch, transform. Process each sbom seperately
    # instead of main fucntion, isolate each sbom here to ake sure the sboms dont interrupt each other
    name = target["container_name"]
    sbom_path = pathlib.Path(target["sbom_file"])
    project_uuid = target["dt_project_uuid"]

    if not sbom_path.exists():
        log.warning("Skipping %s - SBOM file not found at %s", name, sbom_path)
        return []

    try:
        token = client.upload_sbom(project_uuid, sbom_path)
        client.wait_for_processing(token)
        dt_components = client.fetch_components(project_uuid)
    except (requests.HTTPError, TimeoutError) as e:
        log.error("Failed to process %s: %s", name, e)
        return []

    log.info("Transforming %d components from %s", len(dt_components), name)

    cyclonedx_components: list[dict] = []
    for c in dt_components:
        vulns = client.fetch_vulnerabilities(c.get("uuid", ""))
        has_vulns = len(vulns) > 0
        cyclonedx_components.append(
            build_cyclonedx_component(c, has_vulns, name)
        )

    return cyclonedx_components

def main():
    parser = argparse.ArgumentParser(description="SBOM ingestion orchestrator")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the full pipeline but skip writing Assets/SBOM.json for now",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Only process specific targets by container_name (default: all)",
    )
    args = parser.parse_args()

    load_dotenv(ENV_PATH)
    api_key = os.getenv("DT_API_KEY")
    base_url = os.getenv("DT_BASE_URL", "http://192.168.4.38:1010")

    if not api_key:
        log.error("DT_API_KEY not set - check your .env file at %s", ENV_PATH)
        sys.exit(1)

    client = DependencyTrackClient(base_url, api_key) # run the entire dt class
    targets = load_targets(args.targets) # load the target sbom files

    log.info("Processing %d target(s): %s",
             len(targets), [t["container_name"] for t in targets])

    all_components = []
    # process each sbom file
    for target in targets:
        components = process_target(target, client)
        all_components.extend(components)

    # dedupe the combined vulnerable components
    all_components = dedupe_components(all_components)
    vuln_count = sum(
        1 for c in all_components
        if any(p["name"] == "has_vulnerabilities" for p in c.get("properties", []))
    )

    # final sbom
    sbom = build_final_sbom(all_components)

    # not replacing the sbom just yet
    if args.dry_run:
        log.info("Dry run - not writing %s", OUTPUT_PATH)
    else: # or replace the existing sbom in the ASSETS folder
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)
        log.info("Wrote %s", OUTPUT_PATH)

if __name__ == "__main__":
    main()
