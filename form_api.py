"""
Organisation Profile & SBOM submission API.

Serves the profile form and the SBOM upload page, and exposes endpoints
for submitting both to the engine at runtime.

Usage:
    uvicorn form_api:app --reload
"""

from __future__ import annotations

import json
import pathlib
from typing import List

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from pipeline.sbom_merge import (
    load_existing_components,
    extract_components_from_upload,
    extract_vulnerabilities_from_upload,
    merge_components,
    dedupe_vulnerabilities,
    build_merged_sbom,
    get_component_criticality,
)

PROFILE_PATH = pathlib.Path("Assets/Test-bed Profile.json")
SBOM_PATH    = pathlib.Path("Assets/SBOM.json")

app = FastAPI(title="CTI Curation — Profile & SBOM API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Profile endpoints (existing) ──────────────────────────────────────────

@app.get("/")
async def serve_form() -> FileResponse:
    return FileResponse("profile_form.html")


@app.post("/submit-profile")
async def submit_profile(request: Request) -> dict:
    payload = await request.json()
    PROFILE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"status": "ok", "message": "Profile updated"}


# ── SBOM endpoints ────────────────────────────────────────────────────────

@app.get("/sbom")
async def serve_sbom_page() -> FileResponse:
    """Serve the SBOM upload page."""
    return FileResponse("sbom_upload.html")


@app.get("/api/sbom/current")
async def get_current_sbom() -> dict:
    """Return a summary of the currently loaded SBOM."""
    if not SBOM_PATH.exists():
        return {"status": "empty", "components": 0, "vulnerabilities": 0}

    try:
        data = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
        components = data.get("components", [])
        vulns = data.get("vulnerabilities", [])

        criticality_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
        cpe_count = 0
        for comp in components:
            crit = get_component_criticality(comp)
            criticality_counts[crit] = criticality_counts.get(crit, 0) + 1
            if comp.get("cpe"):
                cpe_count += 1

        sources = set()
        for comp in components:
            for prop in comp.get("properties", []):
                if prop.get("name") == "source_file":
                    sources.add(prop["value"])

        return {
            "status": "loaded",
            "total_components": len(components),
            "with_cpe": cpe_count,
            "without_cpe": len(components) - cpe_count,
            "criticality": criticality_counts,
            "vulnerabilities": len(vulns),
            "source_files": sorted(sources),
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def _validate_sbom(data: dict) -> list[dict]:
    """Validate a CycloneDX SBOM and return a list of issues."""
    issues = []

    bom_format = data.get("bomFormat", "")
    if bom_format != "CycloneDX":
        issues.append({
            "severity": "error",
            "message": f"bomFormat is '{bom_format}' — expected 'CycloneDX'"
        })

    components = data.get("components", [])
    if not components:
        issues.append({
            "severity": "error",
            "message": "No components found — SBOM is empty"
        })
        return issues

    total = len(components)
    missing_name = sum(1 for c in components if not c.get("name"))
    missing_cpe = sum(1 for c in components if not c.get("cpe"))
    missing_criticality = sum(
        1 for c in components
        if "criticality" not in {p["name"]: p["value"] for p in c.get("properties", [])}
    )

    if missing_name:
        issues.append({
            "severity": "error",
            "message": f"{missing_name}/{total} components missing 'name'"
        })
    if missing_cpe:
        issues.append({
            "severity": "warning",
            "message": f"{missing_cpe}/{total} components missing 'cpe' — CVE matching will not work for these"
        })
    if missing_criticality:
        issues.append({
            "severity": "info",
            "message": f"{missing_criticality}/{total} components missing 'criticality' — engine will assign based on component type"
        })

    return issues


@app.post("/api/sbom/upload")
async def upload_sbom(files: List[UploadFile] = File(...)) -> JSONResponse:
    """
    Accept one or more CycloneDX JSON SBOM files.
    Merges them with the existing SBOM (if any), deduplicates,
    ensures criticality, and saves the combined result.
    """
    all_new_components: list[dict] = []
    all_new_vulns: list[dict] = []
    all_issues: list[dict] = []
    file_names: list[str] = []
    rejected_files: list[str] = []

    for uploaded_file in files:
        fname = uploaded_file.filename or "unknown.json"

        try:
            content = await uploaded_file.read()
            data = json.loads(content)
        except json.JSONDecodeError as e:
            all_issues.append({"severity": "error", "message": f"{fname}: invalid JSON — {e}"})
            rejected_files.append(fname)
            continue
        except Exception as e:
            all_issues.append({"severity": "error", "message": f"{fname}: failed to read — {e}"})
            rejected_files.append(fname)
            continue

        file_issues = _validate_sbom(data)
        has_errors = any(i["severity"] == "error" for i in file_issues)

        for issue in file_issues:
            issue["message"] = f"{fname}: {issue['message']}"
        all_issues.extend(file_issues)

        if has_errors:
            rejected_files.append(fname)
            continue

        components = extract_components_from_upload(data)
        for comp in components:
            props = comp.get("properties", [])
            if not any(p.get("name") == "source_file" for p in props):
                props.append({"name": "source_file", "value": fname})
                comp["properties"] = props

        all_new_components.extend(components)
        all_new_vulns.extend(extract_vulnerabilities_from_upload(data))
        file_names.append(fname)

    if not file_names:
        return JSONResponse(
            status_code=422,
            content={
                "status": "rejected",
                "message": "All uploaded files had blocking issues — nothing saved",
                "rejected_files": rejected_files,
                "issues": all_issues,
            }
        )

    existing_components = load_existing_components(SBOM_PATH)
    existing_vulns = []
    if SBOM_PATH.exists():
        try:
            existing_data = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
            existing_vulns = existing_data.get("vulnerabilities", [])
        except (json.JSONDecodeError, KeyError):
            pass

    merged_components = merge_components(existing_components, all_new_components)
    merged_vulns = dedupe_vulnerabilities(existing_vulns + all_new_vulns)

    sbom = build_merged_sbom(
        components=merged_components,
        description=f"Merged SBOM from {len(file_names)} uploaded file(s). "
                    f"Total components after deduplication: {len(merged_components)}.",
    )

    if merged_vulns:
        sbom["vulnerabilities"] = merged_vulns

    SBOM_PATH.parent.mkdir(parents=True, exist_ok=True)
    SBOM_PATH.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    cpe_count = sum(1 for c in merged_components if c.get("cpe"))

    return JSONResponse(
        status_code=200,
        content={
            "status": "accepted",
            "message": (
                f"Merged {len(all_new_components)} new components from {len(file_names)} file(s) "
                f"with {len(existing_components)} existing. "
                f"After deduplication: {len(merged_components)} total, {cpe_count} with CPE."
            ),
            "accepted_files": file_names,
            "rejected_files": rejected_files,
            "total_components": len(merged_components),
            "with_cpe": cpe_count,
            "issues": all_issues,
        }
    )


@app.post("/api/sbom/clear")
async def clear_sbom() -> dict:
    """Clear the current SBOM — resets to empty for a fresh start."""
    empty = build_merged_sbom(components=[], description="Empty SBOM — awaiting upload.")
    SBOM_PATH.parent.mkdir(parents=True, exist_ok=True)
    SBOM_PATH.write_text(json.dumps(empty, indent=2), encoding="utf-8")
    return {"status": "ok", "message": "SBOM cleared — ready for new uploads"}
