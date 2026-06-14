"""
SBOM Validator — checks that a CycloneDX SBOM has the fields the curation engine needs.

Usage:
    python validate_sbom.py Assets/SBOM.json
    python validate_sbom.py /path/to/my_org_sbom.json
"""

import json
import sys


def validate(path: str) -> list[str]:
    """Return a list of issues. Empty list = valid."""
    issues = []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [f"File not found: {path}"]
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    if data.get("bomFormat") != "CycloneDX":
        issues.append("Missing or incorrect bomFormat (expected 'CycloneDX')")

    components = data.get("components", [])
    if not components:
        issues.append("No components found — SBOM is empty")
        return issues

    total = len(components)
    missing_name = sum(1 for c in components if not c.get("name"))
    missing_cpe = sum(1 for c in components if not c.get("cpe"))
    missing_criticality = sum(
        1 for c in components
        if "criticality" not in {p["name"]: p["value"] for p in c.get("properties", [])}
    )

    if missing_name:
        issues.append(f"{missing_name}/{total} components missing 'name'")
    if missing_cpe:
        issues.append(f"{missing_cpe}/{total} components missing 'cpe' — CVE cross-referencing will not work for these")
    if missing_criticality:
        issues.append(f"{missing_criticality}/{total} components missing 'criticality' — engine will assign based on component type")

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        issues.append("No 'vulnerabilities' section — CVE-to-SBOM matching will have nothing to cross-reference")

    return issues


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_sbom.py <path_to_sbom.json>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Validating: {path}")

    issues = validate(path)

    if not issues:
        print("\nPASSED — SBOM is compatible with the curation engine.")
        sys.exit(0)

    print(f"\n{len(issues)} issue(s) found:\n")
    for issue in issues:
        print(f"  - {issue}")
    print("\nThe engine will still run but scoring accuracy may be reduced.")
    sys.exit(1)


if __name__ == "__main__":
    main()
