"""
Software Supply-Chain & Dependency Auditor (SCA).

Parses package manifests (requirements.txt, package.json) and queries
the open-source Google OSV (Open Source Vulnerabilities) database
to identify known CVEs and security advisories in third-party dependencies.
"""

import json
import os
import re
import urllib.request
import urllib.error
from typing import Optional

from analyzer.ai_client import Finding


SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def parse_requirements_txt(file_path: str) -> list[dict]:
    """Parse a Python requirements.txt file for package names, versions, and line numbers."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                raw_line = line.strip()
                if not raw_line or raw_line.startswith("#") or raw_line.startswith("-"):
                    continue
                match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9A-Za-z\.\-]+)", raw_line)
                if match:
                    packages.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "PyPI",
                        "file": file_path,
                        "line_number": idx,
                    })
    except Exception:
        pass
    return packages


def parse_package_json(file_path: str) -> list[dict]:
    """Parse a Node.js package.json file for dependencies and line numbers."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        content = "".join(lines)
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        for name, ver in all_deps.items():
            clean_ver = ver.lstrip("^~>=< ")
            if clean_ver:
                line_no = 1
                for idx, line in enumerate(lines, 1):
                    if f'"{name}"' in line:
                        line_no = idx
                        break
                packages.append({
                    "name": name,
                    "version": clean_ver,
                    "ecosystem": "npm",
                    "file": file_path,
                    "line_number": line_no,
                })
    except Exception:
        pass
    return packages


def query_osv_database(package_name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Query the Google Open Source Vulnerabilities (OSV) API.

    API endpoint: https://api.osv.dev/v1/query
    Free, public, open-source database of published CVEs and security advisories.
    """
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SecureScope-SCA/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("vulns", [])
    except Exception:
        return []


def extract_fixed_version(vuln_data: dict) -> Optional[str]:
    """Extract recommended fixed version from OSV ranges."""
    for affected in vuln_data.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def audit_dependencies(target_path: str, max_per_package: int = 3) -> list[Finding]:
    """
    Scan the target directory for package manifests and query OSV for vulnerabilities.

    Args:
        target_path: Absolute or relative directory path to inspect.
        max_per_package: Maximum number of CVE findings to report per vulnerable package.

    Returns:
        List of Finding objects for discovered supply-chain vulnerabilities.
    """
    findings = []
    manifests_found = []

    # Look for package manifests in target directory
    for root, _, files in os.walk(target_path):
        if "node_modules" in root or ".venv" in root or "venv" in root or ".git" in root:
            continue
        for file in files:
            if file == "requirements.txt":
                manifests_found.append((os.path.join(root, file), "requirements.txt"))
            elif file == "package.json":
                manifests_found.append((os.path.join(root, file), "package.json"))

    for manifest_path, manifest_type in manifests_found:
        if manifest_type == "requirements.txt":
            packages = parse_requirements_txt(manifest_path)
        else:
            packages = parse_package_json(manifest_path)

        rel_path = os.path.relpath(manifest_path, target_path)

        for pkg in packages:
            vulns = query_osv_database(pkg["name"], pkg["version"], pkg["ecosystem"])
            if not vulns:
                continue

            # Process and calculate severity for each vuln
            processed_vulns = []
            for v in vulns:
                vuln_id = v.get("id", "UNKNOWN-CVE")
                summary = v.get("summary") or v.get("details", "")[:120]
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

                severity = "HIGH"
                database_specific = v.get("database_specific", {})
                if database_specific.get("severity") in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
                    sev_str = database_specific["severity"]
                    severity = "MEDIUM" if sev_str == "MODERATE" else sev_str

                fixed_ver = extract_fixed_version(v)
                cve_url = f"https://osv.dev/vulnerability/{vuln_id}"

                processed_vulns.append({
                    "id": vuln_id,
                    "cve_id": cve_id,
                    "summary": summary,
                    "severity": severity,
                    "weight": SEVERITY_WEIGHT.get(severity, 2),
                    "fixed_ver": fixed_ver,
                    "url": cve_url,
                })

            # Sort by severity weight descending
            processed_vulns.sort(key=lambda x: x["weight"], reverse=True)

            for pv in processed_vulns[:max_per_package]:
                fix_msg = (
                    f"Upgrade '{pkg['name']}' to >= {pv['fixed_ver']} (patched in {pv['fixed_ver']}). "
                    f"Advisory: {pv['url']}"
                    if pv["fixed_ver"]
                    else f"Upgrade '{pkg['name']}' to latest secure release. Advisory: {pv['url']}"
                )

                finding = Finding(
                    vulnerability=f"Vulnerable Dependency: {pkg['name']}=={pkg['version']} ({pv['cve_id']})",
                    severity=pv["severity"],
                    description=f"Package '{pkg['name']}' version {pkg['version']} has known vulnerability {pv['cve_id']}: {pv['summary']}",
                    fix_suggestion=fix_msg,
                    owasp_id="A06:2021",
                    owasp_name="Vulnerable and Outdated Components",
                    line_number=pkg.get("line_number", 1),
                    confidence="HIGH",
                    file_path=manifest_path,
                    relative_path=rel_path,
                    language=pkg["ecosystem"],
                    category="vulnerable_dependency",
                    cve_references=[
                        {
                            "id": pv["cve_id"],
                            "title": pv["summary"],
                            "url": pv["url"],
                            "source": "Google OSV Database",
                        }
                    ],
                )
                findings.append(finding)

    return findings
