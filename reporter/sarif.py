"""
SARIF 2.1.0 Reporter for SecureScope.

Exports findings in the official OASIS Static Analysis Results
Interchange Format (SARIF) v2.1.0. Allows native ingestion by
GitHub Code Scanning, GitLab Security, and IDE extensions.
"""

import json
from datetime import datetime, timezone
from typing import Optional


def _map_severity_to_sarif_level(severity: str) -> str:
    """Map SecureScope severity to SARIF level (error, warning, note, none)."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "warning")


def export_sarif(
    findings: list,
    output_file: str,
    target_path: str = "",
    tool_version: str = "1.0.0",
) -> str:
    """
    Generate an OASIS SARIF 2.1.0 JSON report.

    Args:
        findings: List of Finding objects.
        output_file: Path to write the .sarif file.
        target_path: Root scan path.
        tool_version: Version of SecureScope.

    Returns:
        The output file path.
    """
    # Collect unique rules across findings
    rules_dict = {}
    sarif_results = []

    for i, f in enumerate(findings):
        # Construct rule ID from OWASP ID or category
        rule_id = f.owasp_id if f.owasp_id and f.owasp_id != "N/A" else f"SEC-{f.category.upper()}"
        rule_id = rule_id.replace(":", "-").replace(" ", "-")

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.vulnerability or "SecurityFinding",
                "shortDescription": {
                    "text": f.vulnerability or "Security vulnerability detected by SecureScope",
                },
                "fullDescription": {
                    "text": f.description or "Potential security issue flagged during analysis.",
                },
                "help": {
                    "text": f"Remediation: {f.fix_suggestion}",
                    "markdown": f"### Remediation\n\n{f.fix_suggestion}\n\n**OWASP:** {f.owasp_id} — {f.owasp_name}",
                },
                "properties": {
                    "category": f.category,
                    "owasp": f.owasp_id,
                    "precision": "high" if getattr(f, "confidence", "") == "HIGH" else "medium",
                },
            }

        sarif_level = _map_severity_to_sarif_level(f.severity)

        # Build location
        line_num = f.line_number if f.line_number and f.line_number > 0 else 1
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.relative_path.replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": line_num,
                    "startColumn": 1,
                },
            }
        }

        result_item = {
            "ruleId": rule_id,
            "ruleIndex": list(rules_dict.keys()).index(rule_id),
            "level": sarif_level,
            "message": {
                "text": f"{f.vulnerability}: {f.description} (Suggested Fix: {f.fix_suggestion})",
            },
            "locations": [location],
            "properties": {
                "severity": f.severity,
                "confidence": getattr(f, "confidence", "MEDIUM"),
                "cve_references": getattr(f, "cve_references", []),
            },
        }
        sarif_results.append(result_item)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureScope",
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/SuperSaiyan101/securescope",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }

    with open(output_file, "w", encoding="utf-8") as fp:
        json.dump(sarif_doc, fp, indent=2, ensure_ascii=False)

    return output_file
