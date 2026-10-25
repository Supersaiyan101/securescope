"""
JSON Export — Structured machine-readable output.

Exports all findings and scan metadata as a JSON file
for CI/CD integration, dashboards, or downstream tools.
"""

import json
from datetime import datetime, timezone


def export_json(
    findings: list,
    total_files: int,
    files_with_hits: int,
    total_snippets: int,
    ai_calls: int,
    scan_time: float,
    errors: list[str],
    output_file: str,
    target_path: str = "",
    provider: str = "",
    model: str = "",
):
    """
    Export scan results to a JSON file.

    Args:
        findings: List of Finding objects.
        total_files: Total files scanned.
        files_with_hits: Files with pre-filter hits.
        total_snippets: Total suspicious snippets found.
        ai_calls: Number of AI API calls made.
        scan_time: Total scan time in seconds.
        errors: List of error strings.
        output_file: Path to write the JSON file.
        target_path: Original target directory scanned.
        provider: AI provider used (groq/ollama).
        model: AI model name used.
    """
    # Build severity counts
    severity_counts = {}
    owasp_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        owasp_key = f.owasp_id
        owasp_counts[owasp_key] = owasp_counts.get(owasp_key, 0) + 1

    report = {
        "tool": "SecureScope",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_path,
        "ai": {
            "provider": provider,
            "model": model,
        },
        "summary": {
            "total_files_scanned": total_files,
            "files_with_issues": files_with_hits,
            "pre_filter_snippets": total_snippets,
            "ai_confirmed_findings": len(findings),
            "ai_api_calls": ai_calls,
            "scan_time_seconds": round(scan_time, 2),
            "severity_breakdown": severity_counts,
            "owasp_breakdown": owasp_counts,
        },
        "findings": [
            {
                "id": i + 1,
                "vulnerability": f.vulnerability,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "fix_suggestion": f.fix_suggestion,
                "owasp_id": f.owasp_id,
                "owasp_name": f.owasp_name,
                "file": f.relative_path,
                "line_number": f.line_number,
                "language": f.language,
            }
            for i, f in enumerate(findings)
        ],
        "errors": errors,
    }

    with open(output_file, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)

    return output_file
