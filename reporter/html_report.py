"""
HTML Report Generator — Beautiful standalone HTML report.

Generates a self-contained HTML file with embedded CSS and JS.
No external dependencies needed to view the report.
Uses Jinja2 for templating.
"""

import os
from datetime import datetime, timezone

from jinja2 import Template


def generate_html_report(
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
    Generate a standalone HTML security report.

    Args:
        findings: List of Finding objects.
        total_files: Total files scanned.
        files_with_hits: Files with pre-filter hits.
        total_snippets: Total suspicious snippets found.
        ai_calls: Number of AI API calls made.
        scan_time: Total scan time in seconds.
        errors: List of error strings.
        output_file: Path to write the HTML file.
        target_path: Original target directory scanned.
        provider: AI provider used.
        model: AI model name used.
    """
    # Build severity counts
    severity_counts = {}
    owasp_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        key = f"{f.owasp_id} {f.owasp_name}"
        owasp_counts[key] = owasp_counts.get(key, 0) + 1

    template_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "templates",
        "report.html",
    )

    with open(template_path, "r", encoding="utf-8") as f:
        template_str = f.read()

    template = Template(template_str)

    # Privacy-friendly clean display for target path (hide full system paths)
    display_target = os.path.basename(target_path.rstrip("/\\")) or target_path

    html = template.render(
        tool_name="SecureScope",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        target_path=display_target,
        provider=provider,
        model=model,
        total_files=total_files,
        files_with_hits=files_with_hits,
        total_snippets=total_snippets,
        total_findings=len(findings),
        ai_calls=ai_calls,
        scan_time=f"{scan_time:.1f}",
        severity_counts=severity_counts,
        owasp_counts=owasp_counts,
        findings=findings,
        errors=errors,
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    return output_file
