"""
Terminal Reporter — Rich colored terminal output.

Displays findings as beautiful tables with severity-based colors,
summary stats, and OWASP category breakdowns using the Rich library.
"""

import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from config import SEVERITY_COLORS, SEVERITY_ORDER

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(legacy_windows=False)


def _severity_style(severity: str) -> str:
    """Get the Rich style for a severity level."""
    return SEVERITY_COLORS.get(severity, "white")


def _severity_icon(severity: str) -> str:
    """Get an icon for a severity level."""
    icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }
    return icons.get(severity, "⚪")


def print_banner():
    """Print the SecureScope banner."""
    banner = Text()
    banner.append("🔐 SecureScope", style="bold cyan")
    banner.append(" — AI-Powered Code Security Scanner\n", style="dim")
    banner.append("   Powered by open-weight AI models", style="dim italic")
    console.print(Panel(banner, box=box.DOUBLE_EDGE, border_style="cyan"))
    console.print()


def print_scan_summary(
    total_files: int,
    files_with_hits: int,
    total_snippets: int,
    total_findings: int,
    ai_calls: int,
    scan_time: float,
):
    """Print the scan summary stats."""
    table = Table(
        title="📊 Scan Summary",
        box=box.ROUNDED,
        border_style="blue",
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Files scanned", str(total_files))
    table.add_row("Files with potential issues", str(files_with_hits))
    table.add_row("Suspicious snippets found", str(total_snippets))
    table.add_row("AI-confirmed findings", str(total_findings))
    table.add_row("AI API calls made", str(ai_calls))
    table.add_row("Scan time", f"{scan_time:.1f}s")

    console.print(table)
    console.print()


def print_severity_breakdown(findings: list):
    """Print a breakdown of findings by severity."""
    counts = {}
    for f in findings:
        sev = f.severity
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(
        title="⚠️  Severity Breakdown",
        box=box.ROUNDED,
        border_style="yellow",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Bar", min_width=20)

    max_count = max(counts.values()) if counts else 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        bar_len = int((count / max_count) * 20)
        bar = "█" * bar_len
        style = _severity_style(sev)
        icon = _severity_icon(sev)
        table.add_row(
            Text(f"{icon} {sev}", style=style),
            Text(str(count), style=style),
            Text(bar, style=style),
        )

    console.print(table)
    console.print()


def print_owasp_breakdown(findings: list):
    """Print a breakdown of findings by OWASP category."""
    owasp_counts: dict[str, int] = {}
    for f in findings:
        key = f"{f.owasp_id} {f.owasp_name}"
        owasp_counts[key] = owasp_counts.get(key, 0) + 1

    if not owasp_counts:
        return

    table = Table(
        title="🗺️  OWASP Top 10 Coverage",
        box=box.ROUNDED,
        border_style="magenta",
    )
    table.add_column("OWASP Category", style="bold magenta")
    table.add_column("Findings", justify="center")

    for cat, count in sorted(owasp_counts.items()):
        table.add_row(cat, str(count))

    console.print(table)
    console.print()


def print_findings(findings: list):
    """Print all findings as detailed panels."""
    if not findings:
        console.print(
            Panel(
                "[bold green]✅ No security vulnerabilities detected![/bold green]\n\n"
                "Your code passed both regex pre-filtering and AI analysis.",
                title="All Clear",
                border_style="green",
                box=box.DOUBLE_EDGE,
            )
        )
        return

    for i, finding in enumerate(findings, 1):
        sev = finding.severity
        style = _severity_style(sev)
        icon = _severity_icon(sev)

        content = Text()
        content.append(f"Severity: ", style="bold")
        content.append(f"{icon} {sev}\n", style=style)

        content.append(f"OWASP: ", style="bold")
        content.append(f"{finding.owasp_id} — {finding.owasp_name}\n", style="magenta")

        content.append(f"Confidence: ", style="bold")
        content.append(f"{finding.confidence}\n", style="dim")

        content.append(f"File: ", style="bold")
        content.append(f"{finding.relative_path}", style="underline")
        if finding.line_number:
            content.append(f" (line {finding.line_number})")
        content.append("\n")

        content.append(f"\nDescription: ", style="bold")
        content.append(f"{finding.description}\n")

        content.append(f"\n💡 Fix: ", style="bold green")
        content.append(f"{finding.fix_suggestion}\n", style="green")

        console.print(
            Panel(
                content,
                title=f"[{style}]#{i} — {finding.vulnerability}[/{style}]",
                border_style=style.replace("bold ", ""),
                box=box.ROUNDED,
            )
        )
        console.print()


def print_errors(errors: list[str]):
    """Print any errors that occurred during scanning."""
    if not errors:
        return

    for error in errors:
        console.print(f"[bold red]❌ Error:[/bold red] {error}")
    console.print()


def print_report(
    findings: list,
    total_files: int,
    files_with_hits: int,
    total_snippets: int,
    ai_calls: int,
    scan_time: float,
    errors: list[str],
):
    """Print the complete terminal report."""
    print_banner()
    print_scan_summary(
        total_files, files_with_hits, total_snippets,
        len(findings), ai_calls, scan_time,
    )
    print_severity_breakdown(findings)
    print_owasp_breakdown(findings)
    print_findings(findings)
    print_errors(errors)

    # Final verdict
    if not findings:
        verdict_style = "green"
        verdict_text = "🎉 PASSED — No vulnerabilities detected"
    else:
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        if critical_count > 0:
            verdict_style = "red"
            verdict_text = f"🚨 FAILED — {critical_count} CRITICAL issue(s) found"
        elif high_count > 0:
            verdict_style = "yellow"
            verdict_text = f"⚠️  WARNING — {high_count} HIGH severity issue(s) found"
        else:
            verdict_style = "cyan"
            verdict_text = f"ℹ️  REVIEW — {len(findings)} issue(s) to review"

    console.print(
        Panel(
            f"[bold {verdict_style}]{verdict_text}[/bold {verdict_style}]",
            box=box.DOUBLE_EDGE,
            border_style=verdict_style,
        )
    )
