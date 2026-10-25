#!/usr/bin/env python3
"""
SecureScope CLI — AI-Powered Code Security Scanner.

Entry point for the SecureScope tool. Parses CLI arguments,
orchestrates the scan pipeline, and outputs results.

Usage:
    python cli.py --path ./my-project
    python cli.py --path ./my-project --output html --report-file report.html
    python cli.py --path ./my-project --diff --output all
    python cli.py --path ./my-project --provider ollama --model llama3
"""

import argparse
import os
import sys
import time

# Ensure UTF-8 output on Windows consoles to prevent charmap encoding errors with emojis/unicode
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path so imports work when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from scanner.file_walker import walk_files
from scanner.pre_filter import pre_filter_files
from analyzer.ai_client import analyze_snippets
from analyzer.cve_search import enrich_findings_with_cve
from reporter.terminal import print_report, print_banner
from reporter.json_export import export_json
from reporter.html_report import generate_html_report
from reporter.voice_briefing import generate_voice_briefing


console = Console(legacy_windows=False)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="securescope",
        description="🔐 SecureScope — AI-Powered Code Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --path ./my-project
  python cli.py --path ./my-project --output html
  python cli.py --path ./my-project --diff --output all
  python cli.py --path ./my-project --provider ollama --model llama3
        """,
    )
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="Path to the directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["terminal", "html", "json", "all"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--report-file",
        type=str,
        default="securescope_report",
        help="Output filename without extension (default: securescope_report)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Only scan git-changed files",
    )
    parser.add_argument(
        "--provider",
        type=str,
        choices=["groq", "ollama"],
        default="groq",
        help="AI provider to use (default: groq)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="AI model name (defaults depend on provider)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed processing information",
    )
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Only run regex pre-filter (no AI analysis)",
    )
    parser.add_argument(
        "--enrich-cve",
        action="store_true",
        default=True,
        help="Enrich findings with live CVE and Security Advisory data via SerpApi (default: enabled)",
    )
    parser.add_argument(
        "--voice",
        action="store_true",
        help="Generate an executive audio briefing using ElevenLabs Text-to-Speech",
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    target_path = os.path.abspath(args.path)

    if not os.path.isdir(target_path):
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {target_path}")
        sys.exit(1)

    start_time = time.time()

    # ── Step 1: Print banner ──────────────────────────────────────────────
    print_banner()

    # ── Step 2: Walk files ────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("📂 Discovering files...", total=None)
        files = walk_files(target_path, diff_only=args.diff)
        progress.update(task, description=f"📂 Found {len(files)} scannable files")
        progress.stop()

    if not files:
        console.print("[yellow]No supported files found to scan.[/yellow]")
        sys.exit(0)

    if args.verbose:
        console.print(f"[dim]Languages: {', '.join(sorted(set(f['language'] for f in files)))}[/dim]")

    # ── Step 3: Pre-filter with regex ─────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("🔍 Pre-filtering files...", total=len(files))
        filter_results = pre_filter_files(files)
        progress.update(task, completed=len(files))

    total_snippets = sum(len(r.snippets) for r in filter_results)
    all_snippets = [s for r in filter_results for s in r.snippets]

    console.print(
        f"[cyan]📋 Pre-filter: {len(filter_results)} files flagged, "
        f"{total_snippets} suspicious snippets found[/cyan]"
    )

    if not all_snippets:
        console.print("[bold green]✅ No suspicious patterns found — code looks clean![/bold green]")
        scan_time = time.time() - start_time
        print_report(
            findings=[],
            total_files=len(files),
            files_with_hits=0,
            total_snippets=0,
            ai_calls=0,
            scan_time=scan_time,
            errors=[],
        )
        sys.exit(0)

    # ── Step 4: AI Analysis ───────────────────────────────────────────────
    if args.skip_ai:
        console.print("[yellow]⏭️  Skipping AI analysis (--skip-ai flag)[/yellow]")
        # Convert pre-filter results to intelligent findings with OWASP taxonomy and severities
        from analyzer.ai_client import Finding
        findings = []

        CATEGORY_METADATA = {
            "injection": {
                "severity": "CRITICAL",
                "owasp_id": "A03:2021",
                "owasp_name": "Injection",
                "title": "Injection Vulnerability (SQL/Command/Eval)",
                "fix": "Use parameterized queries (e.g. cursor.execute('SELECT * FROM t WHERE id = ?', (val,))) or avoid eval/shell=True.",
            },
            "hardcoded_secret": {
                "severity": "CRITICAL",
                "owasp_id": "A02:2021",
                "owasp_name": "Cryptographic Failures",
                "title": "Hardcoded Secret / Credential Leak",
                "fix": "Extract sensitive secrets and API keys into secure environment variables (os.environ or .env).",
            },
            "weak_crypto": {
                "severity": "HIGH",
                "owasp_id": "A02:2021",
                "owasp_name": "Cryptographic Failures",
                "title": "Weak or Deprecated Cryptographic Algorithm",
                "fix": "Replace MD5/SHA-1 with modern collision-resistant algorithms such as SHA-256, Argon2, or bcrypt.",
            },
            "deserialization": {
                "severity": "HIGH",
                "owasp_id": "A08:2021",
                "owasp_name": "Software and Data Integrity Failures",
                "title": "Insecure Deserialization",
                "fix": "Avoid deserializing untrusted data with pickle or yaml.load without yaml.SafeLoader.",
            },
            "auth_issues": {
                "severity": "HIGH",
                "owasp_id": "A07:2021",
                "owasp_name": "Identification & Authentication Failures",
                "title": "Insecure Authentication or Disabled TLS",
                "fix": "Enforce SSL/TLS validation (remove verify=False) and require cryptographically signed JWT algorithms.",
            },
            "ssrf": {
                "severity": "HIGH",
                "owasp_id": "A10:2021",
                "owasp_name": "Server-Side Request Forgery (SSRF)",
                "title": "Unvalidated URL Fetching (SSRF Risk)",
                "fix": "Validate destination URLs against a strict whitelist of approved domains and block internal private IP ranges.",
            },
            "debug_enabled": {
                "severity": "MEDIUM",
                "owasp_id": "A05:2021",
                "owasp_name": "Security Misconfiguration",
                "title": "Debug Mode Enabled in Production Code",
                "fix": "Disable debug flags (DEBUG = False) and suppress verbose stack traces in production environments.",
            },
        }

        for snippet in all_snippets:
            meta = CATEGORY_METADATA.get(snippet.category, {
                "severity": "MEDIUM",
                "owasp_id": "A04:2021",
                "owasp_name": "Insecure Design",
                "title": f"Suspicious Pattern: {snippet.category}",
                "fix": "Review code logic manually for security implications.",
            })
            findings.append(Finding(
                vulnerability=meta["title"],
                severity=meta["severity"],
                description=f"Pre-filter rule detected dangerous pattern '{snippet.category}' in {snippet.language}: {snippet.line_content[:120]}",
                fix_suggestion=meta["fix"],
                owasp_id=meta["owasp_id"],
                owasp_name=meta["owasp_name"],
                line_number=snippet.line_number,
                confidence="HIGH" if meta["severity"] == "CRITICAL" else "MEDIUM",
                file_path=snippet.file_path,
                relative_path=snippet.relative_path,
                language=snippet.language,
                category=snippet.category,
            ))
        ai_calls = 0
        ai_errors = []
    else:
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("🤖 AI analyzing snippets...", total=None)

            def on_progress(msg: str):
                progress.update(task, description=f"🤖 {msg}")

            analysis = analyze_snippets(
                snippets=all_snippets,
                provider=args.provider,
                model=args.model,
                on_progress=on_progress,
            )
            progress.update(task, description=f"🤖 AI analysis complete — {len(analysis.findings)} findings")

        findings = analysis.findings
        ai_calls = analysis.ai_calls_made
        ai_errors = analysis.errors

    # ── Step 5: Filter by minimum severity & enrich with CVE data ───────────
    from config import SEVERITY_ORDER
    min_sev = args.severity.upper()
    min_sev_value = SEVERITY_ORDER.get(min_sev, 0)
    findings = [
        f for f in findings
        if SEVERITY_ORDER.get(f.severity, 0) >= min_sev_value
    ]

    # Enrich findings with live CVE and Security Advisory data via SerpApi
    if args.enrich_cve and findings:
        enrich_findings_with_cve(findings)

    scan_time = time.time() - start_time

    # ── Step 6: Output results ────────────────────────────────────────────
    # Google Gemma 2 is our flagship open-weight AI model
    model_name = args.model or ("gemma2-9b-it" if args.provider == "groq" else "gemma2")

    if args.output in ("terminal", "all"):
        print_report(
            findings=findings,
            total_files=len(files),
            files_with_hits=len(filter_results),
            total_snippets=total_snippets,
            ai_calls=ai_calls,
            scan_time=scan_time,
            errors=ai_errors,
        )

    if args.output in ("json", "all"):
        json_file = args.report_file + ".json"
        export_json(
            findings=findings,
            total_files=len(files),
            files_with_hits=len(filter_results),
            total_snippets=total_snippets,
            ai_calls=ai_calls,
            scan_time=scan_time,
            errors=ai_errors,
            output_file=json_file,
            target_path=target_path,
            provider=args.provider,
            model=model_name,
        )
        console.print(f"[green]📄 JSON report saved: {json_file}[/green]")

    if args.output in ("html", "all"):
        html_file = args.report_file + ".html"
        generate_html_report(
            findings=findings,
            total_files=len(files),
            files_with_hits=len(filter_results),
            total_snippets=total_snippets,
            ai_calls=ai_calls,
            scan_time=scan_time,
            errors=ai_errors,
            output_file=html_file,
            target_path=target_path,
            provider=args.provider,
            model=model_name,
        )
        console.print(f"[green]📊 HTML report saved: {html_file}[/green]")

    # ── Step 7: Executive Audio Briefing (ElevenLabs) ──────────────────────
    if args.voice:
        audio_file, transcript = generate_voice_briefing(
            findings=findings,
            total_files=len(files),
            scan_time=scan_time,
            output_audio_path=args.report_file + "_briefing.mp3",
        )
        if audio_file:
            console.print(f"[bold green]🎙️ ElevenLabs Audio Briefing saved: {audio_file}[/bold green]")
        else:
            console.print(
                f"[yellow]🎙️ Voice briefing transcript generated: {args.report_file}_briefing_transcript.txt\n"
                f"   (Set ELEVENLABS_API_KEY to synthesize MP3 audio)[/yellow]"
            )


if __name__ == "__main__":
    main()
