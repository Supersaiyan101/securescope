"""
SecureScope Real-Time Web Server & Local Dashboard.

Provides a lightweight, zero-dependency HTTP server that lets developers
visually trigger code scans, inspect vulnerability cards, filter by severity,
download unified Git patches, and apply automated remediations.
"""

import http.server
import json
import os
import sys
import threading
import time
import urllib.parse
from typing import Any, Optional

from config import SEVERITY_ORDER
from scanner.file_walker import walk_files
from scanner.pre_filter import pre_filter_files
from scanner.dependency_auditor import audit_dependencies
from analyzer.ai_client import Finding, analyze_snippets
from analyzer.cve_search import enrich_findings_with_cve
from remediator.patcher import generate_unified_patch, apply_patch_directly


# Thread-safe in-memory store for the active scan state
SCAN_STATE = {
    "is_scanning": False,
    "target_path": "",
    "findings": [],
    "finding_objects": [],
    "stats": {
        "total_files": 0,
        "files_with_hits": 0,
        "total_snippets": 0,
        "total_findings": 0,
        "scan_time": 0.0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    },
    "last_scan_timestamp": None,
}
STATE_LOCK = threading.Lock()


def execute_scan(
    target_path: str,
    skip_ai: bool = True,
    no_sca: bool = False,
    provider: str = "groq",
    model: Optional[str] = None,
) -> dict:
    """Execute the full SecureScope scan pipeline programmatically."""
    abs_path = os.path.abspath(target_path)
    if not os.path.isdir(abs_path):
        return {"error": f"Directory not found: {target_path}"}

    start_time = time.time()
    files = walk_files(abs_path)
    filter_results = pre_filter_files(files)
    total_snippets = sum(len(r.snippets) for r in filter_results)
    all_snippets = [s for r in filter_results for s in r.snippets]

    findings: list[Finding] = []

    # AI Analysis or Regex Fallback
    if all_snippets:
        if skip_ai:
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
                    "fix": "Replace legacy hash functions with modern collision-resistant algorithms such as SHA-256, Argon2, or bcrypt.",
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
                    "fix": "Enforce SSL/TLS certificate validation (avoid disabling verification) and require cryptographically signed JWT algorithms.",
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
        else:
            analysis = analyze_snippets(all_snippets, provider=provider, model=model)
            findings.extend(analysis.findings)

    # Software Composition Analysis (SCA)
    if not no_sca:
        sca_findings = audit_dependencies(abs_path)
        findings.extend(sca_findings)

    # Enrich findings with live CVE intelligence
    if findings:
        enrich_findings_with_cve(findings)

    scan_time = time.time() - start_time

    # Calculate severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.severity.upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Convert finding dataclasses to serializable dictionaries
    serialized_findings = []
    for idx, f in enumerate(findings, 1):
        # Mask target path for privacy
        rel = f.relative_path or os.path.basename(f.file_path)
        serialized_findings.append({
            "id": idx,
            "vulnerability": f.vulnerability,
            "severity": f.severity,
            "description": f.description,
            "fix_suggestion": f.fix_suggestion,
            "owasp_id": f.owasp_id,
            "owasp_name": f.owasp_name,
            "line_number": f.line_number,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "relative_path": rel,
            "language": f.language,
            "category": f.category,
            "cve_references": f.cve_references or [],
        })

    with STATE_LOCK:
        SCAN_STATE["target_path"] = abs_path
        SCAN_STATE["finding_objects"] = findings
        SCAN_STATE["findings"] = serialized_findings
        SCAN_STATE["stats"] = {
            "total_files": len(files),
            "files_with_hits": len(filter_results),
            "total_snippets": total_snippets,
            "total_findings": len(findings),
            "scan_time": round(scan_time, 2),
            "severity_counts": sev_counts,
        }
        SCAN_STATE["last_scan_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

    return {
        "status": "success",
        "stats": SCAN_STATE["stats"],
        "findings": serialized_findings,
        "target_path": os.path.basename(abs_path),
    }


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScope — Live Security Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #162032;
            --border: #1f293d;
            --border-hover: #334155;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --success: #10b981;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }

        /* Top Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .brand h1 {
            font-size: 1.6rem;
            font-weight: 700;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .badge-live {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
            font-size: 0.75rem;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
        }
        .badge-live::before {
            content: "";
            width: 6px;
            height: 6px;
            background: var(--success);
            border-radius: 50%;
            display: inline-block;
        }

        /* Control Panel */
        .control-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .control-row {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        .path-input {
            flex: 1;
            min-width: 280px;
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }
        .path-input:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }
        .btn-scan {
            background: linear-gradient(135deg, #0ea5e9, #6366f1);
            color: white;
            font-weight: 600;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        .btn-scan:hover {
            opacity: 0.95;
            transform: translateY(-1px);
        }
        .btn-action {
            background: var(--surface-card);
            color: var(--text-main);
            border: 1px solid var(--border);
            padding: 0.65rem 1.1rem;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            font-size: 0.85rem;
        }
        .btn-action:hover {
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            text-align: center;
        }
        .stat-card .val {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        .stat-card .lbl {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Filters & Search */
        .filters-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .filter-tabs {
            display: flex;
            gap: 0.5rem;
            background: var(--surface);
            padding: 0.3rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        .tab-btn.active {
            background: var(--surface-card);
            color: var(--text-main);
        }
        .search-box {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            width: 240px;
        }

        /* Finding Card */
        .finding-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            transition: border-color 0.2s;
        }
        .finding-card:hover {
            border-color: var(--border-hover);
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.75rem;
        }
        .finding-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-main);
        }
        .tag-pill {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
        }
        .pill-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .pill-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .pill-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .pill-LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }

        .meta-line {
            display: flex;
            gap: 1rem;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
        }
        .desc-box {
            font-size: 0.9rem;
            color: var(--text-main);
            margin-bottom: 1rem;
            background: rgba(0,0,0,0.2);
            padding: 0.75rem;
            border-radius: 6px;
        }
        .fix-box {
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid var(--success);
            padding: 0.75rem;
            border-radius: 0 6px 6px 0;
            font-size: 0.88rem;
            margin-bottom: 0.75rem;
        }
        .cve-chips {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }
        .cve-chip {
            background: #1e293b;
            color: #38bdf8;
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-decoration: none;
            border: 1px solid #334155;
            font-family: 'JetBrains Mono', monospace;
        }
        .cve-chip:hover {
            border-color: #38bdf8;
        }
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #10b981;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 600;
            display: none;
            box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            z-index: 1000;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="brand">
                <h1>🔐 SecureScope Dashboard</h1>
                <span class="badge-live">Live Server</span>
            </div>
            <div style="display: flex; gap: 0.5rem;">
                <a href="/api/patch" class="btn-action">📥 Download Git Patch</a>
                <button onclick="applyAllFixes()" class="btn-action">⚡ Auto-Fix Files</button>
            </div>
        </header>

        <section class="control-panel">
            <div class="control-row">
                <input type="text" id="targetPath" class="path-input" value="./tests/fixtures/vulnerable_app" placeholder="Directory path to scan...">
                <button class="btn-scan" onclick="triggerScan()">
                    <span id="scanSpinner">🚀</span> Run Security Audit
                </button>
            </div>
        </section>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="val" id="valTotalFindings" style="color: #38bdf8;">0</div>
                <div class="lbl">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="val" id="valCritical" style="color: var(--critical);">0</div>
                <div class="lbl">Critical Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="val" id="valHigh" style="color: var(--high);">0</div>
                <div class="lbl">High Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="val" id="valScanTime" style="color: var(--success);">0.0s</div>
                <div class="lbl">Scan Duration</div>
            </div>
        </div>

        <div class="filters-bar">
            <div class="filter-tabs">
                <button class="tab-btn active" onclick="filterSeverity('ALL')">All</button>
                <button class="tab-btn" onclick="filterSeverity('CRITICAL')">Critical</button>
                <button class="tab-btn" onclick="filterSeverity('HIGH')">High</button>
                <button class="tab-btn" onclick="filterSeverity('MEDIUM')">Medium</button>
            </div>
            <input type="text" class="search-box" id="searchBox" placeholder="Search findings..." onkeyup="filterSearch()">
        </div>

        <div id="findingsContainer">
            <div style="text-align: center; color: var(--text-muted); padding: 3rem 0;">
                Click "Run Security Audit" above to scan the target codebase.
            </div>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        let currentFindings = [];
        let activeSeverity = 'ALL';

        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.style.background = isError ? '#ef4444' : '#10b981';
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 3500);
        }

        async function triggerScan() {
            const path = document.getElementById('targetPath').value.trim();
            const btn = document.querySelector('.btn-scan');
            btn.disabled = true;
            btn.innerHTML = '⏳ Scanning...';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path, skip_ai: true })
                });
                const data = await res.json();
                if (data.error) {
                    showToast(data.error, true);
                } else {
                    currentFindings = data.findings || [];
                    updateStats(data.stats);
                    renderFindings();
                    showToast(`Scan complete: ${data.findings.length} issue(s) identified.`);
                }
            } catch (err) {
                showToast('Failed to connect to SecureScope server.', true);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '🚀 Run Security Audit';
            }
        }

        function updateStats(stats) {
            document.getElementById('valTotalFindings').textContent = stats.total_findings;
            document.getElementById('valCritical').textContent = stats.severity_counts.CRITICAL || 0;
            document.getElementById('valHigh').textContent = stats.severity_counts.HIGH || 0;
            document.getElementById('valScanTime').textContent = stats.scan_time + 's';
        }

        function renderFindings() {
            const container = document.getElementById('findingsContainer');
            const term = document.getElementById('searchBox').value.toLowerCase();

            const filtered = currentFindings.filter(f => {
                const matchSev = activeSeverity === 'ALL' || f.severity === activeSeverity;
                const matchSearch = f.vulnerability.toLowerCase().includes(term) ||
                                    f.relative_path.toLowerCase().includes(term) ||
                                    f.description.toLowerCase().includes(term);
                return matchSev && matchSearch;
            });

            if (filtered.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching vulnerabilities found.</div>';
                return;
            }

            container.innerHTML = filtered.map(f => `
                <div class="finding-card">
                    <div class="finding-header">
                        <div class="finding-title">#${f.id} — ${f.vulnerability}</div>
                        <span class="tag-pill pill-${f.severity}">${f.severity}</span>
                    </div>
                    <div class="meta-line">
                        <span>📁 ${f.relative_path}:${f.line_number}</span>
                        <span>🛡️ ${f.owasp_id} ${f.owasp_name}</span>
                    </div>
                    <div class="desc-box">${f.description}</div>
                    <div class="fix-box">💡 <strong>Remediation:</strong> ${f.fix_suggestion}</div>
                    ${f.cve_references && f.cve_references.length > 0 ? `
                        <div class="cve-chips">
                            ${f.cve_references.map(c => `<a class="cve-chip" href="${c.url}" target="_blank">🔗 ${c.id}: ${c.title.substring(0, 45)}...</a>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }

        function filterSeverity(sev) {
            activeSeverity = sev;
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.textContent.toUpperCase() === sev);
            });
            renderFindings();
        }

        function filterSearch() {
            renderFindings();
        }

        async function applyAllFixes() {
            try {
                const res = await fetch('/api/fix', { method: 'POST' });
                const data = await res.json();
                if (data.status === 'success') {
                    showToast(`Successfully applied ${data.patched_count} security fixes (safety backups saved as .bak)`);
                } else {
                    showToast(data.message || 'No fixes could be applied.', true);
                }
            } catch (err) {
                showToast('Failed to apply remediation.', true);
            }
        }

        // Run initial scan on load
        window.addEventListener('DOMContentLoaded', () => {
            triggerScan();
        });
    </script>
</body>
</html>
"""


class SecureScopeHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler for SecureScope Web UI & API."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stdout request logs for a clean console experience."""
        pass

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._set_headers(200, "text/html")
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        elif path == "/api/status":
            self._set_headers(200)
            with STATE_LOCK:
                resp = {
                    "version": "1.0.0",
                    "engine": "Google Gemma 2",
                    "stats": SCAN_STATE["stats"],
                    "target_path": SCAN_STATE["target_path"],
                }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        elif path == "/api/patch":
            with STATE_LOCK:
                findings = SCAN_STATE["finding_objects"]
                target = SCAN_STATE["target_path"]

            if not findings or not target:
                self._set_headers(404, "text/plain")
                self.wfile.write(b"No active findings to generate patch.")
                return

            patch_content, _ = generate_unified_patch(findings, target)
            self.send_response(200)
            self.send_header("Content-Type", "text/x-diff; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="securescope.patch"')
            self.end_headers()
            self.wfile.write(patch_content.encode("utf-8"))
            return

        else:
            self._set_headers(404, "text/plain")
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        if path == "/api/scan":
            target_path = req_data.get("path", "./tests/fixtures/vulnerable_app")
            skip_ai = req_data.get("skip_ai", True)
            no_sca = req_data.get("no_sca", False)
            provider = req_data.get("provider", "groq")

            result = execute_scan(
                target_path=target_path,
                skip_ai=skip_ai,
                no_sca=no_sca,
                provider=provider,
            )
            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        elif path == "/api/fix":
            with STATE_LOCK:
                findings = SCAN_STATE["finding_objects"]
                target = SCAN_STATE["target_path"]

            if not findings or not target:
                self._set_headers(400)
                self.wfile.write(json.dumps({"status": "error", "message": "No findings available to fix."}).encode("utf-8"))
                return

            patched_count = apply_patch_directly(findings, target, create_backup=True)
            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "success",
                "patched_count": patched_count,
            }).encode("utf-8"))
            return

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode("utf-8"))


def start_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the SecureScope web dashboard server."""
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, SecureScopeHTTPHandler)
    url = f"http://{host}:{port}"
    print(f"\n🌐 SecureScope Web Dashboard running at: {url}")
    print(f"   Opening in browser... (Press Ctrl+C to stop)\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Stopping SecureScope Web Dashboard...")
        httpd.server_close()
