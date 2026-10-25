---
title: SecureScope: Building a Privacy-First AI Code Security Agent with Google Gemma 2, SerpApi & ElevenLabs
published: true
tags: hf26challenge, hacktoberfest, ai, opensource
canonical_url: 
description: How I built a local-first code security agent powered by Google Gemma 2 that audits repos offline, searches live CVEs via SerpApi, auto-fixes vulnerabilities, and synthesizes executive voice briefings with ElevenLabs.
---

*This project is submitted for the **Hacktoberfest 2026 — Week 3: Open-Source AI Challenge** (`#hf26challenge`).*

---

## 🧭 The Dilemma: Why Code Security Demands Open-Source AI

In the spirit of Hacktoberfest's 'Slow and Steady' sloth philosophy: moving too fast and breaking things is how API keys leak and injection flaws reach production. SecureScope brings steady, methodical, privacy-preserving AI audits to your workflow — because slow and steady wins the security race. 🦥

Every developer knows the sinking feeling of discovering an unintentional security vulnerability in production. Maybe it was an unescaped SQL parameter, a leaked API key in a configuration file, or an insecure deserialization call that slipped past code review.

Naturally, the industry has turned to AI for code analysis. But today's commercial AI code scanners present a painful paradox:

> **To find vulnerabilities in your private code, you must upload your entire proprietary codebase to a third-party closed-source cloud.**

For individual open-source developers, privacy-conscious startups, and regulated industries (fintech, healthcare, defense), this is often an unacceptable trade-off. Your intellectual property is transferred over the wire, subject to third-party retention policies, vendor rate limits, and recurring subscription bills.

I built **[SecureScope](https://github.com/SuperSaiyan101/securescope)** to break this trade-off.

SecureScope is an open-source, local-first code security intelligence agent built with **Google Gemma 2** at its core. It scans code across 6+ languages, screens vulnerabilities with a microsecond regex pre-filter, verifies threats using specialized open-weight AI personas, audits dependencies against the open-source **Google OSV** database, grounds findings in live **SerpApi** CVE data, generates unified git diff patches, enforces Git pre-commit hooks, and synthesizes executive voice briefings with **ElevenLabs** — all while keeping your source code strictly under your control.

---

## 🏆 Target Prize Categories

SecureScope was intentionally engineered to highlight open-weight AI and partner ecosystems:

| Category | Partner / Tech | How SecureScope Leverages It |
|---|---|---|
| 🌟 **Best Use of Gemma ($200)** | **Google Gemma 2** (`gemma2-9b-it`) | Primary open-weight foundation model driving vulnerability verification, false-positive elimination, confidence scoring, and drop-in code fix generation. |
| 🌐 **Best Use of SerpApi ($100)** | **SerpApi** | Live search agent querying NIST NVD, MITRE CWE, and GitHub Advisories to enrich findings with verified CVE data and security research links. |
| 🎙️ **Best Use of ElevenLabs ($100)** | **ElevenLabs** | Executive voice audio security briefing (`--voice`), converting complex scan diagnostics into clear spoken debriefs (`.mp3`). |
| 🐙 **Best Use of GitHub ($100)** | **GitHub Ecosystem** | Complete GitHub integration: **SARIF 2.1.0** alerts in GitHub Code Scanning, automated CI/CD security gating workflow, and one-click **Git Pre-Commit Hooks**. |

---

## 💡 Why Open Innovation Matters for SecureScope

The core prompt for Week 3 asks: *Where does an open-based approach work better than a closed one?* Here is the direct engineering reality:

### 1. Does it run on a laptop with no internet?
**Yes, 100%.** Using Ollama, SecureScope downloads Google Gemma 2 once and runs completely offline:
```bash
python cli.py --path ./my-project --provider ollama --model gemma2 --output all
```
Whether you are on an airplane, in an air-gapped lab, or working remotely without Wi-Fi, the entire audit pipeline — from file discovery to AI reasoning, SARIF export, and HTML report generation — executes locally on your CPU/GPU.

### 2. Does it keep data off servers you don't control?
**Absolutely.** Your code never leaves localhost. No proprietary logic, internal database connection strings, or architectural secrets are transmitted to closed-model API providers or stored in external prompt logs.

### 3. Does it allow model swapping and custom agent behavior?
**Yes.** Closed platforms lock you into their choice of model. SecureScope uses a modular adapter architecture. Want to switch from Google Gemma 2 to CodeGemma, or test a custom security fine-tune? Simply pass a flag:
```bash
python cli.py --path . --provider ollama --model codegemma
```
The specialized security prompts (`analyzer/prompts.py`) are fully open-source and customizable for team-specific coding standards.

### 4. Does it cost nothing to run?
**Zero marginal cost.** Running commercial API audits across high-frequency CI/CD pipelines can cost hundreds of dollars monthly in token usage. Running Gemma 2 locally or via generous free open-model endpoints means maintainers and students can run unlimited scans for $0.

---

### 📊 Direct Comparison: Closed SaaS vs. SecureScope

| Capability | Traditional Closed SaaS SAST | SecureScope (Open-Weight AI) |
|---|---|---|
| **Code Privacy** | Code uploaded to vendor cloud | **Zero code leaves your machine** |
| **Offline Execution** | ❌ Impossible | **✅ 100% offline with Ollama** |
| **Model Transparency** | Black-box commercial LLM | **Open-weight Google Gemma 2** |
| **CVE Validation** | Static rule matching | **Live SerpApi search + NIST links** |
| **Supply Chain (SCA)** | Expensive add-on tier | **Free Google OSV database audit** |
| **Auto-Remediation** | Static hints | **Unified Git patches (`.patch`) & auto-fix (`.bak`)** |
| **Pre-Commit Guard** | Complex enterprise setup | **One-click install (`--install-hook`)** |
| **Audio Debrief** | ❌ None | **ElevenLabs Executive Briefing** |
| **GitHub Native** | Proprietary dashboards | **OASIS SARIF 2.1.0 Code Scanning** |
| **Cost at Scale** | $50 – $500 / month / seat | **$0.00 (Self-hosted & open-source)** |

---

## 🏗️ Architecture: How SecureScope Operates

SecureScope avoids brute-forcing entire repositories into an LLM context window. Instead, it utilizes an efficient **multi-stage security pipeline**:

```plaintext
                      ┌───────────────────────────────┐
                      │    Target Codebase / Repo     │
                      └──────────────┬────────────────┘
                                     │
                         1. Git-Aware File Walker
                            (respects .gitignore,
                             supports --diff mode)
                                     │
                                     ▼
                         2. Regex Pre-Filter Engine
                            (Screens 200+ patterns;
                             skips clean files in <1ms)
                                     │
                                     ▼
                      3. Google Gemma 2 Analysis
                       (Multi-Role AI Security Agent)
                  ┌──────────────────┼──────────────────┐
                  ▼                  ▼                  ▼
           Role 1: Secrets    Role 2: Injection  Role 3: Auth & SSRF
                  └──────────────────┬──────────────────┘
                                     │
                      4. Live Threat Grounding (SerpApi)
                         (Fetches NIST NVD & MITRE CVEs)
                                     │
                                     ▼
                      5. Supply Chain Auditing (Google OSV)
                         (Audits requirements.txt & package.json)
                                     │
                                     ▼
                         6. OWASP Top 10 Mapping
                            (A01:2021 to A10:2021)
                                     │
                                     ▼
                        7. Multi-Modal Reporting
                  ┌────────────┬─────────────┬─────────────┐
                  ▼            ▼             ▼             ▼
            Rich Terminal  SARIF 2.1.0  Interactive   ElevenLabs
              Dashboard     (GitHub)     HTML Report   Voice Debrief
                                     │
                                     ▼
                      8. Automated Remediation Engine
                         (Unified .patch & safe .bak fixing)
```

### Stage 1: Git-Aware File Traversal & Diff Mode
The file walker (`scanner/file_walker.py`) queries `git ls-files` to automatically honor `.gitignore` rules, skips build artifacts (`node_modules`, `dist`, `venv`), and includes a `--diff` mode that scans only staged files in milliseconds.

### Stage 2: Sub-Millisecond Regex Pre-Filter
Scanning clean files with an LLM is slow and wasteful. SecureScope runs language-specific regex rules (`scanner/languages.py`) covering Python, JavaScript, TypeScript, Go, Java, and PHP. Clean files are bypassed instantly; only suspicious snippets with surrounding context are packaged for AI review.

### Stage 3: Multi-Role Reasoning with Google Gemma 2
Candidate snippets are dispatched to Google Gemma 2 (`analyzer/ai_client.py`). Specialized auditor personas analyze each flaw:
- **Injection Auditor**: Traces whether untrusted inputs flow into `sqlite3.execute()`, `child_process.exec()`, or `eval()`.
- **Credential & Secret Detector**: Distinguishes between real high-entropy API tokens and harmless test dummy strings.
- **Access & Cryptographic Reviewer**: Flags weak hashing (`MD5`, `SHA1`), disabled TLS validation, and unsafe deserialization (`pickle.loads`, unsafe YAML).

### Stage 4: Live Threat Grounding via SerpApi
When Gemma 2 confirms a vulnerability, SecureScope queries SerpApi (`analyzer/cve_search.py`) against the National Vulnerability Database (NVD) and MITRE CWE:
```python
search_query = f"{vulnerability} {language} (site:cve.mitre.org OR site:nvd.nist.gov)"
```
This attaches verified CVE IDs, severity scores, and direct research links to every report.

### Stage 5: Software Composition Analysis (SCA) via Google OSV
Over 80% of real-world vulnerabilities stem from third-party dependencies. SecureScope parses `requirements.txt` and `package.json`, querying Google's Open Source Vulnerabilities (OSV) API to detect known CVEs, exact line numbers, and recommended patched version numbers (`>= x.y.z`).

### Stage 6: Automated Remediation Engine
SecureScope doesn't just detect vulnerabilities—it fixes them. Using `remediator/patcher.py`, developers can generate a unified Git diff (`securescope.patch`) or apply safe automated fixes directly to source files with `.bak` safety backups.

---

## 📸 The Multi-Modal Reporting Experience

![Image description](https://dev-to-uploads.s3.us-east-2.amazonaws.com/uploads/articles/zmvfgaglx4meoeikcnn2.png)

SecureScope delivers findings across four complementary output channels:

1. **Rich Terminal Dashboard**: Color-coded severity gauges, OWASP Top 10 breakdown tables, and highlighted code snippets.
2. **Interactive Standalone HTML Report**: Zero-dependency dark-mode dashboard with expandable vulnerability cards, fix suggestions, and clickable CVE badges.
3. **OASIS SARIF 2.1.0 Export**: Direct ingestion into GitHub Advanced Security and GitHub Code Scanning alerts.
4. **ElevenLabs Audio Security Briefing**: Synthesizes an executive spoken overview (`.mp3`) summarizing critical risks for engineering leads on the go.

---

## 🌐 Real-Time Web Dashboard (`--serve`)

For developers who prefer an interactive visual interface, SecureScope includes a built-in, zero-dependency local web server:

```bash
python cli.py --serve
```

Running this command spins up a local dashboard at `http://localhost:8080` where you can:
- Trigger live audits across any directory path.
- Filter findings by Severity (Critical, High, Medium, Low) and instant text search.
- Click **"Download Git Patch"** to grab a ready-to-commit `.patch` file.
- Click **"Auto-Fix Files"** to remediate code directly with automatic safety backups.

---

## 🔬 Real-World Example: Finding & Fixing an Injection Flaw

![Image description](https://dev-to-uploads.s3.us-east-2.amazonaws.com/uploads/articles/k7z7xrbnrzercv6wnq9i.png)

To test the system, I ran SecureScope against a deliberately vulnerable fixture containing an unsafe SQL query:

### Vulnerable Input Code (`app.py`):
```python
def search_users(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Flaw: Direct string interpolation into SQL query
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
```

### SecureScope Terminal Output:
```plaintext
╭──────────────── #1 — SQL Injection via String Formatting ────────────────╮
│ Severity: 🔴 CRITICAL                                                    │
│ OWASP: A03:2021 — Injection                                              │
│ Confidence: HIGH                                                         │
│ File: app.py (line 45)                                                   │
│                                                                          │
│ Description: User-controlled 'username' parameter is directly formatted │
│ into the SQL query string, allowing arbitrary SQL command execution.    │
│                                                                          │
│ 💡 Fix: Use parameterized queries:                                       │
│ cursor.execute("SELECT * FROM users WHERE name = ?", (username,))        │
│                                                                          │
│ 🌐 Live CVE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)     │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Auto-Remediation with Unified Patching:
Running `python cli.py --patch` generates a clean Git patch:
```diff
--- a/app.py
+++ b/app.py
@@ -45,1 +45,1 @@
-    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
+    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```
Apply with `git apply securescope.patch` or pass `--fix` to patch the file automatically!

### Generated ElevenLabs Voice Briefing Transcript:
> *"Attention security team. This is your SecureScope automated security audit briefing. We scanned 2 files in 0.1 seconds, identifying 1 critical vulnerability: SQL Injection via String Formatting in app.py. AI-suggested parameterized query patches have been compiled in your HTML report."*

---

## 🪝 Zero-Config Git Pre-Commit Hook

Prevent vulnerable code and leaked secrets from ever reaching your Git history with a single command:

```bash
# Install the hook into your current Git repository:
python cli.py --install-hook

# Now git commit automatically screens your staged diff in <0.2s:
git commit -m "feat: user search"
# 🔐 [SecureScope] Auditing staged code and dependencies before commit...
# 🚨 [SecureScope] Commit rejected: Security issues detected in staged changes!
#    • Run 'python cli.py --diff' to view full findings.
#    • Run 'python cli.py --fix' to automatically apply remediations.
```

---

## ⚡ Quickstart & How to Run

### 1. Installation
```bash
git clone https://github.com/SuperSaiyan101/securescope.git
cd securescope
pip install -r requirements.txt
```

### 2. Instant Local Scan (No API Key Required)
```bash
python cli.py --path ./tests/fixtures/vulnerable_app --skip-ai --output all
```

### 3. Full AI Scan with Google Gemma 2
```bash
export GROQ_API_KEY="gsk_..."  # Windows: $env:GROQ_API_KEY="gsk_..."
python cli.py --path ./my-project --output all
```

### 4. 100% Offline Local Scan with Ollama
```bash
ollama pull gemma2
python cli.py --path ./my-project --provider ollama --model gemma2 --output all
```

### 5. Generate Voice Briefing with ElevenLabs
```bash
export ELEVENLABS_API_KEY="your_key"
python cli.py --path ./my-project --voice --output all
```

### 6. Auto-Remediation & Patching
```bash
# Generate unified git diff patch:
python cli.py --path ./my-project --patch

# Or auto-fix source files with safety backups (.bak):
python cli.py --path ./my-project --fix
```

### 7. Launch Real-Time Web Dashboard
```bash
python cli.py --serve
# Open http://localhost:8080 in your browser
```

---

## 🐙 CI/CD Integration: GitHub Actions & SARIF Code Scanning

SecureScope includes a drop-in workflow (`.github/workflows/securescope.yml`) that audits every pull request, exports SARIF 2.1.0 results into the native **GitHub Security Tab**, and blocks merges on critical flaws:

```yaml
name: SecureScope Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -r requirements.txt
      - name: Run SecureScope Audit
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: python cli.py --path . --output all --report-file securescope_report --fail-on critical

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: securescope_report.sarif
        continue-on-error: true
```

---

## 🛠️ How I Built It (Show Your Work)

This project was developed iteratively using **OpenCode**, an open-source terminal coding agent harness connecting to open-weight LLMs. 

Using OpenCode, I:
1. **Architected the hybrid engine**: Combined regex pre-filtering with Google Gemma 2 for speed and precision.
2. **Standardized on Open Formats**: Implemented OASIS SARIF 2.1.0 to integrate seamlessly with GitHub Advanced Security.
3. **Engineered Auto-Remediation**: Built a unified diff patch generator and direct AST file patcher with automatic `.bak` backups.
4. **Integrated Supply Chain Auditing**: Connected directly to the Google OSV API to inspect `requirements.txt` and `package.json` with zero API keys.
5. **Crafted Developer Guards**: Designed a one-click Git pre-commit hook and a zero-dependency local web server for visual security audits.

Building an open security tool using an open agent harness felt like the ultimate demonstration of what open-source AI makes possible in 2026.

---

## 🔗 Code & Repository

- **GitHub Repository**: [https://github.com/SuperSaiyan101/securescope](https://github.com/SuperSaiyan101/securescope)
- **License**: MIT License

---

*What are your biggest pain points with modern code security scanners? Try running SecureScope on your project, and share your thoughts and feedback below!*
