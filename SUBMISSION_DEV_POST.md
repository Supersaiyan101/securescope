---
title: SecureScope: Building a Privacy-First AI Code Security Agent with Google Gemma 2, SerpApi & ElevenLabs
published: true
tags: hf26challenge, hacktoberfest, ai, opensource
cover_image: https://raw.githubusercontent.com/username/securescope/main/assets/cover.png
canonical_url: 
description: How I built a local-first code security agent powered by Google Gemma 2 that audits repos offline, searches live CVEs via SerpApi, and synthesizes executive voice briefings with ElevenLabs.
---

*This project is submitted for the **Hacktoberfest 2026 — Week 3: Open-Source AI Challenge** (`#hf26challenge`).*

---

## 🧭 The Dilemma: Why Code Security Demands Open-Source AI

Every developer knows the sinking feeling of discovering an unintentional security vulnerability in production. Maybe it was an unescaped SQL parameter, a leaked API key in a configuration file, or an insecure deserialization call that slipped past code review.

Naturally, the industry has turned to AI for code analysis. But today's commercial AI code scanners present a painful paradox:

> **To find vulnerabilities in your private code, you must upload your entire proprietary codebase to a third-party closed-source cloud.**

For individual open-source developers, privacy-conscious startups, and regulated industries (fintech, healthcare, defense), this is often an unacceptable trade-off. Your intellectual property is transferred over the wire, subject to third-party retention policies, vendor rate limits, and recurring subscription bills.

I built **[SecureScope](https://github.com/YOUR_GITHUB_USERNAME/securescope)** to break this trade-off.

SecureScope is an open-source, local-first code security intelligence agent built with **Google Gemma 2** at its core. It scans code across 6+ languages, screens vulnerabilities with a microsecond regex pre-filter, verifies threats using specialized open-weight AI personas, grounds findings in live **SerpApi** CVE data, and synthesizes executive voice briefings with **ElevenLabs** — all while keeping your source code strictly under your control.

---

## 🏆 Target Prize Categories

SecureScope was intentionally engineered to highlight open-weight AI and partner ecosystems:

| Category | Partner / Tech | How SecureScope Leverages It |
|---|---|---|
| 🌟 **Best Use of Gemma ($200)** | **Google Gemma 2** (`gemma2-9b-it`) | Primary open-weight foundation model driving vulnerability detection, confidence scoring, and drop-in code fix generation. |
| 🌐 **Best Use of SerpApi ($100)** | **SerpApi** | Live search agent querying NIST NVD, MITRE CWE, and GitHub Advisories to enrich findings with verified CVE data. |
| 🎙️ **Best Use of ElevenLabs ($100)** | **ElevenLabs** | Executive voice audio security briefing (`--voice`), converting complex scan diagnostics into clear spoken debriefs. |
| 🐙 **Best Use of GitHub ($100)** | **GitHub Actions** | Automated CI/CD security workflow (`.github/workflows/securescope.yml`) scanning pull requests on every commit. |

---

## 💡 Why Open Innovation Matters for SecureScope

The core prompt for Week 3 asks: *Where does an open-based approach work better than a closed one?* Here is the direct engineering reality:

### 1. Does it run on a laptop with no internet?
**Yes, 100%.** Using Ollama, SecureScope downloads Google Gemma 2 once and runs completely offline:
```bash
python cli.py --path ./my-project --provider ollama --model gemma2 --output all
```
Whether you are on an airplane, in an air-gapped lab, or working remotely without Wi-Fi, the entire audit pipeline — from file discovery to AI reasoning and HTML report generation — executes locally on your CPU/GPU.

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
| **Audio Debrief** | ❌ None | **ElevenLabs Executive Briefing** |
| **Cost at Scale** | $50 – $500 / month / seat | **$0.00 (Self-hosted & open-source)** |

---

## 🏗️ Architecture: How SecureScope Operates

SecureScope avoids brute-forcing entire repositories into an LLM context window. Instead, it utilizes an efficient **5-stage pipeline**:

```
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
                             skips clean files)
                                     │
                                     ▼
                      3. Google Gemma 2 Analysis
                       (Multi-Role AI Security Agent)
                  ┌──────────────────┼──────────────────┐
                  ▼                  ▼                  ▼
           Role 1: Secrets    Role 2: Injection  Role 3: Auth & SSRF
                  └──────────────────┬──────────────────┘
                                     │
                      4. Live CVE Grounding (SerpApi)
                         (Fetches NIST NVD & MITRE CVEs)
                                     │
                                     ▼
                         5. OWASP Top 10 Mapping
                            (A01:2021 to A10:2021)
                                     │
                                     ▼
                        6. Multi-Modal Reporting
                  ┌──────────────────┼──────────────────┐
                  ▼                  ▼                  ▼
            Rich Terminal      Interactive HTML   ElevenLabs Voice
              Dashboard           Dashboard           Briefing
```

### Stage 1: Git-Aware File Traversal
The file walker (`scanner/file_walker.py`) queries `git ls-files` to automatically honor `.gitignore` rules, skips build directories (`node_modules`, `dist`, `venv`), and includes a `--diff` mode that isolates files changed in the active Git branch.

### Stage 2: Sub-Millisecond Regex Pre-Filter
Scanning hundreds of clean files with an LLM is slow and wasteful. SecureScope runs language-specific regex rules (`scanner/languages.py`) covering Python, JavaScript, TypeScript, Go, Java, and PHP. Clean files are skipped instantly; only suspicious lines with surrounding code context are packaged as candidate snippets.

### Stage 3: Multi-Role Reasoning with Google Gemma 2
Candidate snippets are dispatched to Google Gemma 2 (`analyzer/ai_client.py`). Instead of a vague prompt, we assign specialized security auditor personas:
- **Injection Auditor**: Traces whether untrusted parameters flow into `sqlite3.execute()`, `child_process.exec()`, or `eval()`.
- **Credential & Secret Detector**: Distinguishes between actual high-entropy API keys and benign variable declarations.
- **Access & Cryptographic Reviewer**: Flags broken algorithms (`MD5`, `SHA1`, `DES`) and insecure deserialization (`pickle.loads`, unsafe YAML).

### Stage 4: Live Threat Grounding via SerpApi
When Gemma 2 confirms a vulnerability, SecureScope calls SerpApi (`analyzer/cve_search.py`) to query the National Vulnerability Database (NVD) and MITRE CWE:
```python
search_query = f"{vulnerability} {language} (site:cve.mitre.org OR site:nvd.nist.gov)"
```
This decorates each finding with real-world CVE identifiers, CVSS context, and direct research links.

### Stage 5: Multi-Modal Reporting & ElevenLabs Voice
Results are compiled into three output streams:
1. **Rich Terminal Dashboard**: Color-coded severity meters and OWASP category breakdown.
2. **Interactive Standalone HTML Report**: Zero-dependency dark-mode dashboard with expandable code diffs.
3. **ElevenLabs Audio Security Briefing**: Synthesizes a spoken executive summary (`.mp3`) alerting teams to critical risks.

---

## 🔬 Real-World Example: Finding & Fixing an Injection Flaw

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
```
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

### Generated ElevenLabs Voice Briefing Transcript:
> *"Attention security team. This is your SecureScope automated security audit briefing. We scanned 2 files in 0.1 seconds, identifying 1 critical vulnerability: SQL Injection via String Formatting in app.py. AI-suggested parameterized query patches have been compiled in your HTML report."*

---

## ⚡ Quickstart & How to Run

### 1. Installation
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/securescope.git
cd securescope
pip install -r requirements.txt
```

### 2. Instant Scan (Offline / No API Key Needed)
```bash
python cli.py --path ./tests/fixtures/vulnerable_app --skip-ai --output all
```

### 3. Full AI Scan with Google Gemma 2
```bash
# Set free Groq API key for cloud Gemma 2
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

---

## 🐙 CI/CD Integration: GitHub Actions

SecureScope includes a drop-in workflow (`.github/workflows/securescope.yml`) to automatically audit incoming Pull Requests:

```yaml
name: SecureScope Security Gate
on: [push, pull_request]

jobs:
  audit:
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
        run: python cli.py --path . --output all --report-file pr_report
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: pr_report.html
```

---

## 🛠️ How I Built It (Show Your Work)

This project was developed iteratively using **OpenCode**, an open-source terminal coding agent harness connecting to open-weight LLMs. 

Using OpenCode, I:
1. Prototyped the regex pre-filtering engine across multiple programming languages.
2. Iterated on specialized system prompts to eliminate LLM hallucinations and enforce structured JSON outputs.
3. Implemented standard library fallbacks (e.g. `urllib` instead of heavyweight HTTP clients) to keep dependencies minimal and installation lightning fast.
4. Stress-tested the scanner against real-world and synthetic OWASP Top 10 test suites.

Building an open security tool using an open agent harness felt like the ultimate demonstration of what open-source AI makes possible in 2026.

---

## 🔗 Code & Repository

- **GitHub Repository**: [https://github.com/YOUR_GITHUB_USERNAME/securescope](https://github.com/YOUR_GITHUB_USERNAME/securescope)
- **License**: MIT License

---

*What are your biggest pain points with modern code security scanners? Try running SecureScope on your project, and share your thoughts and feedback below!*
