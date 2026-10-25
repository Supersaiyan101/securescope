# 🔐 SecureScope

**AI-powered local code security scanner built on open-weight models.**

SecureScope scans your codebase for security vulnerabilities, hardcoded secrets, and injection flaws using open-weight AI (powered by **Google Gemma 2** via Groq or local Ollama). It enriches findings with live **SerpApi** CVE intelligence, maps every vulnerability to the **OWASP Top 10**, generates concrete AI-powered code fix suggestions, and synthesizes executive audio briefings using **ElevenLabs**.

> Built for [Hacktoberfest 2026 — Week 3: Open-Source AI Challenge](https://hacktoberfest.com) (`#hf26challenge`)

---

## 🏆 Hacktoberfest 2026 Prize Integrations

SecureScope is engineered to showcase the best of open-source AI and partner integrations:

| Category | Partner / Model | How SecureScope Uses It |
|---|---|---|
| 🌟 **Featured Category ($200)** | **Google Gemma 2** (`gemma2-9b-it`) | Flagship open-weight foundation model driving code analysis, vulnerability scoring, and remediation suggestions. |
| 🌐 **Partner Category ($100)** | **SerpApi** | Real-time web search agent grounding AI findings in live NIST NVD, MITRE CWE, and GitHub Security Advisories. |
| 🎙️ **Partner Category ($100)** | **ElevenLabs** | Executive voice audio security briefing (`--voice`), synthesizing spoken audit summaries and risk alerts. |
| 🐙 **Partner Category ($100)** | **GitHub Actions** | Drop-in CI/CD workflow template (`.github/workflows/securescope.yml`) to audit Pull Requests and enforce security gates. |

---

## ✨ Features

- **Google Gemma 2 Powered** — Flagship open-weight model with strong code reasoning and zero vendor lock-in.
- **100% Offline Capable** — Runs completely offline with Ollama (`--provider ollama --model gemma2`). Your proprietary code never leaves your computer.
- **Live CVE Intelligence (SerpApi)** — Enriches code findings with real-time CVE IDs and National Vulnerability Database links.
- **Executive Voice Briefings (ElevenLabs)** — Produces instant audio security briefings (`--voice`) alongside audio transcripts.
- **Multi-Language Support** — Python, JavaScript, TypeScript, Go, Java, PHP, and configuration files.
- **OWASP Top 10 (2021) Mapping** — Every finding is classified into A01–A10 taxonomy with severity scoring.
- **AI Fix Suggestions** — Generates drop-in code patches, not just warning messages.
- **Fast Regex Pre-Filter** — Screens files in milliseconds before contacting the AI model, preserving compute and tokens.
- **Interactive Dark-Mode HTML Report** — Zero-dependency standalone HTML dashboard with expandable code findings and remediation steps.
- **Structured JSON Export** — Machine-readable reports designed for automated CI/CD security pipelines.
- **Git Diff Mode** — Scan only changed files in current branch/PR with `--diff`.

---

## 📁 Project Structure

```
securescope/
├── cli.py                      # Main CLI entry point with Rich terminal dashboard
├── config.py                   # Central settings: Gemma 2, SerpApi, ElevenLabs, OWASP rules
├── scanner/
│   ├── __init__.py
│   ├── file_walker.py          # Git-aware file traversal (respects .gitignore, supports --diff)
│   ├── pre_filter.py           # Multi-language regex engine extracting suspicious snippets
│   ├── languages.py            # 200+ targeted vulnerability patterns across 6+ languages
│   └── dependency_auditor.py   # Software Supply-Chain & Dependency Auditor (Google OSV)
├── analyzer/
│   ├── __init__.py
│   ├── ai_client.py            # AI adapter for Google Gemma 2 (Groq API & Ollama local)
│   ├── prompts.py              # Specialized multi-role system prompts (Secrets, Injection, Auth, Crypto)
│   ├── owasp_mapper.py         # Maps findings into OWASP Top 10 (2021) categories
│   └── cve_search.py           # Live CVE & advisory enrichment powered by SerpApi
├── remediator/
│   ├── __init__.py
│   └── patcher.py              # Automated Git unified diff patch & safe remediation engine
├── reporter/
│   ├── __init__.py
│   ├── terminal.py             # Rich terminal reporter with tables, colors, and progress
│   ├── sarif.py                # OASIS SARIF 2.1.0 generator for GitHub Code Scanning
│   ├── html_report.py          # Standalone HTML report generator
│   ├── json_export.py          # CI/CD JSON exporter
│   └── voice_briefing.py       # ElevenLabs Text-to-Speech audio security briefing generator
├── templates/
│   └── report.html             # Dark-mode Jinja2 HTML report template with CVE badges
├── .github/
│   └── workflows/
│       └── securescope.yml     # Drop-in GitHub Actions automated security audit workflow
├── tests/
│   └── fixtures/               # Vulnerable test suite covering OWASP Top 10 (Python & JS)
├── requirements.txt            # Python dependencies
├── SUBMISSION_DEV_POST.md      # Ready-to-publish Hacktoberfest DEV.to submission
├── LICENSE                     # MIT License
└── README.md                   # Project documentation
```

---

## 🔄 Architecture & Data Flow

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

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/SuperSaiyan101/securescope.git
cd securescope

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quickstart & Usage

### 1. Instant Scan (Pre-Filter & CVE Mapping)
Run on the included test fixtures without an AI key:
```bash
python cli.py --path ./tests/fixtures/vulnerable_app --skip-ai --output all
```

### 2. Full AI Security Scan with Google Gemma 2 (Cloud)
Using free Groq API:
```bash
# Set your Groq API key (free at console.groq.com)
export GROQ_API_KEY="gsk_..."  # On Windows PowerShell: $env:GROQ_API_KEY="gsk_..."

# Run audit using Gemma 2
python cli.py --path ./my-project --output all
```

### 3. 100% Offline Scanning with Local Gemma 2 (Ollama)
```bash
ollama pull gemma2
python cli.py --path ./my-project --provider ollama --model gemma2 --output all
```

### 4. Enable Live SerpApi CVE Intelligence
```bash
export SERPAPI_API_KEY="your_serpapi_key"
python cli.py --path ./my-project --enrich-cve --output all
```

### 5. Generate ElevenLabs Executive Voice Briefing
```bash
export ELEVENLABS_API_KEY="your_elevenlabs_key"
python cli.py --path ./my-project --voice --output all
```

### 6. Export to SARIF for GitHub Code Scanning
```bash
python cli.py --path ./my-project --output sarif --report-file securescope_report
```

### 7. Auto-Remediation: Generate Git Patches or Auto-Fix
```bash
# Generate a unified git patch:
python cli.py --path ./my-project --patch --report-file securescope_patch
# Apply generated patch with Git:
git apply securescope_patch.patch

# Or directly apply remediation with safety backups (.bak):
python cli.py --path ./my-project --fix
```

### 8. Software Supply-Chain & Dependency Auditing (SCA)
SecureScope automatically audits third-party package manifests (`requirements.txt`, `package.json`) against the open-source **Google OSV (Open Source Vulnerabilities)** database, pinpointing known CVEs, severity ratings, and recommended fixed versions:
```bash
# Auditing is enabled by default during scans:
python cli.py --path ./my-project

# To disable dependency auditing:
python cli.py --path ./my-project --no-sca
```


---

## 🔑 Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `GROQ_API_KEY` | Optional | — | Free key to run Google Gemma 2 (`gemma2-9b-it`) in cloud |
| `OLLAMA_HOST` | Optional | `http://localhost:11434` | Local Ollama endpoint for 100% offline scanning |
| `SERPAPI_API_KEY` | Optional | — | Real-time CVE and vulnerability intelligence search |
| `ELEVENLABS_API_KEY` | Optional | — | Generates executive audio briefings (`.mp3`) |
| `ELEVENLABS_VOICE_ID` | Optional | `21m00Tcm4TlvDq8ikWAM` | Voice ID for audio narration |

---

## 🐙 CI/CD Integration (GitHub Actions)

A pre-configured GitHub Actions workflow is provided in `.github/workflows/securescope.yml`. It runs on every push and pull request, uploads reports as artifacts, and blocks merges if `CRITICAL` vulnerabilities are discovered.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
