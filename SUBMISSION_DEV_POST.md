---
title: SecureScope: Building a Local AI Code Security Agent Powered by Google Gemma 2, SerpApi & ElevenLabs
published: true
tags: hf26challenge, hacktoberfest, ai, opensource
cover_image: https://raw.githubusercontent.com/username/securescope/main/assets/cover.png
canonical_url: 
description: A privacy-first, local code security scanner that maps findings to OWASP Top 10, searches live CVEs via SerpApi, and synthesizes audio briefings with ElevenLabs.
---

*This project is submitted for the **Hacktoberfest 2026 — Week 3: Open-Source AI Challenge** (`#hf26challenge`).*

---

## 🏆 Target Prize Categories

SecureScope was purpose-built to combine open-weight AI with leading developer toolkits:

- 🌟 **Best Use of Gemma ($200)** — Uses Google Gemma 2 (`gemma2-9b-it` / `codegemma`) as the primary open-weight foundation model for vulnerability detection and remediation code generation.
- 🌐 **Best Use of SerpApi ($100)** — Empowers the security agent with real-time web search over NIST National Vulnerability Database (NVD) and MITRE CWE records.
- 🎙️ **Best Use of ElevenLabs ($100)** — Synthesizes spoken executive security briefings and risk alerts from scan results.
- 🐙 **Best Use of GitHub / GitHub Actions ($100)** — Includes an automated drop-in CI/CD pull request security gate.

---

## 🎯 What I Built

Modern engineering teams want the power of AI to detect security vulnerabilities early, but **sending proprietary codebases to third-party commercial cloud APIs creates severe compliance, intellectual property, and privacy risks.**

I built **[SecureScope](https://github.com/YOUR_GITHUB_USERNAME/securescope)**: a local-first, privacy-preserving code security scanner and intelligence agent powered by **Google Gemma 2**.

SecureScope provides:
1. **Multi-Language Security Auditing** (Python, JavaScript, TypeScript, Go, Java, PHP, and configs).
2. **Fast Regex Pre-Filtering** that eliminates 95%+ of clean files before calling the LLM.
3. **Multi-Role AI Reasoning** with Google Gemma 2, analyzing suspicious code context for injection flaws, authentication bugs, broken cryptography, and secret leaks.
4. **Live CVE Grounding via SerpApi**, searching live CVE and NIST databases to validate vulnerability impact.
5. **OWASP Top 10 (2021) Classification** and concrete, drop-in fix suggestions.
6. **Executive Audio Briefings with ElevenLabs** (`--voice`), synthesizing spoken audit summaries for security leads and PR reviews.
7. **Interactive Dark-Mode HTML Dashboards** and structured JSON outputs for CI/CD pipelines.

---

## 💡 Why Open-Source AI (Google Gemma) Was Essential

When designing SecureScope, relying on open-weight AI was the defining architectural decision:

### 1. 🛡️ Absolute Data Privacy & Zero Leaks
Source code represents the core intellectual property of developers and companies. When utilizing Google Gemma 2 locally through Ollama, **your source code never leaves your computer**. There is zero transmission over the wire and zero risk of your proprietary algorithms training external models.

### 2. 🔌 Air-Gapped & Offline Security Audits
Security teams in sensitive sectors (finance, defense, healthcare) often work in restricted or air-gapped environments. With open-weight Gemma 2, SecureScope executes full scans without requiring an internet connection:
```bash
python cli.py --path ./my-project --provider ollama --model gemma2
```

### 3. 🔄 Model Swappability & Community Freedom
Closed APIs bind developers to vendor price increases, rate limits, and breaking deprecation schedules. With open-weight AI, teams can switch between Gemma 2, CodeGemma, or domain-specific fine-tunes with a single command-line flag.

### 4. 💸 Zero Marginal Cost at Scale
Auditing every pull request and commit using commercial token APIs is cost-prohibitive for open-source maintainers and startups. Running self-hosted open-weight models in CI/CD reduces marginal costs to zero.

---

## 🏗️ Architecture & How It Works

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

### 1. Multi-Role Prompting with Gemma 2
Rather than a generic prompt, SecureScope divides analysis into specialized security personas:
- **Credential & Secret Detector**: Inspects high-entropy tokens, AWS/GCP keys, and database URIs.
- **Injection Auditor**: Evaluates untrusted data flow into dangerous execution sinks (SQL, subprocess, eval, innerHTML).
- **Authentication & Access Specialist**: Identifies broken JWT verification, disabled TLS checks (`verify=False`), and IDOR risks.
- **Cryptographic Reviewer**: Flags broken primitives (MD5, SHA-1, DES) and insecure deserialization (pickle, unsafe YAML).

### 2. Live Threat Intelligence with SerpApi
When a vulnerability is detected, SecureScope uses SerpApi to query real-world vulnerability databases:
```python
# analyzer/cve_search.py
search_query = f"{vulnerability} {language} (site:cve.mitre.org OR site:nvd.nist.gov)"
# Returns exact CVE IDs, descriptions, and verified advisory URLs
```
This grounds the AI's recommendations with official CVE/CWE numbers.

### 3. Voice Executive Briefings with ElevenLabs
With the `--voice` flag, SecureScope invokes ElevenLabs to synthesize an executive audio briefing:
> *"Attention security team. This is your SecureScope security audit briefing. We scanned 14 files in 1.2 seconds, identifying 2 critical severity vulnerabilities involving SQL injection in server.js. Remediation patches have been compiled in your HTML report."*

---

## ⚡ Quickstart & Usage

### Installation
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/securescope.git
cd securescope
pip install -r requirements.txt
```

### Instant Test Run (No API key needed)
```bash
python cli.py --path ./tests/fixtures/vulnerable_app --skip-ai --output all
```

### Full AI Scan with Google Gemma 2
```bash
export GROQ_API_KEY="gsk_..."
python cli.py --path ./my-project --output all
```

### 100% Offline with Local Gemma (Ollama)
```bash
ollama pull gemma2
python cli.py --path ./my-project --provider ollama --model gemma2 --output all
```

### Executive Voice Briefing with ElevenLabs
```bash
export ELEVENLABS_API_KEY="your_key"
python cli.py --path ./my-project --voice --output all
```

---

## 🐙 Automated CI/CD (GitHub Actions)

SecureScope comes with a complete GitHub Actions workflow (`.github/workflows/securescope.yml`):
- Executes automatically on `push` and `pull_request`
- Scans changed files with `--diff`
- Uploads interactive HTML dashboards and JSON data as build artifacts
- Fails the build pipeline if `CRITICAL` severity issues are discovered

---

## 🛠️ Built with OpenCode

SecureScope was developed using **OpenCode**, the open-source terminal coding agent connected to open-weight LLMs, demonstrating the power of building security tools with open developer ecosystems.

---

## 🔗 Links & Code

- **GitHub Repository**: [https://github.com/YOUR_GITHUB_USERNAME/securescope](https://github.com/YOUR_GITHUB_USERNAME/securescope)
- **License**: MIT License

---

*Feedback and contributions are warmly welcome! Try scanning your repo and let me know your thoughts in the comments!*
