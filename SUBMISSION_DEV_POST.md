---
title: SecureScope: Building an AI Code Security Scanner Powered by Open-Weight LLMs
published: true
tags: hf26challenge, hacktoberfest, ai, opensource
cover_image: https://raw.githubusercontent.com/username/securescope/main/assets/cover.png
canonical_url: 
description: A privacy-first, local-capable code security scanner that maps findings to OWASP Top 10 and suggests fixes using open-weight models.
---

*This article is submitted for the **Hacktoberfest 2026 — Week 3: Open-Source AI Challenge** (`#hf26challenge`).*

---

## 🎯 What I Built

Modern developers rely heavily on commercial SAST tools and proprietary cloud security scanners. The problem? **Sending your entire proprietary codebase to third-party cloud servers is often a non-starter for security-conscious teams, enterprises, and open-source developers alike.**

To solve this, I built **[SecureScope](https://github.com/YOUR_GITHUB_USERNAME/securescope)**: a privacy-first, AI-powered code security scanner that runs locally on open-weight models (Llama 3 via Groq or Ollama).

SecureScope scans code across multiple languages, screens files using a fast regex pre-filter, feeds suspicious context into specialized open-weight AI agent roles, maps each vulnerability directly to the **OWASP Top 10 (2021)**, and produces actionable fix suggestions alongside terminal, JSON, and standalone dark-mode HTML reports.

---

## 💡 Why Open-Source AI Matters for This Project

When designing SecureScope, relying on open-source / open-weight AI wasn't just an implementation detail — **it was the core requirement**. Here is why:

### 1. 🛡️ Data Privacy & Zero Leaks
Code contains proprietary business logic, internal API routes, and sometimes accidental secrets. With open-weight models like Meta's **Llama 3** running locally through **Ollama** or via dedicated inference endpoints, your proprietary source code never leaves your perimeter or trains third-party commercial LLMs.

### 2. 🔌 True Offline & Air-Gapped Capabilities
Security auditing often happens in regulated environments (finance, defense, healthcare) without outbound internet access. SecureScope can execute 100% offline using local inference (`--provider ollama --model llama3`).

### 3. 🔄 Model Swappability & Community Innovation
Closed APIs lock you into single-vendor rate limits, pricing changes, and deprecation cycles. With open-weight AI, developers can swap in specialized coding models (like Qwen Coder, DeepSeek Coder, or fine-tuned security models) with a simple CLI flag:
```bash
python cli.py --provider ollama --model qwen2.5-coder
```

### 4. 💸 Zero Marginal Cost for CI/CD Pipelines
Running proprietary API audits on every Git push or Pull Request can get cost-prohibitive fast. By leveraging open-weight models and free/self-hosted inference tiers, development teams can integrate security audits into every pull request for free.

---

## 🏗️ Architecture & How It Works

SecureScope uses a multi-stage pipeline designed for both speed and depth:

```
                  ┌───────────────────────────────┐
                  │    Target Project / Repo      │
                  └──────────────┬────────────────┘
                                 │
                     1. Git-Aware File Walker
                        (respects .gitignore,
                         supports --diff mode)
                                 │
                                 ▼
                     2. Regex-Based Pre-Filter
                        (Multi-language patterns:
                         Py, JS, TS, Go, Java, PHP)
                                 │
                                 ▼
                   3. Multi-Role AI Analysis
                  (Llama 3 / Open-Weight Models)
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       Role 1: Secrets    Role 2: Injection  Role 3: Auth & SSRF
              └──────────────────┬──────────────────┘
                                 ▼
                     4. OWASP Top 10 Mapper
                        (A01 - A10 Taxonomy)
                                 │
                                 ▼
                    5. Multi-Format Reporters
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
        Rich Terminal       Structured JSON    Standalone HTML
         Dashboard             (CI/CD)          Visual Report
```

### Key Components

1. **Git-Aware File Walker (`scanner/file_walker.py`)**: Traverses codebases while strictly respecting `.gitignore`, excluding vendor directories (`node_modules`, `venv`, etc.), and supporting a `--diff` mode for fast PR scanning.
2. **Pre-Filter Engine (`scanner/pre_filter.py` & `scanner/languages.py`)**: Uses targeted regex patterns to identify suspicious code lines before contacting the LLM. Clean files are skipped entirely, saving compute cycles and API tokens.
3. **Multi-Role AI Analyzer (`analyzer/ai_client.py` & `analyzer/prompts.py`)**: Crafts specialized role prompts for different vulnerability types (secrets, command/SQL injection, authentication, crypto weaknesses).
4. **OWASP Top 10 Mapping (`analyzer/owasp_mapper.py`)**: Categorizes all findings into the official OWASP Top 10 (2021) classification system with confidence ratings.
5. **Interactive Dark-Mode HTML Report (`reporter/html_report.py`)**: Generates an interactive, zero-dependency HTML dashboard complete with expandable findings and remediation advice.

---

## ⚡ Quick Demo & Usage

### 1. Installation
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/securescope.git
cd securescope
pip install -r requirements.txt
```

### 2. Run a full scan with HTML + JSON reports:
```bash
python cli.py --path ./my-project --output all --report-file audit_results
```

### 3. Run in 100% offline local mode with Ollama:
```bash
python cli.py --path ./my-project --provider ollama --model llama3
```

### 4. Run in CI/CD on git-changed files only:
```bash
python cli.py --path . --diff --output json
```

---

## ⚙️ CI/CD Integration (GitHub Actions)

SecureScope includes a ready-to-use GitHub Actions workflow (`.github/workflows/securescope.yml`) that can automatically audit pull requests, upload artifacts, and fail builds if `CRITICAL` severity issues are detected:

```yaml
- name: Run SecureScope
  env:
    GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
  run: |
    python cli.py --path . --output all --report-file securescope_report
```

---

## 🛠️ Built with OpenCode & Open Tools

This project was developed using **OpenCode**, an open-source terminal-based AI coding harness connecting to open-weight LLMs, demonstrating the power of developer workflows entirely powered by open-source tooling.

---

## 🔗 Links & Code

- **GitHub Repository**: [https://github.com/YOUR_GITHUB_USERNAME/securescope](https://github.com/YOUR_GITHUB_USERNAME/securescope)
- **License**: MIT License

---

*Feedback and contributions are welcome! Let me know in the comments how your team approaches local, privacy-preserving security scanning.*
