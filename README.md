# 🔐 SecureScope

**AI-powered local code security scanner built on open-weight models.**

SecureScope scans your codebase for security vulnerabilities using open-source AI (Llama 3 via Groq / Ollama). Your source code **never leaves your machine** when using a local model. It maps findings to the OWASP Top 10, provides severity scores, and generates AI-powered fix suggestions.

> Built for [Hacktoberfest 2026 — Week 3: Open-Source AI Challenge](https://hacktoberfest.com)

---

## ✨ Features

- **Multi-language support** — Python, JavaScript, TypeScript, Go, Java, PHP
- **OWASP Top 10 mapping** — every finding maps to a real vulnerability category
- **AI-generated fix suggestions** — not just "here's the bug", but HOW to fix it
- **Severity scoring** — CRITICAL / HIGH / MEDIUM / LOW per finding
- **Beautiful HTML report** — shareable, visual, screenshot-worthy
- **Rich terminal output** — color-coded findings with progress bars
- **JSON export** — machine-readable output for automation
- **Git diff mode** — only scan changed files (CI/CD ready)
- **Regex pre-filter** — fast first pass before AI analysis (saves API calls)
- **Multi-role AI analysis** — separate specialized prompts for different vulnerability categories
- **GitHub Actions template** — drop-in CI/CD integration
- **Offline capable** — use Ollama for 100% local, air-gapped scanning

---

## 📁 Project Structure

```
securescope/
├── cli.py                      # Entry point — Rich CLI with argparse + progress bars
├── config.py                   # Model config, OWASP mappings, file type rules, severity levels
├── scanner/
│   ├── __init__.py
│   ├── file_walker.py          # Git-aware file traversal (respects .gitignore, supports --diff)
│   ├── pre_filter.py           # Regex-based pre-screening (fast pass for obvious issues)
│   └── languages.py            # Per-language file extensions and regex patterns
├── analyzer/
│   ├── __init__.py
│   ├── ai_client.py            # AI backend adapter (Groq API / Ollama local)
│   ├── prompts.py              # Specialized system prompts per vulnerability category
│   └── owasp_mapper.py         # Maps AI findings → OWASP Top 10 categories
├── reporter/
│   ├── __init__.py
│   ├── terminal.py             # Rich library terminal output (tables, colors, panels)
│   ├── html_report.py          # Generates standalone HTML report using Jinja2
│   └── json_export.py          # Exports findings as structured JSON
├── templates/
│   └── report.html             # Jinja2 HTML template for the visual report
├── .github/
│   └── workflows/
│       └── securescope.yml     # GitHub Actions workflow template
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup (pip installable)
├── .gitignore
├── LICENSE                     # MIT License
└── README.md                   # This file
```

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.10+ | Ecosystem, speed of development |
| AI Model | Llama 3 (70B/8B) | Open-weight, strong at code analysis |
| AI Provider | Groq (cloud) / Ollama (local) | Groq = fast + free tier; Ollama = 100% offline |
| CLI Framework | argparse + Rich | Beautiful terminal output, zero complexity |
| HTML Reports | Jinja2 | Simple templating for standalone HTML |
| Git Integration | subprocess (git CLI) | No extra deps, uses system git |

---

## 🔄 How It Works — Data Flow

```
1. CLI parses arguments (path, mode, output format)
         ↓
2. file_walker.py traverses the target directory
   - Respects .gitignore
   - In --diff mode, only picks git-changed files
   - Filters by supported language extensions
         ↓
3. pre_filter.py runs regex patterns on each file
   - Catches: hardcoded secrets, SQL strings, eval/exec, weak crypto, etc.
   - Extracts "suspicious snippets" (the code chunk + line numbers)
   - Files with zero regex hits are skipped (saves AI calls)
         ↓
4. ai_client.py sends snippets to the AI model
   - Uses 4 specialized roles (prompts.py):
     Role 1: Secret/credential leak detection
     Role 2: Injection flaws (SQL, command, XSS)
     Role 3: Authentication & session issues
     Role 4: Cryptography & hashing weaknesses
   - Each role analyzes only the relevant snippets
   - AI returns structured JSON with: vulnerability, severity, description, fix
         ↓
5. owasp_mapper.py maps each finding to OWASP Top 10 (2021)
   - A01:2021 Broken Access Control
   - A02:2021 Cryptographic Failures
   - A03:2021 Injection
   - ... etc.
         ↓
6. Reporter outputs results:
   - terminal.py  → Rich tables in the terminal
   - html_report.py → Standalone HTML file
   - json_export.py → findings.json
```

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/securescope.git
cd securescope

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic scan
```bash
python cli.py --path /path/to/your/project
```

### Scan with HTML report
```bash
python cli.py --path ./my-project --output html --report-file report.html
```

### Scan only git-changed files
```bash
python cli.py --path ./my-project --diff
```

### Use local Ollama instead of Groq
```bash
python cli.py --path ./my-project --provider ollama --model llama3
```

### JSON export for CI/CD
```bash
python cli.py --path ./my-project --output json --report-file findings.json
```

---

## 🔑 Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | Yes (if using Groq) | — | Free API key from [console.groq.com](https://console.groq.com) |
| `OLLAMA_HOST` | No | `http://localhost:11434` | Ollama server URL |

### CLI Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--path` | str | `.` | Path to scan |
| `--output` | str | `terminal` | Output format: `terminal`, `html`, `json`, `all` |
| `--report-file` | str | `securescope_report` | Output filename (without extension) |
| `--diff` | flag | `false` | Only scan git-changed files |
| `--provider` | str | `groq` | AI provider: `groq` or `ollama` |
| `--model` | str | `llama-3.1-8b-instant` | Model name to use |
| `--severity` | str | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--verbose` | flag | `false` | Show detailed processing info |

---

## 🗺️ OWASP Top 10 (2021) Coverage

| ID | Category | SecureScope Detection |
|----|----------|----------------------|
| A01 | Broken Access Control | Auth checks, role validation |
| A02 | Cryptographic Failures | Weak hashing, hardcoded keys, poor TLS |
| A03 | Injection | SQL, command, XSS, template injection |
| A04 | Insecure Design | Insecure defaults, missing validation |
| A05 | Security Misconfiguration | Debug modes, verbose errors, default creds |
| A06 | Vulnerable Components | Known risky imports/patterns |
| A07 | Auth Failures | Weak passwords, missing MFA hints |
| A08 | Data Integrity Failures | Deserialization, unsigned data |
| A09 | Logging Failures | Missing audit logs, sensitive data in logs |
| A10 | SSRF | Unvalidated URL fetching |

---

## 🧪 Testing

```bash
# Run on the included test fixtures
python cli.py --path ./tests/fixtures/vulnerable_app --output all
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- [Groq](https://groq.com) — Lightning-fast open-model inference
- [Ollama](https://ollama.ai) — Local LLM runtime
- [Meta Llama 3](https://llama.meta.com) — Open-weight foundation model
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Industry-standard vulnerability classification
- [Rich](https://github.com/Textualize/rich) — Beautiful terminal output
