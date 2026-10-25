"""
SecureScope Configuration

Central configuration for AI providers, OWASP mappings,
severity levels, and file type rules.
"""

import os

# ---------------------------------------------------------------------------
# AI Provider Settings
# ---------------------------------------------------------------------------

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_DEFAULT_MODEL = "llama-3.1-8b-instant"

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_DEFAULT_MODEL = "llama3"

# Max tokens per AI request
MAX_TOKENS = 2048

# Max characters per code snippet sent to AI
MAX_SNIPPET_CHARS = 3000

# ---------------------------------------------------------------------------
# Severity Levels (ordered)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) Mapping
# ---------------------------------------------------------------------------

OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "keywords": [
            "access control", "authorization", "privilege", "role",
            "permission", "idor", "path traversal", "directory traversal",
        ],
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "keywords": [
            "crypto", "encrypt", "hash", "md5", "sha1", "base64",
            "password", "secret", "key", "tls", "ssl", "certificate",
        ],
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "keywords": [
            "injection", "sql", "command", "xss", "cross-site",
            "template", "ldap", "xpath", "eval", "exec", "os.system",
            "subprocess", "shell", "sanitize", "escape",
        ],
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "keywords": [
            "insecure design", "validation", "default", "trust boundary",
            "business logic",
        ],
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "keywords": [
            "debug", "verbose error", "default credential", "default password",
            "stack trace", "misconfiguration", "cors", "header",
        ],
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "keywords": [
            "vulnerable", "outdated", "dependency", "cve", "version",
            "known vulnerability",
        ],
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "keywords": [
            "authentication", "login", "session", "token", "jwt",
            "brute force", "credential", "mfa", "2fa", "password policy",
        ],
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "keywords": [
            "deserialization", "pickle", "yaml.load", "integrity",
            "unsigned", "ci/cd", "pipeline",
        ],
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "keywords": [
            "logging", "audit", "monitor", "sensitive data in log",
            "log injection",
        ],
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "keywords": [
            "ssrf", "url", "fetch", "request", "redirect",
            "internal network", "metadata",
        ],
    },
}

# ---------------------------------------------------------------------------
# Supported Languages — extension → language name
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".go": "Go",
    ".java": "Java",
    ".php": "PHP",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".cs": "C#",
    ".c": "C",
    ".cpp": "C++",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".env": "Environment File",
    ".toml": "TOML",
    ".cfg": "Config",
    ".ini": "Config",
    ".xml": "XML",
    ".html": "HTML",
    ".sql": "SQL",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".dockerfile": "Dockerfile",
}

# Files that are always scanned regardless of extension
ALWAYS_SCAN_FILENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".htaccess",
    "nginx.conf",
}

# Directories to always skip
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".next", ".nuxt", "vendor", "target",
    ".idea", ".vscode", "coverage", ".coverage",
}

# Max file size to scan (bytes) — skip very large files
MAX_FILE_SIZE = 500_000  # 500 KB
