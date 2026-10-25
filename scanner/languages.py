"""
Language-specific regex patterns for pre-filtering.

Each language has a set of regex patterns grouped by vulnerability category.
These are used for the fast first-pass before AI analysis.
"""

import re

# ---------------------------------------------------------------------------
# Universal patterns (apply to ALL languages)
# ---------------------------------------------------------------------------

UNIVERSAL_PATTERNS = {
    "hardcoded_secret": [
        # Generic secret/password/token assignments
        re.compile(
            r"""(?:password|passwd|pwd|secret|api_?key|apikey|token|auth_?token|access_?key|private_?key|client_?secret)"""
            r"""\s*[=:]\s*['"][^'"]{8,}['"]""",
            re.IGNORECASE,
        ),
        # AWS keys
        re.compile(r"""AKIA[0-9A-Z]{16}"""),
        # Generic high-entropy strings assigned to suspicious variable names
        re.compile(
            r"""(?:SECRET|KEY|TOKEN|PASSWORD)\s*[=:]\s*['"][A-Za-z0-9+/=_\-]{20,}['"]""",
            re.IGNORECASE,
        ),
        # Private key blocks
        re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""),
        # Connection strings with credentials
        re.compile(
            r"""(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@]+@""",
            re.IGNORECASE,
        ),
    ],
    "hardcoded_ip": [
        # Internal/private IPs hardcoded
        re.compile(
            r"""(?:['"])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:['"])"""
        ),
    ],
    "weak_crypto": [
        re.compile(r"""\bmd5\b""", re.IGNORECASE),
        re.compile(r"""\bsha1\b""", re.IGNORECASE),
        re.compile(r"""\bDES\b"""),
        re.compile(r"""\bRC4\b""", re.IGNORECASE),
    ],
    "debug_enabled": [
        re.compile(r"""DEBUG\s*=\s*True""", re.IGNORECASE),
        re.compile(r"""debug\s*[=:]\s*true""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Python-specific patterns
# ---------------------------------------------------------------------------

PYTHON_PATTERNS = {
    "injection": [
        # SQL string formatting
        re.compile(r"""execute\s*\(\s*(?:f['"]|['"].*%s|['"].*\.format\()"""),
        # Command injection
        re.compile(r"""os\.system\s*\("""),
        re.compile(r"""subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True"""),
        re.compile(r"""eval\s*\("""),
        re.compile(r"""exec\s*\("""),
        re.compile(r"""__import__\s*\("""),
    ],
    "deserialization": [
        re.compile(r"""pickle\.loads?\s*\("""),
        re.compile(r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"""),
        re.compile(r"""marshal\.loads?\s*\("""),
        re.compile(r"""shelve\.open\s*\("""),
    ],
    "weak_crypto": [
        re.compile(r"""hashlib\.md5\s*\("""),
        re.compile(r"""hashlib\.sha1\s*\("""),
    ],
    "auth_issues": [
        re.compile(r"""verify\s*=\s*False"""),
        re.compile(r"""CSRF.*=.*False""", re.IGNORECASE),
        re.compile(r"""@csrf_exempt"""),
    ],
    "ssrf": [
        re.compile(r"""requests\.get\s*\(\s*(?:user|request|input|param)""", re.IGNORECASE),
        re.compile(r"""urllib\.request\.urlopen\s*\(\s*(?:user|request|input|param)""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# JavaScript / TypeScript patterns
# ---------------------------------------------------------------------------

JS_PATTERNS = {
    "injection": [
        # SQL injection
        re.compile(r"""\.query\s*\(\s*[`'"].*\$\{"""),
        re.compile(r"""\.query\s*\(\s*['"].*\+\s*(?:req|user|input|param)""", re.IGNORECASE),
        # eval
        re.compile(r"""\beval\s*\("""),
        # innerHTML XSS
        re.compile(r"""\.innerHTML\s*="""),
        # document.write
        re.compile(r"""document\.write\s*\("""),
    ],
    "auth_issues": [
        re.compile(r"""jwt\.(?:decode|verify)\s*\(.*(?:algorithms|options).*none""", re.IGNORECASE),
        re.compile(r"""(?:cookie|session).*(?:secure|httponly)\s*[=:]\s*false""", re.IGNORECASE),
    ],
    "deserialization": [
        re.compile(r"""JSON\.parse\s*\(\s*(?:req|user|input|body)""", re.IGNORECASE),
        re.compile(r"""\.deserialize\s*\("""),
    ],
    "ssrf": [
        re.compile(r"""fetch\s*\(\s*(?:req|user|input|param|url)""", re.IGNORECASE),
        re.compile(r"""axios\.get\s*\(\s*(?:req|user|input|param|url)""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Go patterns
# ---------------------------------------------------------------------------

GO_PATTERNS = {
    "injection": [
        re.compile(r"""fmt\.Sprintf\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE)""", re.IGNORECASE),
        re.compile(r"""exec\.Command\s*\("""),
    ],
    "weak_crypto": [
        re.compile(r"""crypto/md5"""),
        re.compile(r"""crypto/sha1"""),
        re.compile(r"""crypto/des"""),
    ],
    "auth_issues": [
        re.compile(r"""InsecureSkipVerify\s*:\s*true"""),
    ],
}

# ---------------------------------------------------------------------------
# Java patterns
# ---------------------------------------------------------------------------

JAVA_PATTERNS = {
    "injection": [
        re.compile(r"""Statement\s*.*\.execute(?:Query|Update)\s*\(.*\+"""),
        re.compile(r"""Runtime\.getRuntime\(\)\.exec\s*\("""),
        re.compile(r"""ProcessBuilder\s*\("""),
    ],
    "deserialization": [
        re.compile(r"""ObjectInputStream\s*\("""),
        re.compile(r"""readObject\s*\("""),
        re.compile(r"""XMLDecoder\s*\("""),
    ],
    "weak_crypto": [
        re.compile(r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)""", re.IGNORECASE),
        re.compile(r"""Cipher\.getInstance\s*\(\s*["']DES""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# PHP patterns
# ---------------------------------------------------------------------------

PHP_PATTERNS = {
    "injection": [
        re.compile(r"""mysql_query\s*\(.*\$"""),
        re.compile(r"""mysqli_query\s*\(.*\$"""),
        re.compile(r"""\beval\s*\(\s*\$"""),
        re.compile(r"""system\s*\(\s*\$"""),
        re.compile(r"""exec\s*\(\s*\$"""),
        re.compile(r"""passthru\s*\(\s*\$"""),
        re.compile(r"""shell_exec\s*\(\s*\$"""),
    ],
    "deserialization": [
        re.compile(r"""unserialize\s*\(\s*\$"""),
    ],
    "auth_issues": [
        re.compile(r"""extract\s*\(\s*\$_(GET|POST|REQUEST)"""),
    ],
}

# ---------------------------------------------------------------------------
# SQL patterns
# ---------------------------------------------------------------------------

SQL_PATTERNS = {
    "injection": [
        re.compile(r"""EXECUTE\s+IMMEDIATE""", re.IGNORECASE),
    ],
    "auth_issues": [
        re.compile(r"""GRANT\s+ALL""", re.IGNORECASE),
        re.compile(r"""IDENTIFIED\s+BY\s+['"]""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Config / YAML / env patterns
# ---------------------------------------------------------------------------

CONFIG_PATTERNS = {
    "hardcoded_secret": [
        re.compile(r"""(?:password|secret|key|token)\s*[=:]\s*\S+""", re.IGNORECASE),
    ],
    "debug_enabled": [
        re.compile(r"""(?:debug|verbose)\s*[=:]\s*(?:true|1|yes|on)""", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Mapping: language name → pattern dict
# ---------------------------------------------------------------------------

LANGUAGE_PATTERNS = {
    "Python": PYTHON_PATTERNS,
    "JavaScript": JS_PATTERNS,
    "JavaScript (React)": JS_PATTERNS,
    "TypeScript": JS_PATTERNS,
    "TypeScript (React)": JS_PATTERNS,
    "Go": GO_PATTERNS,
    "Java": JAVA_PATTERNS,
    "PHP": PHP_PATTERNS,
    "SQL": SQL_PATTERNS,
    "YAML": CONFIG_PATTERNS,
    "JSON": CONFIG_PATTERNS,
    "TOML": CONFIG_PATTERNS,
    "Config": CONFIG_PATTERNS,
    "Environment File": CONFIG_PATTERNS,
    "XML": CONFIG_PATTERNS,
    "Shell": PYTHON_PATTERNS,  # reuse injection patterns
    "PowerShell": PYTHON_PATTERNS,
    "Dockerfile": CONFIG_PATTERNS,
    "HTML": JS_PATTERNS,  # XSS patterns
    "Ruby": PYTHON_PATTERNS,
    "Rust": GO_PATTERNS,
    "C#": JAVA_PATTERNS,
    "C": GO_PATTERNS,
    "C++": GO_PATTERNS,
}
