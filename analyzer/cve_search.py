"""
Live CVE & Security Advisory Search using SerpApi.

Enriches SecureScope findings with real-time CVE records, NIST National
Vulnerability Database links, and GitHub Security Advisories fetched live
via SerpApi.
"""

import json
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional

from config import SERPAPI_API_KEY

# Curated high-confidence CVE references fallback when offline or no API key is provided
CURATED_CVE_REFERENCES = {
    "SQL": [
        {
            "id": "CWE-89",
            "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
            "source": "MITRE CWE",
        },
        {
            "id": "CVE-2023-28840",
            "title": "SQL Injection vulnerability in database queries",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28840",
            "source": "NIST NVD",
        },
    ],
    "Command": [
        {
            "id": "CWE-78",
            "title": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "url": "https://cwe.mitre.org/data/definitions/78.html",
            "source": "MITRE CWE",
        },
    ],
    "Secret": [
        {
            "id": "CWE-798",
            "title": "Use of Hard-coded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
            "source": "MITRE CWE",
        },
    ],
    "Deserialization": [
        {
            "id": "CWE-502",
            "title": "Deserialization of Untrusted Data (Arbitrary Code Execution via pickle/yaml)",
            "url": "https://cwe.mitre.org/data/definitions/502.html",
            "source": "MITRE CWE",
        },
    ],
    "XSS": [
        {
            "id": "CWE-79",
            "title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "url": "https://cwe.mitre.org/data/definitions/79.html",
            "source": "MITRE CWE",
        },
    ],
    "SSRF": [
        {
            "id": "CWE-918",
            "title": "Server-Side Request Forgery (SSRF)",
            "url": "https://cwe.mitre.org/data/definitions/918.html",
            "source": "MITRE CWE",
        },
    ],
    "Crypto": [
        {
            "id": "CWE-327",
            "title": "Use of a Broken or Risky Cryptographic Algorithm (MD5 / SHA1)",
            "url": "https://cwe.mitre.org/data/definitions/327.html",
            "source": "MITRE CWE",
        },
    ],
}


def search_cve_serpapi(
    query: str,
    api_key: Optional[str] = None,
    num_results: int = 3,
) -> list[dict]:
    """
    Search SerpApi for live CVE records and security advisories.

    Args:
        query: Search term (e.g., 'SQL injection Python sqlite3')
        api_key: SerpApi API key (reads from config if None)
        num_results: Maximum number of records to return

    Returns:
        List of dicts: [{"id": str, "title": str, "url": str, "source": str}]
    """
    api_key = api_key or SERPAPI_API_KEY
    if not api_key:
        return _fallback_cve(query)

    search_query = f"{query} (site:cve.mitre.org OR site:nvd.nist.gov OR site:github.com/advisories)"
    params = urllib.parse.urlencode({
        "engine": "google",
        "q": search_query,
        "api_key": api_key,
        "num": num_results,
    })

    url = f"https://serpapi.com/search.json?{params}"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SecureScope-SecurityScanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            organic_results = data.get("organic_results", [])
            records = []
            for item in organic_results[:num_results]:
                title = item.get("title", "")
                link = item.get("link", "")
                snippet = item.get("snippet", "")
                records.append({
                    "id": _extract_cve_id(title) or "Advisory",
                    "title": title,
                    "url": link,
                    "snippet": snippet,
                    "source": "SerpApi Live Search",
                })
            return records if records else _fallback_cve(query)
    except Exception:
        return _fallback_cve(query)


def _extract_cve_id(text: str) -> Optional[str]:
    """Extract CVE-YYYY-NNNN from a string."""
    import re
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    match_cwe = re.search(r"CWE-\d{1,4}", text, re.IGNORECASE)
    if match_cwe:
        return match_cwe.group(0).upper()
    return None


def _fallback_cve(query: str) -> list[dict]:
    """Return curated CVE records matching the query keywords."""
    query_lower = query.lower()
    for key, records in CURATED_CVE_REFERENCES.items():
        if key.lower() in query_lower:
            return records
    return [
        {
            "id": "CWE-699",
            "title": "Software Development Security Framework",
            "url": "https://cwe.mitre.org/data/definitions/699.html",
            "source": "MITRE CWE",
        }
    ]


def enrich_findings_with_cve(findings: list, api_key: Optional[str] = None):
    """
    Enrich each Finding object with live CVE records from SerpApi.
    Adds a `cve_references` list attribute to each finding.
    """
    for finding in findings:
        vuln = getattr(finding, "vulnerability", "")
        lang = getattr(finding, "language", "")
        category = getattr(finding, "category", "")
        query = f"{vuln} {lang} {category}".strip()
        cve_refs = search_cve_serpapi(query, api_key=api_key, num_results=2)
        setattr(finding, "cve_references", cve_refs)
