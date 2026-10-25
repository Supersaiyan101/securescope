"""
AI Client — Backend adapter for Groq API and Ollama.

Sends code snippets to the AI model with specialized prompts,
parses the structured JSON response, and returns findings.
Supports both Groq (cloud, free tier) and Ollama (local, offline).
"""

import json
import os
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from analyzer.prompts import CATEGORY_PROMPTS, COMBINED_PROMPT
from analyzer.owasp_mapper import map_findings
from scanner.pre_filter import Snippet

# Threshold: if total snippets <= this number, use single combined prompt
COMBINED_THRESHOLD = 5


@dataclass
class Finding:
    """A security finding from AI analysis."""

    vulnerability: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    fix_suggestion: str = ""
    owasp_id: str = "N/A"
    owasp_name: str = "Uncategorized"
    owasp_hint: str = ""
    line_number: int | None = None
    confidence: str = "MEDIUM"
    file_path: str = ""
    relative_path: str = ""
    language: str = ""
    category: str = ""
    cve_references: list = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Result of analyzing all snippets."""

    findings: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    snippets_analyzed: int = 0
    ai_calls_made: int = 0
    errors: list[str] = field(default_factory=list)


def _call_groq(
    system_prompt: str,
    user_message: str,
    model: str,
    api_key: str,
) -> str:
    """Call the Groq API and return the response text."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.1,
        "max_tokens": 2048,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Groq API error {e.code}: {error_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Groq API connection error: {e.reason}") from e


def _call_ollama(
    system_prompt: str,
    user_message: str,
    model: str,
    host: str,
) -> str:
    """Call the Ollama local API and return the response text."""
    url = f"{host.rstrip('/')}/api/chat"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_predict": 2048,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Ollama API error {e.code}: {error_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama connection error: {e.reason}") from e


def _parse_ai_response(response_text: str) -> list[dict]:
    """
    Parse the AI response text into a list of finding dicts.

    Handles cases where the AI returns:
    - A JSON array directly: [...]
    - A JSON object with a key containing the array: {"findings": [...]}
    - Text with embedded JSON
    """
    text = response_text.strip()

    # Try direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            # Look for a list value in the dict
            for value in parsed.values():
                if isinstance(value, list):
                    return value
            return []
    except json.JSONDecodeError:
        pass

    # Try to extract JSON array from text
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return []


def _build_user_message(snippets: list[Snippet]) -> str:
    """Build the user message from a list of code snippets."""
    parts = []
    for snippet in snippets:
        parts.append(
            f"--- File: {snippet.relative_path} (line {snippet.line_number}, {snippet.language}) ---\n"
            f"Pre-filter category: {snippet.category}\n"
            f"Matched line: {snippet.line_content}\n\n"
            f"Code context:\n{snippet.context}\n"
        )
    return "\n".join(parts)


def _group_snippets_by_category(snippets: list[Snippet]) -> dict[str, list[Snippet]]:
    """Group snippets by their pre-filter category."""
    groups: dict[str, list[Snippet]] = {}
    for snippet in snippets:
        groups.setdefault(snippet.category, []).append(snippet)
    return groups


def analyze_snippets(
    snippets: list[Snippet],
    provider: str = "groq",
    model: str | None = None,
    api_key: str | None = None,
    ollama_host: str | None = None,
    on_progress: callable = None,
) -> AnalysisResult:
    """
    Analyze code snippets using the AI model.

    Args:
        snippets: List of Snippet objects from the pre-filter.
        provider: "groq" or "ollama".
        model: Model name (uses defaults from config if None).
        api_key: Groq API key (reads from env if None).
        ollama_host: Ollama server URL (reads from env if None).
        on_progress: Optional callback(message: str) for progress updates.

    Returns:
        AnalysisResult with all findings.
    """
    from config import GROQ_API_KEY, GROQ_DEFAULT_MODEL, OLLAMA_HOST, OLLAMA_DEFAULT_MODEL

    result = AnalysisResult()

    if not snippets:
        return result

    # Resolve config
    if provider == "groq":
        api_key = api_key or GROQ_API_KEY
        if not api_key:
            result.errors.append(
                "GROQ_API_KEY not set. Get a free key at https://console.groq.com"
            )
            return result
        model = model or GROQ_DEFAULT_MODEL
    else:
        ollama_host = ollama_host or OLLAMA_HOST
        model = model or OLLAMA_DEFAULT_MODEL

    # Track unique files
    unique_files = {s.relative_path for s in snippets}
    result.files_analyzed = len(unique_files)
    result.snippets_analyzed = len(snippets)

    def call_ai(system_prompt: str, user_message: str) -> str:
        """Route to the correct AI provider."""
        if provider == "groq":
            return _call_groq(system_prompt, user_message, model, api_key)
        else:
            return _call_ollama(system_prompt, user_message, model, ollama_host)

    # Decide: combined or multi-role approach
    if len(snippets) <= COMBINED_THRESHOLD:
        # Single combined analysis
        if on_progress:
            on_progress(f"Analyzing {len(snippets)} snippets with combined prompt...")

        user_msg = _build_user_message(snippets)
        try:
            response = call_ai(COMBINED_PROMPT, user_msg)
            result.ai_calls_made += 1
            raw_findings = _parse_ai_response(response)

            # Enrich findings with file info
            for raw in raw_findings:
                finding = Finding(
                    vulnerability=raw.get("vulnerability", "Unknown"),
                    severity=raw.get("severity", "MEDIUM").upper(),
                    description=raw.get("description", ""),
                    fix_suggestion=raw.get("fix_suggestion", ""),
                    owasp_hint=raw.get("owasp_hint", ""),
                    line_number=raw.get("line_number"),
                    confidence=raw.get("confidence", "MEDIUM").upper(),
                    category="combined",
                )
                # Try to match finding to a specific file
                if finding.line_number:
                    for s in snippets:
                        if s.line_number == finding.line_number:
                            finding.file_path = s.file_path
                            finding.relative_path = s.relative_path
                            finding.language = s.language
                            break
                if not finding.relative_path and snippets:
                    finding.relative_path = snippets[0].relative_path
                    finding.file_path = snippets[0].file_path
                    finding.language = snippets[0].language

                result.findings.append(finding)

        except RuntimeError as e:
            result.errors.append(str(e))

    else:
        # Multi-role analysis by category
        groups = _group_snippets_by_category(snippets)
        for category, cat_snippets in groups.items():
            prompt = CATEGORY_PROMPTS.get(category, COMBINED_PROMPT)

            if on_progress:
                on_progress(
                    f"Analyzing {len(cat_snippets)} '{category}' snippets..."
                )

            user_msg = _build_user_message(cat_snippets)
            try:
                response = call_ai(prompt, user_msg)
                result.ai_calls_made += 1
                raw_findings = _parse_ai_response(response)

                for raw in raw_findings:
                    finding = Finding(
                        vulnerability=raw.get("vulnerability", "Unknown"),
                        severity=raw.get("severity", "MEDIUM").upper(),
                        description=raw.get("description", ""),
                        fix_suggestion=raw.get("fix_suggestion", ""),
                        owasp_hint=raw.get("owasp_hint", ""),
                        line_number=raw.get("line_number"),
                        confidence=raw.get("confidence", "MEDIUM").upper(),
                        category=category,
                    )
                    # Match to specific file via line number
                    if finding.line_number:
                        for s in cat_snippets:
                            if s.line_number == finding.line_number:
                                finding.file_path = s.file_path
                                finding.relative_path = s.relative_path
                                finding.language = s.language
                                break
                    if not finding.relative_path and cat_snippets:
                        finding.relative_path = cat_snippets[0].relative_path
                        finding.file_path = cat_snippets[0].file_path
                        finding.language = cat_snippets[0].language

                    result.findings.append(finding)

            except RuntimeError as e:
                result.errors.append(f"[{category}] {e}")

    # Map all findings to OWASP
    if result.findings:
        finding_dicts = [
            {
                "vulnerability": f.vulnerability,
                "severity": f.severity,
                "description": f.description,
                "fix_suggestion": f.fix_suggestion,
                "owasp_hint": f.owasp_hint,
                "line_number": f.line_number,
                "confidence": f.confidence,
            }
            for f in result.findings
        ]
        mapped = map_findings(finding_dicts)
        for finding, mapped_dict in zip(result.findings, mapped):
            finding.owasp_id = mapped_dict.get("owasp_id", "N/A")
            finding.owasp_name = mapped_dict.get("owasp_name", "Uncategorized")

    # Sort by severity (critical first)
    from config import SEVERITY_ORDER
    result.findings.sort(
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    return result
