"""
OWASP Mapper — Maps AI findings to OWASP Top 10 (2021) categories.

Uses keyword matching from the AI's owasp_hint field and the finding's
description to assign the correct OWASP category.
"""

from config import OWASP_TOP_10


def map_to_owasp(finding: dict) -> dict:
    """
    Map a single AI finding to the most relevant OWASP Top 10 category.

    The function checks (in order):
    1. The AI's own owasp_hint field (if it contains a valid OWASP ID)
    2. Keyword matching against the finding's vulnerability name + description

    Args:
        finding: A dict with keys from the AI response (vulnerability,
                 severity, description, fix_suggestion, owasp_hint, etc.)

    Returns:
        The finding dict with added 'owasp_id' and 'owasp_name' fields.
    """
    result = dict(finding)

    # 1. Try the AI's own hint first
    hint = finding.get("owasp_hint", "")
    if hint:
        for key, owasp in OWASP_TOP_10.items():
            if key in hint or owasp["id"] in hint:
                result["owasp_id"] = owasp["id"]
                result["owasp_name"] = owasp["name"]
                return result

    # 2. Fall back to keyword matching
    search_text = (
        finding.get("vulnerability", "")
        + " "
        + finding.get("description", "")
    ).lower()

    best_match = None
    best_score = 0

    for _key, owasp in OWASP_TOP_10.items():
        score = sum(1 for kw in owasp["keywords"] if kw in search_text)
        if score > best_score:
            best_score = score
            best_match = owasp

    if best_match and best_score > 0:
        result["owasp_id"] = best_match["id"]
        result["owasp_name"] = best_match["name"]
    else:
        result["owasp_id"] = "N/A"
        result["owasp_name"] = "Uncategorized"

    return result


def map_findings(findings: list[dict]) -> list[dict]:
    """
    Map a list of AI findings to OWASP Top 10 categories.

    Args:
        findings: List of finding dicts from the AI.

    Returns:
        Same list with OWASP mapping fields added to each finding.
    """
    return [map_to_owasp(f) for f in findings]
