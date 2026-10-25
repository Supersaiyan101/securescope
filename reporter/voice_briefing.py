"""
ElevenLabs Audio Security Briefing Generator.

Converts SecureScope scan results into a spoken executive security briefing
using the ElevenLabs Text-to-Speech API. Produces both an audio file (.mp3)
and an executive audio transcript (.txt).
"""

import json
import os
import urllib.request
import urllib.error
from typing import Optional

from config import ELEVENLABS_API_KEY, ELEVENLABS_VOICE_ID


def generate_briefing_script(findings: list, total_files: int, scan_time: float) -> str:
    """Compose the executive spoken briefing text from findings."""
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if getattr(f, "severity", "") == "CRITICAL")
    high_count = sum(1 for f in findings if getattr(f, "severity", "") == "HIGH")

    if total_findings == 0:
        return (
            f"Hello. This is your SecureScope security audit briefing. "
            f"We completed scanning {total_files} files across your repository in {scan_time:.1f} seconds. "
            f"All security checks passed with zero vulnerabilities detected. Your codebase is clean and ready for deployment."
        )

    top_issues = [getattr(f, "vulnerability", "") for f in findings[:2]]
    issues_summary = " and ".join(top_issues) if top_issues else "detected security flaws"

    script = (
        f"Attention security team. This is your SecureScope automated security audit briefing. "
        f"We scanned {total_files} files in {scan_time:.1f} seconds, identifying {total_findings} security concerns. "
    )

    if critical_count > 0:
        script += (
            f"Alert: {critical_count} critical severity vulnerabilities require immediate attention, "
            f"specifically involving {issues_summary}. "
        )
    elif high_count > 0:
        script += (
            f"Warning: {high_count} high severity issues were detected, including {issues_summary}. "
        )
    else:
        script += (
            f"Notice: {total_findings} medium or low severity issues were identified. "
        )

    script += (
        "AI-suggested remediation code and OWASP Top 10 mappings have been compiled in your SecureScope HTML report. "
        "Please review the dashboard and apply the recommended fixes before merging."
    )
    return script


def generate_voice_briefing(
    findings: list,
    total_files: int,
    scan_time: float,
    output_audio_path: str = "securescope_briefing.mp3",
    api_key: Optional[str] = None,
    voice_id: Optional[str] = None,
) -> tuple[Optional[str], str]:
    """
    Generate an ElevenLabs MP3 voice briefing and a transcript file.

    Returns:
        tuple (mp3_file_path_or_none, transcript_text)
    """
    api_key = api_key or ELEVENLABS_API_KEY
    voice_id = voice_id or ELEVENLABS_VOICE_ID

    transcript = generate_briefing_script(findings, total_files, scan_time)

    # Always save the transcript
    transcript_path = os.path.splitext(output_audio_path)[0] + "_transcript.txt"
    with open(transcript_path, "w", encoding="utf-8") as f:
        f.write(transcript)

    if not api_key:
        return None, transcript

    url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": api_key,
    }
    payload = json.dumps({
        "text": transcript,
        "model_id": "eleven_monolingual_v1",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            audio_data = response.read()
            with open(output_audio_path, "wb") as f:
                f.write(audio_data)
            return output_audio_path, transcript
    except Exception:
        # Fall back gracefully to transcript
        return None, transcript
