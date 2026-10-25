"""
Pre-filter — Regex-based fast pass.

Scans files using language-specific regex patterns to extract
suspicious code snippets before sending them to the AI for
deeper analysis. This saves API calls by skipping clean files.
"""

from dataclasses import dataclass, field
from config import MAX_SNIPPET_CHARS
from scanner.languages import UNIVERSAL_PATTERNS, LANGUAGE_PATTERNS


@dataclass
class Snippet:
    """A suspicious code snippet extracted by the pre-filter."""

    file_path: str
    relative_path: str
    language: str
    category: str         # e.g., "injection", "hardcoded_secret"
    line_number: int
    line_content: str
    context: str           # surrounding lines for AI context
    pattern_name: str      # which pattern matched


@dataclass
class PreFilterResult:
    """Result of pre-filtering a single file."""

    file_path: str
    relative_path: str
    language: str
    snippets: list[Snippet] = field(default_factory=list)
    total_lines: int = 0
    scanned: bool = True
    error: str | None = None


def _extract_context(lines: list[str], line_idx: int, context_window: int = 5) -> str:
    """
    Extract surrounding lines around the matched line for AI context.

    Args:
        lines: All lines in the file.
        line_idx: Index of the matched line (0-based).
        context_window: Number of lines before and after to include.

    Returns:
        String of surrounding code with line numbers.
    """
    start = max(0, line_idx - context_window)
    end = min(len(lines), line_idx + context_window + 1)

    context_lines = []
    for i in range(start, end):
        marker = ">>>" if i == line_idx else "   "
        context_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")

    context = "\n".join(context_lines)

    # Truncate if too long
    if len(context) > MAX_SNIPPET_CHARS:
        context = context[:MAX_SNIPPET_CHARS] + "\n... (truncated)"

    return context


def pre_filter_file(file_info: dict) -> PreFilterResult:
    """
    Run regex pre-filtering on a single file.

    Args:
        file_info: Dict with keys: path, relative_path, language, size.

    Returns:
        PreFilterResult with extracted snippets.
    """
    result = PreFilterResult(
        file_path=file_info["path"],
        relative_path=file_info["relative_path"],
        language=file_info["language"],
    )

    try:
        with open(file_info["path"], "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError) as e:
        result.scanned = False
        result.error = str(e)
        return result

    lines = content.splitlines()
    result.total_lines = len(lines)

    # Collect all patterns to run: universal + language-specific
    patterns_to_run: dict[str, list] = {}

    # Add universal patterns
    for category, pattern_list in UNIVERSAL_PATTERNS.items():
        patterns_to_run.setdefault(category, []).extend(pattern_list)

    # Add language-specific patterns
    lang_patterns = LANGUAGE_PATTERNS.get(file_info["language"], {})
    for category, pattern_list in lang_patterns.items():
        patterns_to_run.setdefault(category, []).extend(pattern_list)

    # Track which lines already matched (avoid duplicate snippets)
    matched_lines: set[int] = set()

    for category, pattern_list in patterns_to_run.items():
        for pattern in pattern_list:
            for line_idx, line in enumerate(lines):
                if line_idx in matched_lines:
                    continue

                match = pattern.search(line)
                if match:
                    matched_lines.add(line_idx)
                    snippet = Snippet(
                        file_path=file_info["path"],
                        relative_path=file_info["relative_path"],
                        language=file_info["language"],
                        category=category,
                        line_number=line_idx + 1,  # 1-based
                        line_content=line.strip(),
                        context=_extract_context(lines, line_idx),
                        pattern_name=pattern.pattern[:60],
                    )
                    result.snippets.append(snippet)

    return result


def pre_filter_files(file_list: list[dict]) -> list[PreFilterResult]:
    """
    Run pre-filtering on a list of files.

    Args:
        file_list: List of file info dicts from file_walker.walk_files().

    Returns:
        List of PreFilterResult, including only files that had matches.
    """
    results = []
    for file_info in file_list:
        result = pre_filter_file(file_info)
        if result.snippets or result.error:
            results.append(result)
    return results
