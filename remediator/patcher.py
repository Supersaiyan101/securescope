"""
Auto-Remediation Patch Engine for SecureScope.

Transforms AI security recommendations into standard unified git patches
(e.g., `git apply securescope.patch`) or interactively applies remediation
directly to files with automatic safety backups.
"""

import os
import re
import shutil
from typing import Optional


# Heuristic rule-based remediation templates for common security flaws
REMEDIATION_RULES = [
    # 1. Hardcoded secret / token assignment (Python)
    (
        r"""^(\s*)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|AUTH)[A-Za-z0-9_]*)\s*=\s*['"][^'"]+['"]""",
        r"""\1\2 = os.environ.get("\2", "")  # [SecureScope] Extracted from hardcoded secret""",
    ),
    # 2. Hardcoded secret / token assignment (JavaScript)
    (
        r"""^(\s*(?:const|let|var)\s+)([A-Za-z0-9_]*(?:PASSWORD|SECRET|API_?KEY|TOKEN)[A-Za-z0-9_]*)\s*=\s*['"][^'"]+['"](?:\s*;?)""",
        r"""\1\2 = process.env.\2 || "";  // [SecureScope] Extracted from hardcoded secret""",
    ),
    # 3. Weak crypto: hashlib.md5 / sha1 -> hashlib.sha256
    (
        r"""hashlib\.(?:md5|sha1)\s*\(""",
        r"""hashlib.sha256(""",
    ),
    # 4. Insecure requests verify=False -> verify=True
    (
        r"""verify\s*=\s*False""",
        r"""verify=True""",
    ),
    # 5. Insecure debug mode -> False
    (
        r"""DEBUG\s*=\s*True""",
        r"""DEBUG = False""",
    ),
    (
        r"""debug\s*:\s*true""",
        r"""debug: false""",
    ),
    # 6. Unsafe YAML load -> safe_load
    (
        r"""yaml\.load\s*\(\s*([^,\)]+)\s*\)""",
        r"""yaml.safe_load(\1)""",
    ),
    # 7. Dangerous eval -> safe comment warning
    (
        r"""(\beval\s*\([^\)]+\))""",
        r"""/* [SecureScope CRITICAL] eval() removed for security */ null""",
    ),
    # 8. Insecure cookie flags in JS
    (
        r"""secure\s*:\s*false""",
        r"""secure: true""",
    ),
    (
        r"""httponly\s*:\s*false""",
        r"""httponly: true""",
    ),
]


def generate_remediation_line(original_line: str, language: str = "") -> Optional[str]:
    """
    Apply security remediation rules to a line of vulnerable code.

    Returns the remediated line, or None if no automatic rule matched.
    """
    for pattern, replacement in REMEDIATION_RULES:
        if re.search(pattern, original_line, re.IGNORECASE):
            new_line = re.sub(pattern, replacement, original_line, flags=re.IGNORECASE)
            if new_line != original_line:
                return new_line
    return None


def generate_unified_patch(
    findings: list,
    target_path: str,
    output_patch_file: str = "securescope.patch",
) -> tuple[str, int]:
    """
    Generate a unified git diff patch file for all remediable findings.

    Args:
        findings: List of Finding objects.
        target_path: Root scan directory.
        output_patch_file: Path to write the patch file.

    Returns:
        tuple (patch_file_path, count_of_patches)
    """
    # Group findings by relative file path
    files_to_patch = {}
    for f in findings:
        if not f.file_path or not f.line_number:
            continue
        files_to_patch.setdefault(f.file_path, []).append(f)

    patch_chunks = []
    total_remediated = 0

    for file_path, file_findings in files_to_patch.items():
        if not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                lines = fp.readlines()
        except Exception:
            continue

        rel_path = os.path.relpath(file_path, target_path).replace("\\", "/")
        file_chunks = []

        # Sort findings by line number descending so line offsets stay valid
        file_findings.sort(key=lambda x: x.line_number, reverse=True)

        for f in file_findings:
            line_idx = f.line_number - 1
            if line_idx < 0 or line_idx >= len(lines):
                continue

            orig_line = lines[line_idx]
            fixed_line = generate_remediation_line(orig_line, f.language)

            if not fixed_line:
                # If no pattern matched, provide a safe inline comment fix
                indent = re.match(r"^\s*", orig_line).group(0)
                comment_prefix = "#" if f.language.lower() in ("python", "ruby", "shell", "yaml") else "//"
                fixed_line = f"{orig_line.rstrip()}\n{indent}{comment_prefix} [SecureScope Advisory]: {f.fix_suggestion[:100]}\n"

            # Create unified diff chunk
            chunk = (
                f"@@ -{f.line_number},1 +{f.line_number},1 @@\n"
                f"-{orig_line.rstrip()}\n"
                f"+{fixed_line.rstrip()}\n"
            )
            file_chunks.append(chunk)
            total_remediated += 1

        if file_chunks:
            file_header = (
                f"--- a/{rel_path}\n"
                f"+++ b/{rel_path}\n"
            )
            patch_chunks.append(file_header + "".join(file_chunks))

    if patch_chunks:
        with open(output_patch_file, "w", encoding="utf-8") as fp:
            fp.write("".join(patch_chunks))
        return output_patch_file, total_remediated

    return output_patch_file, 0


def apply_patch_directly(
    findings: list,
    target_path: str,
    create_backup: bool = True,
) -> int:
    """
    Directly apply automated remediation to files on disk.

    Args:
        findings: List of Finding objects.
        target_path: Root scan directory.
        create_backup: Whether to create .bak files before editing.

    Returns:
        Total number of lines remediated.
    """
    files_to_patch = {}
    for f in findings:
        if not f.file_path or not f.line_number:
            continue
        files_to_patch.setdefault(f.file_path, []).append(f)

    total_patched = 0

    for file_path, file_findings in files_to_patch.items():
        if not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                lines = fp.readlines()
        except Exception:
            continue

        if create_backup:
            backup_path = file_path + ".bak"
            shutil.copyfile(file_path, backup_path)

        modified = False
        for f in file_findings:
            line_idx = f.line_number - 1
            if 0 <= line_idx < len(lines):
                orig_line = lines[line_idx]
                remediated = generate_remediation_line(orig_line, f.language)
                if remediated and remediated != orig_line:
                    lines[line_idx] = remediated if remediated.endswith("\n") else remediated + "\n"
                    modified = True
                    total_patched += 1

        if modified:
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.writelines(lines)

    return total_patched
