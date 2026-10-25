"""
File Walker — Git-aware file traversal.

Walks the target directory, respects .gitignore via `git ls-files`,
supports --diff mode to only pick changed files, and filters
by supported language extensions.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from config import (
    SUPPORTED_EXTENSIONS,
    ALWAYS_SCAN_FILENAMES,
    SKIP_DIRS,
    MAX_FILE_SIZE,
)


def _is_git_repo(path: str) -> bool:
    """Check if the given path is inside a git repository."""
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            capture_output=True,
            text=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _git_tracked_files(path: str) -> Optional[list[str]]:
    """Get list of git-tracked files (respects .gitignore)."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=path,
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _git_changed_files(path: str) -> Optional[list[str]]:
    """Get list of files changed in git (staged + unstaged + untracked)."""
    try:
        # Get staged and unstaged changes
        diff_result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
        )
        # Get untracked files
        untracked_result = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=path,
            capture_output=True,
            text=True,
        )

        changed = set()
        if diff_result.returncode == 0:
            changed.update(
                line.strip()
                for line in diff_result.stdout.splitlines()
                if line.strip()
            )
        if untracked_result.returncode == 0:
            changed.update(
                line.strip()
                for line in untracked_result.stdout.splitlines()
                if line.strip()
            )
        return list(changed) if changed else []
    except FileNotFoundError:
        return None


def _should_skip_dir(dirname: str) -> bool:
    """Check if a directory should be skipped."""
    return dirname in SKIP_DIRS or dirname.startswith(".")


def _is_supported_file(filepath: str) -> bool:
    """Check if a file has a supported extension or is a known config file."""
    basename = os.path.basename(filepath)
    if basename in ALWAYS_SCAN_FILENAMES:
        return True
    _, ext = os.path.splitext(filepath)
    return ext.lower() in SUPPORTED_EXTENSIONS


def _get_language(filepath: str) -> str:
    """Get the language name for a file based on its extension."""
    basename = os.path.basename(filepath)
    if basename in ALWAYS_SCAN_FILENAMES:
        if basename.endswith((".yml", ".yaml")):
            return "YAML"
        if basename.startswith(".env"):
            return "Environment File"
        if basename in ("Dockerfile",):
            return "Dockerfile"
        if basename in (".htaccess", "nginx.conf"):
            return "Config"
        return "Config"
    _, ext = os.path.splitext(filepath)
    return SUPPORTED_EXTENSIONS.get(ext.lower(), "Unknown")


def walk_files(
    target_path: str,
    diff_only: bool = False,
) -> list[dict]:
    """
    Walk the target directory and return a list of files to scan.

    Each item in the returned list is a dict:
        {
            "path": str,           # absolute path to the file
            "relative_path": str,  # path relative to target_path
            "language": str,       # detected language name
            "size": int,           # file size in bytes
        }

    Args:
        target_path: Root directory to scan.
        diff_only: If True, only return git-changed files.

    Returns:
        List of file info dicts.
    """
    target_path = os.path.abspath(target_path)

    if not os.path.isdir(target_path):
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    is_git = _is_git_repo(target_path)
    results = []

    # Determine the file list based on mode
    if diff_only and is_git:
        relative_files = _git_changed_files(target_path)
        if relative_files is None:
            relative_files = []
    elif is_git:
        relative_files = _git_tracked_files(target_path)
        if relative_files is None:
            # Fallback to manual walk if git command fails
            relative_files = None
    else:
        relative_files = None

    if relative_files is not None:
        # Use the git-provided file list
        for rel_path in relative_files:
            abs_path = os.path.join(target_path, rel_path)
            if not os.path.isfile(abs_path):
                continue
            if not _is_supported_file(rel_path):
                continue
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            if size > MAX_FILE_SIZE:
                continue
            results.append({
                "path": abs_path,
                "relative_path": rel_path,
                "language": _get_language(rel_path),
                "size": size,
            })
    else:
        # Manual directory walk (non-git or fallback)
        for root, dirs, files in os.walk(target_path):
            # Filter out skippable directories in-place
            dirs[:] = [d for d in dirs if not _should_skip_dir(d)]

            for filename in files:
                abs_path = os.path.join(root, filename)
                rel_path = os.path.relpath(abs_path, target_path)

                if not _is_supported_file(filename):
                    continue
                try:
                    size = os.path.getsize(abs_path)
                except OSError:
                    continue
                if size > MAX_FILE_SIZE:
                    continue

                results.append({
                    "path": abs_path,
                    "relative_path": rel_path,
                    "language": _get_language(filename),
                    "size": size,
                })

    # Sort by path for consistent output
    results.sort(key=lambda f: f["relative_path"])
    return results
