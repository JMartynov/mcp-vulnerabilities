#!/usr/bin/env python3
"""
Bumps semantic version of mcp-vulnerabilities incrementally (patch, minor, or major)
and synchronizes pyproject.toml and src/mcp_vulnerabilities/__init__.py.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from packaging.version import Version, parse as parse_version


def get_current_version(pyproject_path: Path | str = "pyproject.toml") -> str:
    path = Path(pyproject_path)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found.")

    content = path.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        raise ValueError(f"Could not find version pattern in {path}")
    return match.group(1)


def bump_version(current_version: str, part: str = "patch") -> str:
    v = parse_version(current_version)
    if not isinstance(v, Version) or not v.release:
        raise ValueError(f"Invalid semantic version: {current_version}")

    major = v.release[0]
    minor = v.release[1] if len(v.release) > 1 else 0
    patch = v.release[2] if len(v.release) > 2 else 0

    clean_part = part.strip().lower()
    if clean_part in ("patch", "data"):
        patch += 1
    elif clean_part in ("minor", "feature"):
        minor += 1
        patch = 0
    elif clean_part in ("major", "breaking"):
        major += 1
        minor = 0
        patch = 0
    else:
        raise ValueError(f"Unknown bump type: {part}. Expected 'patch', 'minor', or 'major'.")

    return f"{major}.{minor}.{patch}"


def update_version_in_files(
    new_version: str,
    pyproject_path: Path | str = "pyproject.toml",
    init_path: Path | str = "src/mcp_vulnerabilities/__init__.py",
) -> None:
    # 1. Update pyproject.toml
    pyproject_p = Path(pyproject_path)
    if not pyproject_p.exists():
        raise FileNotFoundError(f"{pyproject_p} not found.")
    content = pyproject_p.read_text(encoding="utf-8")
    new_content, count = re.subn(
        r'^version\s*=\s*"[^"]+"',
        f'version = "{new_version}"',
        content,
        flags=re.MULTILINE,
    )
    if count == 0:
        raise ValueError(f"Could not replace version string in {pyproject_p}")
    pyproject_p.write_text(new_content, encoding="utf-8")

    # 2. Update __init__.py
    init_p = Path(init_path)
    if init_p.exists():
        init_content = init_p.read_text(encoding="utf-8")
        new_init_content, init_count = re.subn(
            r'^__version__\s*=\s*"[^"]+"',
            f'__version__ = "{new_version}"',
            init_content,
            flags=re.MULTILINE,
        )
        if init_count > 0:
            init_p.write_text(new_init_content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bump semantic version for mcp-vulnerabilities."
    )
    parser.add_argument(
        "--part",
        choices=["patch", "minor", "major", "data", "feature"],
        default="patch",
        help="Semantic version component to bump (default: patch)",
    )
    parser.add_argument(
        "bump_type",
        nargs="?",
        choices=["patch", "minor", "major", "data", "feature"],
        help="Optional positional bump type (overrides --part if provided)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Calculate and print next version without modifying files",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the version bump to pyproject.toml and __init__.py",
    )
    parser.add_argument(
        "--pyproject",
        default="pyproject.toml",
        help="Path to pyproject.toml",
    )
    parser.add_argument(
        "--init-file",
        default="src/mcp_vulnerabilities/__init__.py",
        help="Path to __init__.py",
    )

    args = parser.parse_args(argv)
    part = args.bump_type if args.bump_type else args.part

    try:
        curr_ver = get_current_version(args.pyproject)
        next_ver = bump_version(curr_ver, part)

        if args.dry_run:
            print(next_ver)
            return 0

        if args.apply:
            update_version_in_files(next_ver, args.pyproject, args.init_file)
            print(f"Bumped version from {curr_ver} to {next_ver}")
            return 0

        # Default info output
        print(f"Current version: {curr_ver}")
        print(f"Next {part} version: {next_ver}")
        print("Use --dry-run to print just the next version, or --apply to update files.")
        return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
