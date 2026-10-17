import re
import subprocess
import sys
from pathlib import Path
import pytest

import mcp_vulnerabilities

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.bump_version import bump_version, get_current_version, update_version_in_files


def test_init_version_matches_pyproject():
    root = Path(__file__).resolve().parent.parent
    pyproject_p = root / "pyproject.toml"
    current_ver = get_current_version(pyproject_p)

    assert hasattr(mcp_vulnerabilities, "__version__")
    assert mcp_vulnerabilities.__version__ == current_ver
    assert bool(current_ver)


def test_bump_version_logic():
    # Patch bump
    assert bump_version("1.0.0", "patch") == "1.0.1"
    assert bump_version("1.0.0", "data") == "1.0.1"
    assert bump_version("2.3.4", "patch") == "2.3.5"

    # Minor bump
    assert bump_version("1.0.0", "minor") == "1.1.0"
    assert bump_version("1.0.0", "feature") == "1.1.0"
    assert bump_version("2.3.4", "minor") == "2.4.0"

    # Major bump
    assert bump_version("1.0.0", "major") == "2.0.0"
    assert bump_version("2.3.4", "major") == "3.0.0"

    # Invalid part
    with pytest.raises(ValueError, match="Unknown bump type"):
        bump_version("1.0.0", "invalid_type")


def test_bump_version_script_cli_dry_run():
    root = Path(__file__).resolve().parent.parent
    script_p = root / "scripts" / "bump_version.py"
    pyproject_p = root / "pyproject.toml"
    current_ver = get_current_version(pyproject_p)

    # Dry-run patch
    res = subprocess.run(
        [sys.executable, str(script_p), "--dry-run"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == bump_version(current_ver, "patch")

    # Dry-run minor
    res = subprocess.run(
        [sys.executable, str(script_p), "--part", "minor", "--dry-run"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == bump_version(current_ver, "minor")

    # Dry-run major
    res = subprocess.run(
        [sys.executable, str(script_p), "--part", "major", "--dry-run"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == bump_version(current_ver, "major")


def test_bump_version_apply_in_temp_files(tmp_path: Path):
    mock_pyproject = tmp_path / "pyproject.toml"
    mock_pyproject.write_text(
        '[project]\nname = "mcp-vulnerabilities"\nversion = "1.0.0"\n'
    )
    mock_init = tmp_path / "__init__.py"
    mock_init.write_text('"""Init."""\n__version__ = "1.0.0"\n')

    next_ver = bump_version(get_current_version(mock_pyproject), "patch")
    update_version_in_files(next_ver, mock_pyproject, mock_init)

    assert get_current_version(mock_pyproject) == "1.0.1"
    assert '__version__ = "1.0.1"' in mock_init.read_text()


def test_release_workflow_structure():
    root = Path(__file__).resolve().parent.parent
    workflow_p = root / ".github" / "workflows" / "release.yaml"
    assert workflow_p.exists()

    content = workflow_p.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines()]

    assert "workflow_call:" in lines or any("workflow_call" in l for l in lines)
    assert "skip-existing: true" in lines or any("skip-existing" in l for l in lines)
