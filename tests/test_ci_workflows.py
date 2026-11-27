"""Regression tests for the CI workflow hardening task (Task 170)."""

import gzip
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

UPDATED_WORKFLOW_TIMEOUTS = {
    "cross_repo_sync.yml": 45,
    "daily_sync.yml": 60,
    "snapshot_release.yml": 30,
    "daily_web_audit.yml": 20,
    "docker.yml": 30,
    "sign_release.yml": 30,
}

RELEASE_PIPELINE_DISPATCHES = (
    "release.yaml",
    "docker.yml",
    "sign_release.yml",
    "daily_web_audit.yml",
    "pages.yml",
)


def _workflow_paths():
    return sorted({*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")})


def _load_workflow(name):
    with (WORKFLOW_DIR / name).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _job_steps(name, job_name):
    return _load_workflow(name)["jobs"][job_name]["steps"]


def _step_by_name(steps, step_name):
    for step in steps:
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"Step not found: {step_name}")


def _first_else_block(script):
    lines = script.splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == "else":
            block = []
            for following in lines[idx + 1:]:
                if following.strip() == "fi":
                    break
                block.append(following)
            return "\n".join(block)
    return ""


# ---------------------------------------------------------------------------
# Requirement 1: every workflow parses and updated jobs declare timeouts
# ---------------------------------------------------------------------------


def test_workflow_directory_contains_workflows():
    assert _workflow_paths(), "No workflow files found in .github/workflows"


@pytest.mark.parametrize("workflow_path", _workflow_paths(), ids=lambda p: p.name)
def test_workflow_is_valid_yaml_dict(workflow_path):
    parsed = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), f"{workflow_path.name} did not parse to a dict"


@pytest.mark.parametrize(
    ("workflow_name", "expected_timeout"),
    sorted(UPDATED_WORKFLOW_TIMEOUTS.items()),
    ids=sorted(UPDATED_WORKFLOW_TIMEOUTS),
)
def test_updated_workflow_jobs_define_timeouts(workflow_name, expected_timeout):
    jobs = _load_workflow(workflow_name).get("jobs", {})
    assert jobs, f"{workflow_name} defines no jobs"
    for job_name, job in jobs.items():
        assert "timeout-minutes" in job, (
            f"{workflow_name}:{job_name} is missing timeout-minutes"
        )
        assert job["timeout-minutes"] == expected_timeout, (
            f"{workflow_name}:{job_name} timeout is {job['timeout-minutes']}, "
            f"expected {expected_timeout}"
        )


# ---------------------------------------------------------------------------
# Requirement 2: shared concurrency, dispatch wiring, audit concurrency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("workflow_name", ["daily_sync.yml", "cross_repo_sync.yml"])
def test_sync_workflows_share_concurrency_group(workflow_name):
    concurrency = _load_workflow(workflow_name).get("concurrency")
    assert isinstance(concurrency, dict), f"{workflow_name} has no concurrency block"
    assert concurrency.get("group") == "mcp-vuln-data-sync"
    assert concurrency.get("cancel-in-progress") is False


@pytest.mark.parametrize("workflow_name", ["daily_sync.yml", "cross_repo_sync.yml"])
def test_sync_workflows_dispatch_release_pipeline(workflow_name):
    text = (WORKFLOW_DIR / workflow_name).read_text(encoding="utf-8")
    for target in RELEASE_PIPELINE_DISPATCHES:
        assert f"gh workflow run {target}" in text, (
            f"{workflow_name} does not dispatch {target}"
        )


def test_daily_sync_else_branch_does_not_duplicate_builders():
    steps = _job_steps("daily_sync.yml", "sync-mcp-vulnerabilities")
    commit_step = next(s for s in steps if s.get("id") == "commit_push")
    else_block = _first_else_block(commit_step["run"])
    assert else_block.strip(), "Could not locate the else branch in daily_sync.yml"
    assert "site_builder" not in else_block
    assert "updates_builder" not in else_block


def test_daily_web_audit_concurrency_is_cancel_in_progress():
    concurrency = _load_workflow("daily_web_audit.yml").get("concurrency")
    assert isinstance(concurrency, dict)
    assert concurrency.get("group") == "daily-web-audit-${{ github.ref }}"
    assert concurrency.get("cancel-in-progress") is True


# ---------------------------------------------------------------------------
# Requirement 3: cross-repo backup ordering, cleanup, retry, staged guard
# ---------------------------------------------------------------------------


def test_cross_repo_sync_backup_precedes_passport_fetch():
    steps = _job_steps("cross_repo_sync.yml", "cross-repo-sync")
    names = [step.get("name") for step in steps]

    backup_name = "Backup Passports and Vulnerabilities for Delta Check"
    fetch_name = "Fetch Latest Passports from mcp-fingerprints (Cross-Repo Sync)"
    assert backup_name in names
    assert fetch_name in names
    assert names.index(backup_name) < names.index(fetch_name)

    backup_run = _step_by_name(steps, backup_name)["run"]
    assert "data/passports.json.gz" in backup_run
    assert "data/passports_backup.json.gz" in backup_run
    assert "data/vulnerabilities" in backup_run
    assert "data/vulnerabilities_backup" in backup_run


def test_cross_repo_sync_delta_check_cleans_up_backups():
    steps = _job_steps("cross_repo_sync.yml", "cross-repo-sync")
    delta_run = _step_by_name(steps, "Check for Deltas")["run"]
    assert "rm -rf data/vulnerabilities_backup data/passports_backup.json.gz" in delta_run


def test_cross_repo_sync_push_retry_loop_and_staged_guard():
    steps = _job_steps("cross_repo_sync.yml", "cross-repo-sync")
    non_delta_run = _step_by_name(
        steps,
        "Commit & Push Canonical Vulnerability Updates Directly to Main",
    )["run"]

    assert "for i in 1 2 3 4 5" in non_delta_run
    assert "git push origin main" in non_delta_run
    assert "git diff --staged --quiet" in non_delta_run


# ---------------------------------------------------------------------------
# Requirement 4: snapshot export/checksum and release-signing fallback
# ---------------------------------------------------------------------------


def test_snapshot_release_exports_osv_bucket_and_checksum():
    text = (WORKFLOW_DIR / "snapshot_release.yml").read_text(encoding="utf-8")
    assert (
        "export-osv --data-dir data/vulnerabilities --output-dir dist/osv" in text
    )
    assert "dist/mcp-offline.tar.gz.sha256" in text


def test_sign_release_handles_vulnerabilities_gz_fallback():
    text = (WORKFLOW_DIR / "sign_release.yml").read_text(encoding="utf-8")
    assert "vulnerabilities.json.gz" in text
    assert "docs/data/vulnerabilities.json.gz" in text
    assert "cp -f vulnerabilities.json.gz docs/data/vulnerabilities.json.gz" in text


# ---------------------------------------------------------------------------
# Requirement 5: scripts/check_deltas.py passport delta detection
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def check_deltas_module():
    script_path = REPO_ROOT / "scripts" / "check_deltas.py"
    spec = importlib.util.spec_from_file_location("check_deltas", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE_PASSPORTS = {
    "total_passports": 2,
    "passports": {
        "alpha": {"version": "1.0.0"},
        "beta": {"version": "2.0.0"},
    },
}


def _write_passports(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)


def _clone(payload):
    return json.loads(json.dumps(payload))


def test_passports_delta_false_when_identical(check_deltas_module, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_passports(tmp_path / "data" / "passports.json.gz", BASE_PASSPORTS)
    _write_passports(tmp_path / "data" / "passports_backup.json.gz", BASE_PASSPORTS)
    assert check_deltas_module.check_passports_delta() is False


def test_passports_delta_true_when_total_increases(
    check_deltas_module, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    backup = _clone(BASE_PASSPORTS)
    current = _clone(BASE_PASSPORTS)
    current["total_passports"] = backup["total_passports"] + 1
    _write_passports(tmp_path / "data" / "passports.json.gz", current)
    _write_passports(tmp_path / "data" / "passports_backup.json.gz", backup)
    assert check_deltas_module.check_passports_delta() is True


def test_passports_delta_true_when_passports_differ_same_total(
    check_deltas_module, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    backup = _clone(BASE_PASSPORTS)
    current = _clone(BASE_PASSPORTS)
    current["passports"]["alpha"]["version"] = "9.9.9"
    _write_passports(tmp_path / "data" / "passports.json.gz", current)
    _write_passports(tmp_path / "data" / "passports_backup.json.gz", backup)
    assert check_deltas_module.check_passports_delta() is True


def test_passports_delta_true_when_backup_missing(
    check_deltas_module, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    _write_passports(tmp_path / "data" / "passports.json.gz", BASE_PASSPORTS)
    assert check_deltas_module.check_passports_delta() is True


def test_passports_delta_false_when_current_missing(
    check_deltas_module, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    _write_passports(tmp_path / "data" / "passports_backup.json.gz", BASE_PASSPORTS)
    assert check_deltas_module.check_passports_delta() is False
