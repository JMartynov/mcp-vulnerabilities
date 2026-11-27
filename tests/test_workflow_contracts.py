"""Contract tests for TASK-112-UPSTREAM GitHub workflow repairs (AC-112.2, AC-112.3)."""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"


def _load_workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOW_DIR / name).read_text(encoding="utf-8"))


def _events(workflow: dict) -> dict:
    # PyYAML parses unquoted YAML `on:` as boolean True.
    return workflow.get(True, workflow.get("on", {}))


def test_cross_repo_sync_schedule_staggered_to_0500_utc():
    """AC-112.2: cross_repo_sync.yml runs at 0 5 * * * after mcp-fingerprints (0 4 * * *)."""
    wf = _load_workflow("cross_repo_sync.yml")
    schedules = _events(wf).get("schedule", [])
    crons = [entry.get("cron") for entry in schedules]
    assert crons == ["0 5 * * *"]


def test_cross_repo_sync_dispatch_payload_contract():
    """AC-112.3: cross_repo_sync.yml consumes upstream_version and passports_count."""
    wf = _load_workflow("cross_repo_sync.yml")
    dispatch = _events(wf)["repository_dispatch"]
    assert "upstream_fingerprints_updated" in dispatch["types"]

    text = (WORKFLOW_DIR / "cross_repo_sync.yml").read_text(encoding="utf-8")
    assert "github.event.client_payload.upstream_version" in text
    assert "github.event.client_payload.passports_count" in text


@pytest.mark.parametrize("workflow_name", ["cross_repo_sync.yml", "daily_sync.yml"])
def test_release_assets_and_ref_dispatches(workflow_name: str):
    """AC-112.2: Attach vulnerabilities.json.gz + SHA256SUMS.txt and pass --ref v${NEW_VERSION}."""
    text = (WORKFLOW_DIR / workflow_name).read_text(encoding="utf-8")

    assert "sha256sum vulnerabilities.json.gz > SHA256SUMS.txt" in text
    assert 'gh release create "v${NEW_VERSION}" vulnerabilities.json.gz SHA256SUMS.txt' in text

    for target in ("release.yaml", "docker.yml", "sign_release.yml"):
        expected_cmd = f'gh workflow run {target} --ref "v${{NEW_VERSION}}"'
        assert expected_cmd in text, f"{workflow_name} missing {expected_cmd}"
        assert f"{expected_cmd} || true" not in text, (
            f"{workflow_name} must not swallow dispatch failures for {target}"
        )


@pytest.mark.parametrize("workflow_name", ["cross_repo_sync.yml", "daily_sync.yml"])
def test_downstream_repository_dispatch_contract(workflow_name: str):
    """AC-112.3: Downstream dispatches target verityredteam-free and verityredteam loudly when PAT set."""
    text = (WORKFLOW_DIR / workflow_name).read_text(encoding="utf-8")

    assert "REPO_DISPATCH_PAT: ${{ secrets.REPO_DISPATCH_PAT }}" in text
    assert "JMartynov/verityredteam-free" in text
    assert "JMartynov/verityredteam" in text
    assert "event_type=upstream_vulnerabilities_updated" in text
    assert 'client_payload[upstream_version]=${NEW_VERSION}' in text
    assert "::warning::REPO_DISPATCH_PAT not configured" in text

    for line in text.splitlines():
        if "repos/${target}/dispatches" in line:
            assert "|| true" not in line, (
                f"{workflow_name} must fail loudly when REPO_DISPATCH_PAT dispatch fails"
            )


@pytest.mark.parametrize(
    "workflow_name",
    ["ci.yml", "pages.yml", "sign_release.yml", "docker.yml", "release.yaml"],
)
def test_downstream_triggered_workflows_have_valid_triggers_and_permissions(workflow_name: str):
    """Verify ci.yml, pages.yml, sign_release.yml, docker.yml, release.yaml accept workflow_dispatch."""
    wf = _load_workflow(workflow_name)
    events = _events(wf)
    assert "workflow_dispatch" in events, f"{workflow_name} missing workflow_dispatch trigger"

    if workflow_name == "sign_release.yml":
        perms = wf["jobs"]["sign"]["permissions"]
        assert perms.get("id-token") == "write"
        assert perms.get("contents") == "write"
    elif workflow_name == "pages.yml":
        perms = wf.get("permissions", {})
        assert perms.get("pages") == "write"
        assert perms.get("id-token") == "write"
        text = (WORKFLOW_DIR / workflow_name).read_text(encoding="utf-8")
        assert "actions/upload-pages-artifact@v4" in text
        assert "actions/deploy-pages@v4" in text
    elif workflow_name == "docker.yml":
        perms = wf["jobs"]["build-and-push"]["permissions"]
        assert perms.get("packages") == "write"
