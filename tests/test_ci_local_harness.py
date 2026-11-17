"""Keep scripts/ci_local.py in step with .github/workflows/.

The harness reads its pins from the workflow files at run time; these tests
fail when a workflow gains a job the harness neither runs nor explains, or when
a pin moves somewhere the harness can no longer read it.
"""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
SCRIPT = REPO / "scripts" / "ci_local.py"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("ci_local", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ci_local"] = module
    spec.loader.exec_module(module)
    return module


def _workflow_jobs():
    jobs = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id in (data.get("jobs") or {}):
            jobs.add((path.name, job_id))
    return jobs


def test_every_workflow_job_is_run_or_explained(harness):
    covered = {(c.workflow, c.job_id) for c in harness.CHECKS} | set(harness.NOT_RUN)
    jobs = _workflow_jobs()
    assert jobs - covered == set(), "add new workflow jobs to CHECKS or NOT_RUN in scripts/ci_local.py"
    assert covered - jobs == set(), "scripts/ci_local.py names workflow jobs that no longer exist"


def test_run_and_not_run_do_not_overlap(harness):
    run = {(c.workflow, c.job_id) for c in harness.CHECKS}
    assert run & set(harness.NOT_RUN) == set()


def test_pins_are_read_from_the_workflows(harness):
    pins = harness.read_pins()
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert f'python-version: "{pins.python_tests}"' in ci
    assert f'node-version: "{pins.node}"' in ci
    assert f'"playwright=={pins.playwright}"' in ci
    assert f'"cmarkgfm=={pins.cmarkgfm}"' in ci
    assert "python -m compileall -q " + " ".join(pins.compileall_targets) in ci

    secret = (WORKFLOWS / "secret-scan.yml").read_text(encoding="utf-8")
    assert f"GITLEAKS_VERSION: {pins.gitleaks_version}" in secret
    assert f"GITLEAKS_SHA256: {pins.gitleaks_sha256}" in secret

    wsec = (WORKFLOWS / "workflow-security.yml").read_text(encoding="utf-8")
    assert f"ACTIONLINT_VERSION: {pins.actionlint_version}" in wsec
    assert f"ACTIONLINT_SHA256: {pins.actionlint_sha256}" in wsec
    assert f"zizmor=={pins.zizmor}" in wsec


def test_shards_match_the_ci_matrix(harness):
    data = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
    matrix = data["jobs"]["python-tests"]["strategy"]["matrix"]["shard"]
    assert list(harness.read_pins().shards) == matrix


def test_hadolint_pin_matches_the_action_image(harness):
    container = (WORKFLOWS / "container-scan.yml").read_text(encoding="utf-8")
    # The action pin decides the hadolint version; bump HADOLINT_VERSION with it.
    assert "hadolint/hadolint-action@2a66e89f53d0771bb131a7fa31f3136336094aa6" in container
    assert harness.HADOLINT_IMAGE == "ghcr.io/hadolint/hadolint:v2.15.0-debian"
    assert re.fullmatch(r"[0-9a-f]{64}", harness.HADOLINT_LINUX_X86_64_SHA256)


@pytest.mark.parametrize(
    "title, ok",
    [
        ("fix(anthropic): cap cache breakpoints", True),
        ("feat!: drop python 3.10", True),
        ("ci(workflows): pin actions", True),
        ("Fix the thing", False),
        ("fix: ", False),
        ("feature(x): y", False),
    ],
)
def test_pr_title_regex_matches_the_workflow(harness, title, ok):
    assert bool(re.match(harness.read_pins().pr_title_regex, title)) is ok


def test_list_runs_without_network_or_installs(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--list"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "ODYSSEUS_CI_CACHE": str(tmp_path)},
    )
    assert proc.returncode == 0, proc.stderr
    assert "python-tests" in proc.stdout
    assert "codeql.yml:analyze" in proc.stdout


def test_unknown_check_is_a_usage_error():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--only", "not-a-check"], capture_output=True, text=True
    )
    assert proc.returncode == 2
    assert "unknown check" in proc.stderr
