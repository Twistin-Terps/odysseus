"""Keep scripts/ci_local.py in step with .github/workflows/.

The harness reads its pins from the workflow files at run time. These tests
fail when a workflow gains a job the harness neither runs nor explains, when a
job the harness mirrors changes, or when a pin moves somewhere the harness can
no longer read it.
"""

import hashlib
import importlib.util
import json
import os
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
    name = "ci_local_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules, so register
    # the module while it loads and is used, then remove it again.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(name, None)


def _workflow_files():
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def _jobs():
    jobs = {}
    for path in _workflow_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (data.get("jobs") or {}).items():
            jobs[(path.name, job_id)] = job
    return jobs


def _job(workflow, job_id):
    return _jobs()[(workflow, job_id)]


def _steps_text(workflow, job_id):
    return "\n".join(
        str(step.get("run", "")) + json.dumps(step.get("with", {}), sort_keys=True)
        + json.dumps(step.get("env", {}), sort_keys=True)
        for step in _job(workflow, job_id).get("steps", [])
    )


def test_every_workflow_job_is_run_or_explained(harness):
    covered = {(c.workflow, c.job_id) for c in harness.CHECKS} | set(harness.NOT_RUN)
    jobs = set(_jobs())
    assert jobs - covered == set(), "add new workflow jobs to CHECKS or NOT_RUN in scripts/ci_local.py"
    assert covered - jobs == set(), "scripts/ci_local.py names workflow jobs that no longer exist"


def test_run_and_not_run_do_not_overlap(harness):
    run = {(c.workflow, c.job_id) for c in harness.CHECKS}
    assert run & set(harness.NOT_RUN) == set()


def test_mirrored_jobs_have_not_changed_since_the_harness_was_checked(harness):
    expected = {(c.workflow, c.job_id) for c in harness.CHECKS}
    assert set(harness.JOB_DIGESTS) == expected
    changed = []
    for (workflow, job_id), digest in harness.JOB_DIGESTS.items():
        job = _job(workflow, job_id)
        actual = hashlib.sha256(json.dumps(job, sort_keys=True).encode()).hexdigest()[:16]
        if actual != digest:
            changed.append(f"{workflow}:{job_id} (now {actual})")
    assert not changed, (
        "these CI jobs changed; check that the matching check in scripts/ci_local.py "
        "still mirrors them, then update JOB_DIGESTS: " + ", ".join(changed)
    )


def test_pins_come_from_the_jobs_that_use_them(harness):
    pins = harness.read_pins()

    def setup_value(workflow, job_id, action, key):
        for step in _job(workflow, job_id)["steps"]:
            if step.get("uses", "").startswith(action):
                return str(step["with"][key])
        raise AssertionError(f"{workflow}:{job_id} has no {action} step")

    for job_id in ("python-syntax", "python-tests", "benchmark-gfm-security"):
        assert setup_value("ci.yml", job_id, "actions/setup-python", "python-version") == pins.python_tests
    for job_id in ("node-syntax", "python-tests"):
        assert setup_value("ci.yml", job_id, "actions/setup-node", "node-version") == pins.node
    assert setup_value("ci.yml", "python-tests", "astral-sh/setup-uv", "version") == pins.uv
    assert setup_value("workflow-security.yml", "zizmor", "actions/setup-python", "python-version") \
        == pins.python_security

    assert f"playwright=={pins.playwright}" in _steps_text("ci.yml", "python-tests")
    assert f"cmarkgfm=={pins.cmarkgfm}" in _steps_text("ci.yml", "benchmark-gfm-security")
    assert "python -m compileall -q " + " ".join(pins.compileall_targets) in _steps_text("ci.yml", "python-syntax")
    assert all(g in _steps_text("ci.yml", "node-syntax") for g in pins.node_check_globs)

    gitleaks = _steps_text("secret-scan.yml", "gitleaks")
    assert pins.gitleaks_version in gitleaks and pins.gitleaks_sha256 in gitleaks
    actionlint = _steps_text("workflow-security.yml", "actionlint")
    assert pins.actionlint_version in actionlint and pins.actionlint_sha256 in actionlint
    assert f"zizmor=={pins.zizmor}" in _steps_text("workflow-security.yml", "zizmor")

    hadolint = _job("container-scan.yml", "hadolint")["steps"]
    ignore = next(s["with"]["ignore"] for s in hadolint if "hadolint-action" in s.get("uses", ""))
    assert tuple(i.strip() for i in ignore.split(",")) == pins.hadolint_ignore


def test_shards_match_the_ci_matrix(harness):
    matrix = _job("ci.yml", "python-tests")["strategy"]["matrix"]["shard"]
    assert list(harness.read_pins().shards) == matrix


def test_hadolint_pin_matches_the_action_image(harness):
    hadolint = _job("container-scan.yml", "hadolint")["steps"]
    uses = next(s["uses"] for s in hadolint if "hadolint-action" in s.get("uses", ""))
    # The action pin decides the hadolint version; bump HADOLINT_VERSION with it.
    assert uses == "hadolint/hadolint-action@2a66e89f53d0771bb131a7fa31f3136336094aa6"
    assert harness.HADOLINT_IMAGE == "ghcr.io/hadolint/hadolint:v2.15.0-debian"


@pytest.mark.parametrize(
    "title, ok",
    [
        ("fix(anthropic): cap cache breakpoints", True),
        ("feat!: drop python 3.10", True),
        ("ci(workflows): pin actions", True),
        ("Fix the thing", False),
        ("fix: ", False),
        ("feature(x): y", False),
        # JavaScript's \w is ASCII-only, so the workflow rejects a non-ASCII scope.
        ("fix(café): accents", False),
    ],
)
def test_pr_title_check_matches_the_workflow(harness, title, ok):
    assert harness.pr_title_ok(harness.read_pins().pr_title_regex, title) is ok


def test_pr_title_check_agrees_with_node_on_the_workflow_regex(harness):
    node = "node"
    if subprocess.run(["which", node], capture_output=True).returncode != 0:
        pytest.skip("node is not installed")
    regex = harness.read_pins().pr_title_regex
    titles = ["fix(café): accents", "fix(api): ok", "docs: fine", "Nope"]
    script = (
        f"const re = /{regex}/;"
        "for (const t of JSON.parse(process.argv[1])) console.log(re.test(t) ? '1' : '0');"
    )
    proc = subprocess.run([node, "-e", script, json.dumps(titles)], capture_output=True, text=True, check=True)
    assert proc.stdout.split() == ["1" if harness.pr_title_ok(regex, t) else "0" for t in titles]


def test_node_check_globs_expand_without_bash(harness):
    files = harness.node_check_files(harness.read_pins().node_check_globs)
    assert "static/app.js" in files
    assert all(f.endswith(".js") for f in files)


def test_list_neither_downloads_nor_creates_files(tmp_path):
    cache = tmp_path / "cache"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "ODYSSEUS_CI_CACHE": str(cache),
        # Any attempted network use would fail fast against this proxy.
        "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
    }
    proc = subprocess.run([sys.executable, str(SCRIPT), "--list"], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "python-tests" in proc.stdout
    assert "codeql.yml:analyze" in proc.stdout
    assert not cache.exists()


@pytest.mark.parametrize("argv", [["--only", "not-a-check"], ["--only", "python-tests", "--skip", "python-tests"]])
def test_bad_selections_are_usage_errors(argv, tmp_path):
    env = {**os.environ, "ODYSSEUS_CI_CACHE": str(tmp_path)}
    proc = subprocess.run([sys.executable, str(SCRIPT), *argv], capture_output=True, text=True, env=env)
    assert proc.returncode == 2, proc.stderr
