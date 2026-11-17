#!/usr/bin/env python3
"""Run the repository's blocking CI checks locally, before pushing.

Usage:
    python3 scripts/ci_local.py                 # every check that can run here
    python3 scripts/ci_local.py --quick         # everything except the pytest suite
    python3 scripts/ci_local.py --only gitleaks,actionlint
    python3 scripts/ci_local.py --shard 2/4     # one pytest shard instead of all four
    python3 scripts/ci_local.py --list          # what maps to which CI job, and what cannot run locally

Each check mirrors one GitHub Actions job. Tool and runtime versions are read
from the workflow files at run time, so the harness follows the pins in
.github/workflows/ instead of keeping its own copy.

Nothing here uses sudo or changes system packages. Python environments, npm
packages, Playwright browsers and pinned tool binaries are installed into a
cache directory outside the repository (``$ODYSSEUS_CI_CACHE``, default
``~/.cache/odysseus-ci-local``), plus ``node_modules/`` exactly as ``npm ci``
creates it. When a check needs something the machine lacks (Python 3.11 with
no ``uv`` to fetch it, a Docker daemon, ...), it is reported as SKIP with the
reason. A SKIP is not a pass: the summary says how many blocking checks did not
run, and ``--strict`` turns them into a failure.

Exit status: 0 when no blocking check failed (and, with --strict, none was
skipped); 1 otherwise; 2 for usage errors.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

# hadolint is pinned only inside hadolint/hadolint-action@2a66e89f (v3.4.0),
# whose Dockerfile is FROM ghcr.io/hadolint/hadolint:v2.15.0-debian. Upstream
# publishes no checksum for the release binary, so this digest was computed
# from the v2.15.0 hadolint-linux-x86_64 release asset on 2026-11-17. It is
# only used when neither a hadolint binary nor a Docker daemon is available.
HADOLINT_VERSION = "2.15.0"
HADOLINT_IMAGE = f"ghcr.io/hadolint/hadolint:v{HADOLINT_VERSION}-debian"
HADOLINT_LINUX_X86_64_SHA256 = "eb8eb4dd06a068cce65cb84743fba69f09ed12a36ff13d58f9af090d6d696970"


# --------------------------------------------------------------------------
# Pins read from the workflow files
# --------------------------------------------------------------------------


class PinError(RuntimeError):
    """A value the harness reads from a workflow file was not found."""


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _one(pattern: str, text: str, what: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise PinError(f"could not find {what} in the workflow files")
    return match.group(1)


@dataclass(frozen=True)
class Pins:
    python_tests: str
    python_security: str
    node: str
    playwright: str
    cmarkgfm: str
    gitleaks_version: str
    gitleaks_sha256: str
    actionlint_version: str
    actionlint_sha256: str
    zizmor: str
    shards: tuple[str, ...]
    compileall_targets: tuple[str, ...]
    node_check_globs: tuple[str, ...]
    hadolint_ignore: tuple[str, ...]
    pr_title_regex: str


def read_pins() -> Pins:
    ci = _workflow("ci.yml")
    secret = _workflow("secret-scan.yml")
    wsec = _workflow("workflow-security.yml")
    container = _workflow("container-scan.yml")
    prdesc = _workflow("pr-description-check.yml")

    shard_list = _one(r'^\s*shard:\s*\[([^\]]+)\]', ci, "the pytest shard matrix")
    ignore = _one(r'^\s*ignore:\s*(\S.*)$', container, "the hadolint ignore list")
    return Pins(
        python_tests=_one(r'python-version:\s*"?(3\.\d+)"?', ci, "the CI Python version"),
        python_security=_one(r"python-version:\s*'?\"?(3\.\d+)", wsec, "the zizmor Python version"),
        node=_one(r'node-version:\s*"?([\d.]+)"?', ci, "the Node version"),
        playwright=_one(r'"playwright==([\d.]+)"', ci, "the Python Playwright pin"),
        cmarkgfm=_one(r'"cmarkgfm==([\d.]+)"', ci, "the cmarkgfm pin"),
        gitleaks_version=_one(r"GITLEAKS_VERSION:\s*([\d.]+)", secret, "the gitleaks version"),
        gitleaks_sha256=_one(r"GITLEAKS_SHA256:\s*([0-9a-f]{64})", secret, "the gitleaks checksum"),
        actionlint_version=_one(r"ACTIONLINT_VERSION:\s*([\d.]+)", wsec, "the actionlint version"),
        actionlint_sha256=_one(r"ACTIONLINT_SHA256:\s*([0-9a-f]{64})", wsec, "the actionlint checksum"),
        zizmor=_one(r"zizmor==([\d.]+)", wsec, "the zizmor pin"),
        shards=tuple(s.strip().strip("'\"") for s in shard_list.split(",")),
        compileall_targets=tuple(
            _one(r"python -m compileall -q (.+)$", ci, "the compileall targets").split()
        ),
        node_check_globs=tuple(
            _one(r"for f in (.+?); do\s*$", ci, "the node --check file globs").split()
        ),
        hadolint_ignore=tuple(i.strip() for i in ignore.split(",")),
        pr_title_regex=_one(r"const re = /(.+)/;", prdesc, "the PR title regex"),
    )


# --------------------------------------------------------------------------
# Results and command running
# --------------------------------------------------------------------------

PASS, FAIL, SKIP, INFO = "PASS", "FAIL", "SKIP", "INFO"


class Skip(Exception):
    """Raised by a check that cannot run on this machine."""


@dataclass
class Result:
    name: str
    ci_job: str
    blocking: bool
    status: str = PASS
    detail: str = ""
    seconds: float = 0.0
    parity: list[str] = field(default_factory=list)


class Context:
    def __init__(self, args: argparse.Namespace, pins: Pins):
        self.args = args
        self.pins = pins
        self.cache = Path(
            os.environ.get("ODYSSEUS_CI_CACHE")
            or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "odysseus-ci-local"
        )
        self.cache.mkdir(parents=True, exist_ok=True)
        self.parity: list[str] = []
        self.failures: list[str] = []

    def note(self, message: str) -> None:
        self.parity.append(message)

    def run(self, cmd: list[str] | str, *, env: dict[str, str] | None = None,
            cwd: Path = REPO, check: bool = True, shell: bool = False) -> int:
        shown = cmd if isinstance(cmd, str) else " ".join(cmd)
        print(f"  $ {shown}", flush=True)
        full_env = {**os.environ, **(env or {})}
        proc = subprocess.run(
            cmd, cwd=cwd, env=full_env, shell=shell,
            executable="/bin/bash" if shell else None,
        )
        if check and proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, shown)
        return proc.returncode


def need(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise Skip(f"missing on PATH: {', '.join(missing)}")


def _digest(*paths: Path, extra: str = "") -> str:
    h = hashlib.sha256(extra.encode())
    for p in paths:
        h.update(p.read_bytes())
    return h.hexdigest()


# --------------------------------------------------------------------------
# Environments: Python venvs, npm packages, pinned binaries
# --------------------------------------------------------------------------


def find_python(ctx: Context, version: str) -> list[str]:
    """Return a command that runs Python `version`, or raise Skip."""
    exe = shutil.which(f"python{version}")
    if exe:
        return [exe]
    if shutil.which("uv"):
        found = subprocess.run(
            ["uv", "python", "find", version], capture_output=True, text=True
        )
        if found.returncode != 0:
            ctx.run(["uv", "python", "install", version])
            found = subprocess.run(
                ["uv", "python", "find", version], capture_output=True, text=True, check=True
            )
        return [found.stdout.strip()]
    raise Skip(f"Python {version} is needed (CI pins it) and neither python{version} nor uv is installed")


def venv(ctx: Context, label: str, version: str, installs: list[list[str]], key: str) -> Path:
    """Create or reuse a cached venv; reinstall when `key` changes. Returns its python."""
    base_python = find_python(ctx, version)
    root = ctx.cache / f"venv-{label}-py{version}"
    py = root / "bin" / "python"
    marker = root / ".ci-local-key"
    if py.exists() and marker.exists() and marker.read_text() == key and not ctx.args.reinstall:
        return py
    if root.exists():
        shutil.rmtree(root)
    ctx.run([*base_python, "-m", "venv", str(root)])
    for step in installs:
        ctx.run([str(py) if part == "{py}" else part for part in step])
    marker.write_text(key)
    return py


def pip_install(*args: str) -> list[str]:
    """An install step for venv(): uv when present (as CI uses), else pip."""
    if shutil.which("uv"):
        return ["uv", "pip", "install", "--python", "{py}", *args]
    return ["{py}", "-m", "pip", "install", "--disable-pip-version-check", *args]


def npm_install(ctx: Context, *, ignore_scripts: bool) -> None:
    """Run `npm ci` only when package-lock.json or the install mode changed."""
    need("node", "npm")
    node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
    if node != f"v{ctx.pins.node}":
        ctx.note(f"Node is {node}; CI pins v{ctx.pins.node}.")
    mode = "ignore-scripts" if ignore_scripts else "full"
    key = _digest(REPO / "package-lock.json", extra=mode)
    marker = REPO / "node_modules" / ".ci-local-key"
    if marker.exists() and marker.read_text() in {key, _digest(REPO / "package-lock.json", extra="full")} \
            and not ctx.args.reinstall:
        return  # a full install also satisfies an ignore-scripts request
    cmd = ["npm", "ci", "--no-audit", "--no-fund"]
    if ignore_scripts:
        cmd.insert(2, "--ignore-scripts")
    ctx.run(cmd)
    marker.write_text(key)


def pinned_binary(ctx: Context, name: str, url: str, sha256: str, member: str | None) -> Path:
    """Download a pinned release asset into the cache, verify it, and return the binary."""
    need("curl")
    dest = ctx.cache / "bin" / f"{name}-{sha256[:12]}"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        download = Path(tmp) / "asset"
        ctx.run(["curl", "-fsSL", "-o", str(download), url])
        actual = hashlib.sha256(download.read_bytes()).hexdigest()
        if actual != sha256:
            raise RuntimeError(f"{name}: checksum mismatch (expected {sha256}, got {actual})")
        if member:
            with tarfile.open(download) as tar:
                src = tar.extractfile(member)
                if src is None:
                    raise RuntimeError(f"{name}: {member} not found in {url}")
                dest.write_bytes(src.read())
        else:
            shutil.copyfile(download, dest)
    dest.chmod(0o755)
    return dest


def docker_running() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def git_output(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_python_syntax(ctx: Context, result: Result) -> None:
    py = find_python(ctx, ctx.pins.python_tests)
    ctx.run([*py, "-m", "compileall", "-q", *ctx.pins.compileall_targets])
    ctx.run([*py, "scripts/build_frontend.py", "--check"])


def check_node_syntax(ctx: Context, result: Result) -> None:
    npm_install(ctx, ignore_scripts=True)
    ctx.run(["node", "scripts/check_frontend.mjs"])
    globs = " ".join(ctx.pins.node_check_globs)
    ctx.run(
        "set -euo pipefail; shopt -s globstar nullglob; "
        f'for f in {globs}; do node --check "$f"; done; '
        "node --check scripts/check_frontend.mjs",
        shell=True,
    )
    ctx.run(["node", "--test", "tests/frontendArchitecture.test.mjs"])


def check_gfm_security(ctx: Context, result: Result) -> None:
    spec = f"cmarkgfm=={ctx.pins.cmarkgfm}"
    py = venv(ctx, "gfm", ctx.pins.python_tests,
              [pip_install("--only-binary=:all:", spec)], key=spec)
    ctx.run([str(py), "tests/test_audit_c5_benchmark_evidence.py", "--gfm"])


def check_pr_title(ctx: Context, result: Result) -> None:
    title = ctx.args.pr_title
    if not title:
        title = git_output("log", "-1", "--format=%s")
        result.parity.append("No --pr-title given; checked the HEAD commit subject instead.")
    if not re.match(ctx.pins.pr_title_regex, title):
        raise AssertionError(f"PR title is not in Conventional Commits format: {title!r}")
    print(f"  PR title OK: {title}")


def check_gitleaks(ctx: Context, result: Result) -> None:
    if git_output("rev-parse", "--is-shallow-repository") == "true":
        if ctx.args.unshallow:
            ctx.run(["git", "fetch", "--unshallow"])
        else:
            result.parity.append(
                "This clone is shallow, so less history was scanned than CI scans "
                "(rerun with --unshallow to fetch the full history first)."
            )
    v = ctx.pins.gitleaks_version
    binary = pinned_binary(
        ctx, "gitleaks",
        f"https://github.com/gitleaks/gitleaks/releases/download/v{v}/gitleaks_{v}_linux_x64.tar.gz",
        ctx.pins.gitleaks_sha256, "gitleaks",
    )
    ctx.run([str(binary), "git", "--no-banner", "--redact", "--verbose", "."])


def check_actionlint(ctx: Context, result: Result) -> None:
    if shutil.which("shellcheck") is None:
        result.parity.append(
            "shellcheck is not installed, so actionlint skipped the shell-script "
            "checks that CI's runner (which has shellcheck) performs."
        )
    v = ctx.pins.actionlint_version
    binary = pinned_binary(
        ctx, "actionlint",
        f"https://github.com/rhysd/actionlint/releases/download/v{v}/actionlint_{v}_linux_amd64.tar.gz",
        ctx.pins.actionlint_sha256, "actionlint",
    )
    ctx.run([str(binary), "-color"])


def check_zizmor(ctx: Context, result: Result) -> None:
    spec = f"zizmor=={ctx.pins.zizmor}"
    bootstrap = str(REPO / "requirements-bootstrap.txt")
    py = venv(
        ctx, "zizmor", ctx.pins.python_security,
        [
            pip_install("--require-hashes", "--only-binary=:all:", "--no-deps", "-r", bootstrap),
            pip_install(spec),
        ],
        key=_digest(REPO / "requirements-bootstrap.txt", extra=spec),
    )
    py_base = find_python(ctx, ctx.pins.python_security)
    ctx.run([*py_base, "scripts/check_ca_trust.py", "--system"])
    ctx.run([str(py.parent / "zizmor"), "--offline", "--min-severity=low", ".github/workflows/"])


def check_hadolint(ctx: Context, result: Result) -> None:
    ignores = [arg for rule in ctx.pins.hadolint_ignore for arg in ("--ignore", rule)]
    lint = ["--failure-threshold", "info", *ignores]
    if docker_running():
        ctx.run(f"docker run --rm -i {HADOLINT_IMAGE} hadolint {' '.join(lint)} - < Dockerfile", shell=True)
        return
    exe = shutil.which("hadolint")
    if exe:
        version = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout
        if HADOLINT_VERSION not in version:
            result.parity.append(f"hadolint on PATH is not v{HADOLINT_VERSION} ({version.strip()}).")
        ctx.run([exe, *lint, "Dockerfile"])
        return
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise Skip("no Docker daemon or hadolint binary, and the pinned download is linux-x86_64 only")
    binary = pinned_binary(
        ctx, "hadolint",
        f"https://github.com/hadolint/hadolint/releases/download/v{HADOLINT_VERSION}/hadolint-linux-x86_64",
        HADOLINT_LINUX_X86_64_SHA256, None,
    )
    ctx.run([str(binary), *lint, "Dockerfile"])


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(
        ["timeout", "3s", "bwrap", "--die-with-parent", "--unshare-pid", "--ro-bind", "/", "/",
         "--proc", "/proc", "--dev", "/dev", "/bin/true"],
        capture_output=True,
    )
    return probe.returncode == 0


def check_python_tests(ctx: Context, result: Result) -> None:
    need("ffmpeg")
    pins = ctx.pins
    py_base = find_python(ctx, pins.python_tests)
    ctx.run([*py_base, "scripts/check_ca_trust.py", "--system"])

    bootstrap = str(REPO / "requirements-bootstrap.txt")
    playwright = f"playwright=={pins.playwright}"
    py = venv(
        ctx, "tests", pins.python_tests,
        [
            pip_install("--require-hashes", "--only-binary=:all:", "--no-deps", "-r", bootstrap),
            ["{py}", str(REPO / "scripts" / "check_ca_trust.py"), "--python"],
            pip_install("-r", str(REPO / "requirements.txt")),
            pip_install(playwright),
        ],
        key=_digest(REPO / "requirements-bootstrap.txt", REPO / "requirements.txt", extra=playwright),
    )
    npm_install(ctx, ignore_scripts=False)
    browsers = ctx.cache / "ms-playwright"
    browser_env = {"PLAYWRIGHT_BROWSERS_PATH": str(browsers)}
    ctx.run(["npx", "playwright", "install", "chromium"], env=browser_env)
    (REPO / "data").mkdir(exist_ok=True)
    ctx.run([str(py), "scripts/check_ca_trust.py", "--system", "--python"])

    if not _bwrap_works():
        result.parity.append(
            "bubblewrap is missing or its PID/mount-namespace probe failed. CI refuses to "
            "start pytest in that state; here the suite ran with containment tests in "
            "their reduced mode, so a pass is weaker than CI's."
        )
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        result.parity.append(
            "Running as root. CI runs as an unprivileged user, and some tests skip under root."
        )

    # GitHub Actions sets these implicitly; the suite fails (instead of skipping)
    # browser and acorn tests when CI is set and their packages are missing.
    env = {"CI": "true", "GITHUB_ACTIONS": "true", **browser_env}
    shards = [ctx.args.shard] if ctx.args.shard else list(pins.shards)
    failed = []
    for shard in shards:  # fail-fast: false in CI, so every shard runs
        print(f"\n  -- pytest shard {shard}", flush=True)
        rc = ctx.run([str(py), "-m", "pytest", "-q", "-rs", "--durations=25", "--shard", shard],
                     env=env, check=False)
        if rc != 0:
            failed.append(f"pytest shard {shard}")

    if pins.shards[0] in shards:  # CI runs the mobile layout checks in the first shard only
        print("\n  -- Playwright mobile layout checks", flush=True)
        rc = ctx.run(
            ["npx", "--no-install", "playwright", "test",
             "--config", "tests/e2e/ios-layout.config.cjs", "--reporter=line"],
            env={**env, "ODYSSEUS_TEST_PYTHON": str(py), "ODYSSEUS_LAYOUT_BROWSER": "chromium"},
            check=False,
        )
        if rc != 0:
            failed.append("Playwright mobile layout checks")
    if failed:
        raise AssertionError("failed: " + ", ".join(failed))


def check_focused_tests(ctx: Context, result: Result) -> None:
    base_ref = f"origin/{ctx.args.base}"
    try:
        base = git_output("merge-base", base_ref, "HEAD")
    except subprocess.CalledProcessError:
        raise Skip(f"no merge base with {base_ref} (fetch it, or pass --base)")
    ctx.run([sys.executable, ".github/scripts/focused_test_guidance.py",
             "--base-sha", base, "--head-sha", git_output("rev-parse", "HEAD")])


@dataclass(frozen=True)
class Check:
    name: str
    ci_job: str
    workflow: str
    job_id: str
    blocking: bool
    quick: bool
    func: Callable[[Context, Result], None]


CHECKS: tuple[Check, ...] = (
    Check("python-syntax", "CI / Python syntax (compileall)", "ci.yml", "python-syntax", True, True, check_python_syntax),
    Check("node-syntax", "CI / JS syntax (node --check)", "ci.yml", "node-syntax", True, True, check_node_syntax),
    Check("gfm-security", "CI / Benchmark GFM rendering security", "ci.yml", "benchmark-gfm-security", True, True, check_gfm_security),
    Check("pr-title", "PR description check / Check PR title (Conventional Commits)", "pr-description-check.yml", "check-title", True, True, check_pr_title),
    Check("gitleaks", "Secret scan / gitleaks", "secret-scan.yml", "gitleaks", True, True, check_gitleaks),
    Check("actionlint", "Workflow security / actionlint", "workflow-security.yml", "actionlint", True, True, check_actionlint),
    Check("zizmor", "Workflow security / zizmor (Actions SAST)", "workflow-security.yml", "zizmor", True, True, check_zizmor),
    Check("hadolint", "Container scan / hadolint (Dockerfile lint)", "container-scan.yml", "hadolint", True, True, check_hadolint),
    Check("focused-tests", "CI / Focused test guidance (report-only)", "ci.yml", "focused-test-guidance", False, True, check_focused_tests),
    Check("python-tests", "CI / Python tests (all shards) + Playwright mobile layout", "ci.yml", "python-tests", True, False, check_python_tests),
)

# Jobs the harness deliberately does not run, and why. tests/test_ci_local_harness.py
# requires every workflow job to appear either in CHECKS or here.
NOT_RUN: dict[tuple[str, str], str] = {
    ("codeql.yml", "analyze"): "GitHub-only: results go to code scanning, and the job fails only if CodeQL itself errors.",
    ("dependency-review.yml", "dependency-review"): "GitHub-only: compares the dependency graph through GitHub's API (canonical repo only).",
    ("dependency-review.yml", "pip-audit"): "Advisory (continue-on-error) and needs the live vulnerability database.",
    ("pr-description-check.yml", "check-description"): "Checks the PR body on GitHub; its logic is covered by tests/test_pr_description_check.py in the pytest suite.",
    ("pr-description-check.yml", "check-mergeable"): "GitHub-only: labels PRs from GitHub's live mergeability state.",
    ("issue-description-check.yml", "check"): "Runs on issues only; its logic is covered by tests/test_issue_description_check.py.",
    ("container-trivy.yml", "scan"): "Advisory (continue-on-error); needs a Docker daemon and the Trivy database.",
    ("container-trivy.yml", "publish"): "Advisory; uploads SARIF to GitHub.",
    ("docker-publish.yml", "build"): "Push-only image publishing; needs a Docker daemon and registry credentials.",
    ("docker-publish.yml", "merge"): "Push-only manifest merge to GHCR.",
    ("searxng-image.yml", "validate"): "Needs a Docker daemon (pulls and runs the pinned SearXNG image).",
    ("deploy-pages.yml", "build"): "Pages build; never gates a PR.",
    ("deploy-pages.yml", "deploy"): "GitHub-only Pages deployment.",
}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    names = [c.name for c in CHECKS]
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--list", action="store_true", help="show the checks and the CI jobs that cannot run locally")
    p.add_argument("--quick", action="store_true", help="skip the pytest suite (python-tests)")
    p.add_argument("--only", help=f"comma-separated checks to run: {', '.join(names)}")
    p.add_argument("--skip", help="comma-separated checks to leave out")
    p.add_argument("--shard", help="run one pytest shard, e.g. 2/4 (default: all shards, as CI does)")
    p.add_argument("--pr-title", help="PR title to check (default: the HEAD commit subject)")
    p.add_argument("--base", default="dev", help="base branch for focused test guidance (default: dev)")
    p.add_argument("--unshallow", action="store_true", help="fetch full git history before gitleaks, as CI scans it")
    p.add_argument("--reinstall", action="store_true", help="rebuild cached venvs and node_modules")
    p.add_argument("--strict", action="store_true", help="exit 1 if any blocking check was skipped")
    args = p.parse_args(argv)
    for opt in ("only", "skip"):
        value = getattr(args, opt)
        if value:
            unknown = set(value.split(",")) - set(names)
            if unknown:
                p.error(f"unknown check(s) for --{opt}: {', '.join(sorted(unknown))}")
    return args


def print_list(pins: Pins) -> None:
    print("Checks (run in this order):")
    for c in CHECKS:
        tag = "blocking" if c.blocking else "report-only"
        extra = "" if c.quick else "   [not in --quick]"
        print(f"  {c.name:<14} {tag:<11} {c.ci_job}{extra}")
    print(f"\nPins read from .github/workflows/: Python {pins.python_tests} (tests), "
          f"{pins.python_security} (zizmor), Node {pins.node}, gitleaks {pins.gitleaks_version}, "
          f"actionlint {pins.actionlint_version}, zizmor {pins.zizmor}, "
          f"shards {', '.join(pins.shards)}")
    print("\nCI jobs not run locally:")
    for (wf, job), why in NOT_RUN.items():
        print(f"  {wf}:{job:<20} {why}")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        pins = read_pins()
    except PinError as exc:
        print(f"ci_local: {exc}. The workflow files changed shape; update scripts/ci_local.py.",
              file=sys.stderr)
        return 1
    if args.list:
        print_list(pins)
        return 0

    selected = [c for c in CHECKS
                if (not args.only or c.name in args.only.split(","))
                and (not args.skip or c.name not in args.skip.split(","))
                and (c.quick or not args.quick or (args.only and c.name in args.only.split(",")))]
    if args.shard and args.shard not in pins.shards:
        print(f"ci_local: --shard must be one of {', '.join(pins.shards)}", file=sys.stderr)
        return 2

    ctx = Context(args, pins)
    results: list[Result] = []
    for check in selected:
        result = Result(check.name, check.ci_job, check.blocking)
        print(f"\n=== {check.name}  ({check.ci_job})", flush=True)
        start = time.monotonic()
        try:
            check.func(ctx, result)
            result.status = PASS if check.blocking else INFO
        except Skip as exc:
            result.status, result.detail = SKIP, str(exc)
        except (subprocess.CalledProcessError, AssertionError, RuntimeError, OSError) as exc:
            result.status, result.detail = FAIL, str(exc)
        result.seconds = time.monotonic() - start
        result.parity.extend(ctx.parity)
        ctx.parity.clear()
        print(f"--- {check.name}: {result.status}" + (f" ({result.detail})" if result.detail else ""))
        results.append(result)

    print("\n" + "=" * 72)
    print("Summary")
    print("=" * 72)
    for r in results:
        print(f"  {r.status:<4}  {r.name:<14} {r.seconds:6.1f}s  {r.ci_job}")
        if r.detail:
            print(f"        {r.detail}")
        for note in r.parity:
            print(f"        note: {note}")

    failed = [r for r in results if r.blocking and r.status == FAIL]
    skipped = [r for r in results if r.blocking and r.status == SKIP]
    print()
    if failed:
        print(f"{len(failed)} blocking check(s) FAILED: {', '.join(r.name for r in failed)}")
    if skipped:
        print(f"{len(skipped)} blocking check(s) did NOT run here: "
              f"{', '.join(r.name for r in skipped)}. This is not the same as green CI.")
    if not failed and not skipped:
        print("All selected blocking checks passed.")
    print("CI jobs that never run locally are listed by --list.")
    return 1 if failed or (args.strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
