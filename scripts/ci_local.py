#!/usr/bin/env python3
"""Run the repository's blocking CI checks locally, before pushing.

Usage:
    python3 scripts/ci_local.py                 # every check that can run here
    python3 scripts/ci_local.py --quick         # everything except the pytest suite
    python3 scripts/ci_local.py --only gitleaks,actionlint
    python3 scripts/ci_local.py --shard 2/4     # one pytest shard instead of all four
    python3 scripts/ci_local.py --list          # what maps to which CI job, and what cannot run locally
    python3 scripts/ci_local.py --strict        # exit 1 unless the run was as thorough as CI

Each check mirrors one GitHub Actions job. Tool and runtime versions are read
from the workflow files at run time, so the harness follows the pins in
.github/workflows/ instead of keeping its own copy.

Nothing here uses sudo or changes system packages. Python environments
(including any Python that uv downloads), npm packages, Playwright browsers and
pinned tool binaries live in a cache directory outside the repository
(``$ODYSSEUS_CI_CACHE``, default ``~/.cache/odysseus-ci-local``), plus
``node_modules/`` exactly as ``npm ci`` creates it. Unlike CI, the harness does
not install Chromium's system libraries (``playwright install --with-deps``
needs root); if they are missing, the browser tests fail rather than pass.

Checks read the working tree, while CI checks out the commit. The summary warns
when uncommitted or untracked files could make the two differ, and the secret
scan also covers staged and unstaged changes.

Results:
    PASS   the check ran as CI runs it and passed
    PASS*  it passed, but ran with weaker coverage than CI (see its notes)
    FAIL   it failed
    SKIP   it could not run on this machine (reason given); not a pass
    INFO   report-only check

Exit status: 1 when a blocking check failed; with --strict, also when a
blocking check was skipped, ran with weaker coverage, or was not selected.
0 otherwise. 2 for usage errors.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import os
import platform
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
# from the v2.15.0 hadolint-linux-x86_64 release asset on 2026-11-17.
HADOLINT_VERSION = "2.15.0"
HADOLINT_IMAGE = f"ghcr.io/hadolint/hadolint:v{HADOLINT_VERSION}-debian"
HADOLINT_LINUX_X86_64_SHA256 = "eb8eb4dd06a068cce65cb84743fba69f09ed12a36ff13d58f9af090d6d696970"

# The release assets CI downloads, and so the only ones with pinned checksums,
# are linux-x86_64 builds.
IS_LINUX_X86_64 = sys.platform == "linux" and platform.machine() == "x86_64"

# Variables that would steer pytest differently from a clean CI runner.
PYTEST_ENV_SCRUB = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "APP_PORT")
# Prefixes of variables through which gitleaks, zizmor and hadolint read a
# developer's own configuration; CI's runners set none of them.
TOOL_ENV_PREFIXES = ("GITLEAKS_", "ZIZMOR_", "HADOLINT_")


def clean_tool_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith(TOOL_ENV_PREFIXES)}


def version_of(text: str) -> str | None:
    match = re.search(r"\bv?(\d+\.\d+\.\d+)\b", text)
    return match.group(1) if match else None


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
    uv: str
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
        python_tests=_one(r'python-version:\s*["\']?(3\.\d+)', ci, "the CI Python version"),
        python_security=_one(r'python-version:\s*["\']?(3\.\d+)', wsec, "the zizmor Python version"),
        node=_one(r'node-version:\s*["\']?([\d.]+)', ci, "the Node version"),
        uv=_one(r'^\s*version:\s*["\']?([\d.]+)', ci, "the uv version"),
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


def pr_title_ok(regex: str, title: str) -> bool:
    """Match like the workflow's JavaScript regex: \\w and friends are ASCII-only."""
    return re.match(regex, title, re.ASCII) is not None


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

    @property
    def degraded(self) -> bool:
        return self.status == PASS and bool(self.parity)


def cache_dir() -> Path:
    raw = os.environ.get("ODYSSEUS_CI_CACHE") or str(
        Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "odysseus-ci-local"
    )
    return Path(raw).expanduser().resolve()


class Context:
    def __init__(self, args: argparse.Namespace, pins: Pins):
        self.args = args
        self.pins = pins
        self.cache = cache_dir()
        self.cache.mkdir(parents=True, exist_ok=True)
        if args.reinstall and (self.cache / "bin").exists():
            shutil.rmtree(self.cache / "bin")
        self.parity: list[str] = []

    def note(self, message: str) -> None:
        if message not in self.parity:
            self.parity.append(message)

    def uv_env(self) -> dict[str, str]:
        """Keep any Python that uv downloads inside the cache."""
        return {
            "UV_PYTHON_INSTALL_DIR": str(self.cache / "uv-python"),
            "UV_PYTHON_BIN_DIR": str(self.cache / "uv-python" / "bin"),
        }

    def run(self, cmd: list[str] | str, *, env: dict[str, str] | None = None,
            cwd: Path = REPO, check: bool = True, shell: bool = False,
            base_env: dict[str, str] | None = None) -> int:
        shown = cmd if isinstance(cmd, str) else " ".join(cmd)
        print(f"  $ {shown}", flush=True)
        full_env = {**(os.environ if base_env is None else base_env), **(env or {})}
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


def git_output(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def tree_changes() -> tuple[list[str], list[str]]:
    """Return (modified or staged tracked paths, untracked non-ignored paths).

    Uses NUL-separated output, so paths with spaces or non-ASCII characters
    arrive unquoted.
    """
    status = subprocess.run(
        ["git", "status", "--porcelain", "-z", "--untracked-files=no"],
        cwd=REPO, capture_output=True, check=True,
    ).stdout.decode("utf-8", "surrogateescape").split("\0")
    modified, entries = [], iter(status)
    for entry in entries:
        if not entry:
            continue
        modified.append(entry[3:])
        if entry[0] in "RC":  # renames and copies carry the old path as a second field
            next(entries, None)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=REPO, capture_output=True, check=True,
    ).stdout.decode("utf-8", "surrogateescape").split("\0")
    return modified, [u for u in untracked if u]


# --------------------------------------------------------------------------
# Environments: Python, venvs, npm packages, pinned binaries
# --------------------------------------------------------------------------


def find_python(ctx: Context, version: str) -> list[str]:
    """Return a command that runs Python `version`, or raise Skip."""
    exe = shutil.which(f"python{version}")
    if exe:
        probe = subprocess.run([exe, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                               capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == version:
            return [exe]
    if shutil.which("uv") is None:
        raise Skip(f"Python {version} is needed (CI pins it) and neither python{version} nor uv is installed")
    # A Python uv already manages, in its default location, is fine to reuse.
    found = subprocess.run(["uv", "python", "find", version], capture_output=True, text=True)
    if found.returncode == 0:
        return [found.stdout.strip()]
    # Otherwise install one into the cache (UV_PYTHON_BIN_DIR keeps its shims there too).
    env = {**os.environ, **ctx.uv_env()}
    found = subprocess.run(["uv", "python", "find", version], capture_output=True, text=True, env=env)
    if found.returncode == 0:
        return [found.stdout.strip()]
    install = subprocess.run(["uv", "python", "install", version], capture_output=True, text=True, env=env)
    found = subprocess.run(["uv", "python", "find", version], capture_output=True, text=True, env=env)
    if install.returncode != 0 or found.returncode != 0:
        reason = (install.stderr or found.stderr).strip().splitlines()[-1:] or ["unknown error"]
        raise Skip(f"Python {version} is needed and uv could not install it: {reason[0]}")
    return [found.stdout.strip()]


def pip_install(*args: str) -> list[str]:
    """An install step for venv(): uv when present (as CI uses), else pip."""
    if shutil.which("uv"):
        return ["uv", "pip", "install", "--python", "{py}", *args]
    return ["{py}", "-m", "pip", "install", "--disable-pip-version-check", *args]


def check_uv_version(ctx: Context) -> None:
    if shutil.which("uv") is None:
        ctx.note(f"uv is not installed, so pip resolved the packages; CI uses uv {ctx.pins.uv}.")
        return
    version = subprocess.run(["uv", "--version"], capture_output=True, text=True).stdout.split()
    if len(version) < 2 or version[1] != ctx.pins.uv:
        found = version[1] if len(version) > 1 else "unknown"
        ctx.note(f"uv is {found}; CI pins uv {ctx.pins.uv}.")


def venv(ctx: Context, label: str, version: str, steps: list[list[str]], key: str,
         result: Result | None = None) -> Path:
    """Create or reuse a cached venv and return its python.

    The venv is rebuilt, running `steps`, whenever `key` changes or --reinstall
    is given. The old venv is moved aside first and deleted only once every
    step has succeeded; if the rebuild fails, the old venv is put back and
    used, and the result gets a note saying its dependencies may be older.
    """
    root = ctx.cache / f"venv-{label}-py{version}"
    py = root / "bin" / "python"
    marker = root / ".ci-local-key"
    if py.exists() and marker.exists() and marker.read_text() == key and not ctx.args.reinstall:
        return py
    base_python = find_python(ctx, version)
    backup = root.with_name(root.name + ".previous")
    if backup.exists():
        shutil.rmtree(backup)
    if root.exists():
        root.rename(backup)
    try:
        ctx.run([*base_python, "-m", "venv", str(root)])
        for step in steps:
            ctx.run([str(py) if part == "{py}" else part for part in step], env=ctx.uv_env())
    except (subprocess.CalledProcessError, OSError) as exc:
        shutil.rmtree(root, ignore_errors=True)
        if not backup.exists():
            raise
        backup.rename(root)  # never lose a working venv to a failed rebuild
        if result is not None:
            result.parity.append(
                f"Could not rebuild the {label} environment ({exc}); used the existing one, "
                "whose dependencies may be older than CI's."
            )
            return py
        raise
    shutil.rmtree(backup, ignore_errors=True)
    marker.write_text(key)
    return py


def npm_install(ctx: Context, *, ignore_scripts: bool) -> None:
    """Run `npm ci` unless node_modules already matches the manifest, lockfile and mode."""
    need("node", "npm")
    node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
    if node != f"v{ctx.pins.node}":
        ctx.note(f"Node is {node}; CI pins v{ctx.pins.node}.")

    def key(mode: str) -> str:
        return _digest(REPO / "package.json", REPO / "package-lock.json", extra=f"{mode}|{node}")

    marker = REPO / "node_modules" / ".ci-local-key"
    wanted = key("ignore-scripts" if ignore_scripts else "full")
    acceptable = {wanted, key("full")}  # a full install also satisfies an ignore-scripts request
    if marker.exists() and marker.read_text() in acceptable and not ctx.args.reinstall:
        # `npm ls` exits non-zero on extraneous or missing packages, e.g. after
        # a local `npm install --no-save`, which `npm ci` would remove.
        if subprocess.run(["npm", "ls", "--all"], cwd=REPO, capture_output=True).returncode == 0:
            return
    cmd = ["npm", "ci", "--no-audit", "--no-fund"]
    if ignore_scripts:
        cmd.insert(2, "--ignore-scripts")
    ctx.run(cmd)
    marker.write_text(wanted)


def pinned_binary(ctx: Context, name: str, url: str, sha256: str, member: str | None) -> Path:
    """Download a pinned release asset into the cache, verify it, and return the binary."""
    need("curl")
    dest = ctx.cache / "bin" / f"{name}-{sha256[:12]}"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        download = Path(tmp) / "asset"
        ctx.run(["curl", "-fsSL", "-o", str(download), url])
        actual = hashlib.sha256(download.read_bytes()).hexdigest()
        if actual != sha256:
            raise RuntimeError(f"{name}: checksum mismatch (expected {sha256}, got {actual})")
        staged = Path(tmp) / "binary"
        if member:
            try:
                with tarfile.open(download) as tar:
                    src = tar.extractfile(member)
                    if src is None:
                        raise KeyError(member)
                    staged.write_bytes(src.read())
            except (KeyError, tarfile.TarError) as exc:
                raise RuntimeError(f"{name}: could not extract {member} from {url}: {exc}") from exc
        else:
            shutil.copyfile(download, staged)
        staged.chmod(0o755)
        os.replace(staged, dest)  # atomic: an interrupted run never leaves a partial binary
    return dest


def release_tool(ctx: Context, result: Result, name: str, version: str,
                 url: str, sha256: str, member: str) -> str:
    """The pinned linux-x86_64 build, or on other platforms a matching binary on PATH."""
    if IS_LINUX_X86_64:
        return str(pinned_binary(ctx, name, url, sha256, member))
    exe = shutil.which(name)
    if exe is None:
        raise Skip(f"CI's pinned {name} build is linux-x86_64 only; install {name} {version} to run this check here")
    found = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout.strip()
    if version_of(found) != version:
        result.parity.append(f"{name} on PATH is not v{version} ({found or 'unknown version'}).")
    return exe


def docker_running() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_python_syntax(ctx: Context, result: Result) -> None:
    py = find_python(ctx, ctx.pins.python_tests)
    ctx.run([*py, "-m", "compileall", "-q", *ctx.pins.compileall_targets])
    ctx.run([*py, "scripts/build_frontend.py", "--check"])


def _through_symlinked_dir(rel: str) -> bool:
    parts = Path(rel).parts[:-1]
    return any((REPO.joinpath(*parts[: i + 1])).is_symlink() for i in range(len(parts)))


def node_check_files(globs: tuple[str, ...]) -> list[str]:
    """Expand CI's `shopt -s globstar nullglob` patterns the way bash does.

    A pattern without glob characters is passed through even when the file is
    missing (nullglob only drops patterns that are globs), so a deleted file
    fails here as it does in CI. Like bash globstar, `**` does not descend
    into symlinked directories. Done in Python so bash 4 is not required.
    """
    files: list[str] = []
    for pattern in globs:
        if not any(ch in pattern for ch in "*?["):
            files.append(pattern)
            continue
        matches = glob.glob(str(REPO / pattern), recursive=True)
        rels = sorted(os.path.relpath(m, REPO) for m in matches)
        files.extend(r for r in rels if not _through_symlinked_dir(r))
    return files


def check_node_syntax(ctx: Context, result: Result) -> None:
    npm_install(ctx, ignore_scripts=True)
    ctx.run(["node", "scripts/check_frontend.mjs"])
    files = node_check_files(ctx.pins.node_check_globs)
    print(f"  $ node --check  ({len(files)} files from {' '.join(ctx.pins.node_check_globs)})")
    for path in files + ["scripts/check_frontend.mjs"]:
        proc = subprocess.run(["node", "--check", path], cwd=REPO)
        if proc.returncode != 0:
            raise AssertionError(f"node --check failed for {path}")
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
    if not pr_title_ok(ctx.pins.pr_title_regex, title):
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
    gitleaks = release_tool(
        ctx, result, "gitleaks", v,
        f"https://github.com/gitleaks/gitleaks/releases/download/v{v}/gitleaks_{v}_linux_x64.tar.gz",
        ctx.pins.gitleaks_sha256, "gitleaks",
    )
    # CI loads .gitleaks.toml from the scanned repository; pass it explicitly so
    # a GITLEAKS_CONFIG in the developer's environment cannot replace it.
    config = str(REPO / ".gitleaks.toml")
    flags = ["--no-banner", "--redact", "--verbose", "--config", config]
    env = clean_tool_env()
    ctx.run([gitleaks, "git", *flags, "."], base_env=env)  # what CI runs: the committed history
    modified, untracked = tree_changes()
    if modified:
        # Content CI will scan once it is committed: staged and unstaged changes.
        ctx.run([gitleaks, "git", "--staged", *flags, "."], base_env=env)
        ctx.run([gitleaks, "git", "--pre-commit", *flags, "."], base_env=env)
    regular = [u for u in untracked if (REPO / u).is_file() and not (REPO / u).is_symlink()]
    if len(regular) != len(untracked):
        result.parity.append(
            f"{len(untracked) - len(regular)} untracked entries that are not regular files "
            "(symlinks, nested repositories) were not scanned."
        )
    if regular:
        with tempfile.TemporaryDirectory() as tmp:
            for rel in regular:
                target = Path(tmp) / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / rel, target)
            ctx.run([gitleaks, "dir", *flags, tmp], base_env=env)


def check_actionlint(ctx: Context, result: Result) -> None:
    if shutil.which("shellcheck") is None:
        result.parity.append(
            "shellcheck is not installed, so actionlint skipped the shell-script "
            "checks that CI's runner (which has shellcheck) performs."
        )
    v = ctx.pins.actionlint_version
    actionlint = release_tool(
        ctx, result, "actionlint", v,
        f"https://github.com/rhysd/actionlint/releases/download/v{v}/actionlint_{v}_linux_amd64.tar.gz",
        ctx.pins.actionlint_sha256, "actionlint",
    )
    ctx.run([actionlint, "-color"])


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
    ctx.run([str(py), "scripts/check_ca_trust.py", "--system"])
    ctx.run([str(py.parent / "zizmor"), "--offline", "--min-severity=low", ".github/workflows/"],
            base_env=clean_tool_env())


def check_hadolint(ctx: Context, result: Result) -> None:
    ignores = [arg for rule in ctx.pins.hadolint_ignore for arg in ("--ignore", rule)]
    env = clean_tool_env()
    with tempfile.TemporaryDirectory() as tmp:
        # The repo has no .hadolint.yaml and CI's action container has no user
        # config; an empty config keeps ~/.config/hadolint.yaml out as well.
        empty = Path(tmp) / "hadolint.yaml"
        empty.write_text("{}\n")
        lint = ["--config", str(empty), "--failure-threshold", "info", *ignores]
        if IS_LINUX_X86_64:  # prefer the checksum-verified binary over a mutable image tag
            binary = pinned_binary(
                ctx, "hadolint",
                f"https://github.com/hadolint/hadolint/releases/download/v{HADOLINT_VERSION}/hadolint-linux-x86_64",
                HADOLINT_LINUX_X86_64_SHA256, None,
            )
            ctx.run([str(binary), *lint, "Dockerfile"], base_env=env)
            return
        exe = shutil.which("hadolint")
        if exe:
            version = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout
            if version_of(version) != HADOLINT_VERSION:
                result.parity.append(f"hadolint on PATH is not v{HADOLINT_VERSION} ({version.strip()}).")
            ctx.run([exe, *lint, "Dockerfile"], base_env=env)
            return
    if docker_running():
        # The image hadolint-action's Dockerfile builds FROM, as CI uses it; a
        # fresh container has no user config.
        ignore_args = " ".join(f"--ignore {rule}" for rule in ctx.pins.hadolint_ignore)
        ctx.run(f"docker run --rm -i {HADOLINT_IMAGE} hadolint --failure-threshold info "
                f"{ignore_args} - < Dockerfile", shell=True)
        return
    raise Skip("no hadolint binary or Docker daemon, and the pinned download is linux-x86_64 only")


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None or shutil.which("timeout") is None:
        return False
    probe = subprocess.run(
        ["timeout", "3s", "bwrap", "--die-with-parent", "--unshare-pid", "--ro-bind", "/", "/",
         "--proc", "/proc", "--dev", "/dev", "/bin/true"],
        capture_output=True,
    )
    return probe.returncode == 0


def pytest_env() -> tuple[dict[str, str], list[str]]:
    """The developer's environment minus variables a clean CI runner would not have."""
    env = dict(os.environ)
    dropped = []
    for name in list(env):
        if name in PYTEST_ENV_SCRUB or (name.startswith("ODYSSEUS_") and name != "ODYSSEUS_CI_CACHE"):
            dropped.append(name)
            del env[name]
    return env, sorted(dropped)


def check_python_tests(ctx: Context, result: Result) -> None:
    need("ffmpeg")
    if not _bwrap_works():
        if not ctx.args.without_bwrap:
            raise Skip(
                "bubblewrap is missing or its PID/mount-namespace probe failed, and CI refuses "
                "to start pytest in that state (the containment tests would fail). Install "
                "bubblewrap with unprivileged user namespaces enabled, or pass --without-bwrap "
                "to run the suite anyway and expect containment failures"
            )
        result.parity.append(
            "Ran without working bubblewrap (--without-bwrap). CI refuses to start pytest "
            "in that state, and containment tests fail here for that reason alone."
        )
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        result.parity.append(
            "Running as root. CI runs as an unprivileged user, and some tests skip under root."
        )

    pins = ctx.pins
    # As in CI, establish system trust before any installer runs.
    ctx.run([*find_python(ctx, pins.python_tests), "scripts/check_ca_trust.py", "--system"])
    check_uv_version(ctx)
    bootstrap = str(REPO / "requirements-bootstrap.txt")
    playwright = f"playwright=={pins.playwright}"
    requirements = str(REPO / "requirements.txt")
    # requirements.txt is mostly unpinned, and CI installs it into a fresh
    # runner every time, getting the newest releases. Rebuilding this venv each
    # day (or with --reinstall) keeps it close to that without upgrading the
    # hash-pinned bootstrap packages, which CI never upgrades either.
    day = time.strftime("%Y-%m-%d")
    py = venv(
        ctx, "tests", pins.python_tests,
        [
            pip_install("--require-hashes", "--only-binary=:all:", "--no-deps", "-r", bootstrap),
            ["{py}", str(REPO / "scripts" / "check_ca_trust.py"), "--python"],
            pip_install("-r", requirements),
            pip_install(playwright),
        ],
        key=_digest(REPO / "requirements-bootstrap.txt", REPO / "requirements.txt",
                    extra=f"{playwright}|{day}"),
        result=result,
    )
    npm_install(ctx, ignore_scripts=False)
    browsers = {"PLAYWRIGHT_BROWSERS_PATH": str(ctx.cache / "ms-playwright")}
    ctx.run(["npx", "playwright", "install", "chromium"], env=browsers)
    (REPO / "data").mkdir(exist_ok=True)
    ctx.run([str(py), "scripts/check_ca_trust.py", "--system", "--python"])

    base_env, dropped = pytest_env()
    if dropped:
        print(f"  (unset for pytest, as on a clean CI runner: {', '.join(dropped)})")
    # GitHub Actions sets these implicitly; the suite fails (instead of skipping)
    # browser and acorn tests when CI is set and their packages are missing.
    env = {"CI": "true", "GITHUB_ACTIONS": "true", **browsers}
    shards = [ctx.args.shard] if ctx.args.shard else list(pins.shards)
    if ctx.args.shard:
        result.parity.append(f"Only pytest shard {ctx.args.shard} ran; CI runs all of {', '.join(pins.shards)}.")
    failed = []
    for shard in shards:  # fail-fast: false in CI, so every shard runs
        print(f"\n  -- pytest shard {shard}", flush=True)
        rc = ctx.run([str(py), "-m", "pytest", "-q", "-rs", "--durations=25", "--shard", shard],
                     env=env, base_env=base_env, check=False)
        if rc != 0:
            failed.append(f"pytest shard {shard}")

    if pins.shards[0] in shards:  # CI runs the mobile layout checks in the first shard only
        print("\n  -- Playwright mobile layout checks", flush=True)
        rc = ctx.run(
            ["npx", "--no-install", "playwright", "test",
             "--config", "tests/e2e/ios-layout.config.cjs", "--reporter=line"],
            env={**env, "ODYSSEUS_TEST_PYTHON": str(py), "ODYSSEUS_LAYOUT_BROWSER": "chromium"},
            base_env=base_env, check=False,
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

# A digest of each mirrored job's definition. tests/test_ci_local_harness.py
# recomputes these from the workflow files; when a job changes, the test fails
# until someone checks the matching check above still mirrors it and updates
# the digest here.
JOB_DIGESTS: dict[tuple[str, str], str] = {
    ("ci.yml", "python-syntax"): "e9416416dcc5925a",
    ("ci.yml", "node-syntax"): "55dfd13112cafc54",
    ("ci.yml", "benchmark-gfm-security"): "99757f8a8db5c019",
    ("pr-description-check.yml", "check-title"): "e52dcb3f71ec2c04",
    ("secret-scan.yml", "gitleaks"): "e3fc5117ce0496fa",
    ("workflow-security.yml", "actionlint"): "b10a7bab85e033f1",
    ("workflow-security.yml", "zizmor"): "8ccfabd87badda45",
    ("container-scan.yml", "hadolint"): "dd770a1359f96435",
    ("ci.yml", "focused-test-guidance"): "253d96b48d618cfd",
    ("ci.yml", "python-tests"): "e111dec31e88dbce",
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
    p.add_argument("--without-bwrap", action="store_true",
                   help="run the pytest suite even without working bubblewrap (CI refuses to)")
    p.add_argument("--reinstall", action="store_true", help="rebuild cached venvs, node_modules and tool binaries")
    p.add_argument("--strict", action="store_true",
                   help="exit 1 unless every blocking check ran, with CI's coverage, and passed")
    args = p.parse_args(argv)
    for opt in ("only", "skip"):
        value = getattr(args, opt)
        if value:
            unknown = set(value.split(",")) - set(names)
            if unknown:
                p.error(f"unknown check(s) for --{opt}: {', '.join(sorted(unknown))}")
    return args


def select(args: argparse.Namespace) -> list[Check]:
    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()
    chosen = []
    for c in CHECKS:
        if only is not None and c.name not in only:
            continue
        if c.name in skip:
            continue
        if args.quick and not c.quick and not (only and c.name in only):
            continue
        chosen.append(c)
    return chosen


def print_list(pins: Pins) -> None:
    print("Checks (run in this order):")
    for c in CHECKS:
        tag = "blocking" if c.blocking else "report-only"
        extra = "" if c.quick else "   [not in --quick]"
        print(f"  {c.name:<14} {tag:<11} {c.ci_job}{extra}")
    print(f"\nPins read from .github/workflows/: Python {pins.python_tests} (tests), "
          f"{pins.python_security} (zizmor), Node {pins.node}, uv {pins.uv}, "
          f"gitleaks {pins.gitleaks_version}, actionlint {pins.actionlint_version}, "
          f"zizmor {pins.zizmor}, shards {', '.join(pins.shards)}")
    print("\nCI jobs not run locally:")
    width = max(len(f"{wf}:{job}") for wf, job in NOT_RUN)
    for (wf, job), why in NOT_RUN.items():
        print(f"  {f'{wf}:{job}':<{width}}  {why}")


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
    if args.shard and args.shard not in pins.shards:
        print(f"ci_local: --shard must be one of {', '.join(pins.shards)}", file=sys.stderr)
        return 2
    selected = select(args)
    if not selected:
        print("ci_local: no checks selected", file=sys.stderr)
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
        except Exception as exc:  # a harness bug must not hide the other checks' results
            result.status, result.detail = FAIL, f"internal error: {type(exc).__name__}: {exc}"
        result.seconds = time.monotonic() - start
        for note in ctx.parity:
            if note not in result.parity:
                result.parity.append(note)
        ctx.parity.clear()
        label = "PASS*" if result.degraded else result.status
        print(f"--- {check.name}: {label}" + (f" ({result.detail})" if result.detail else ""))
        results.append(result)

    try:
        modified, untracked = tree_changes()
        tree_known = True
    except (subprocess.CalledProcessError, OSError):
        modified, untracked, tree_known = [], [], False
    print("\n" + "=" * 72)
    print("Summary")
    print("=" * 72)
    for r in results:
        label = "PASS*" if r.degraded else r.status
        print(f"  {label:<5} {r.name:<14} {r.seconds:6.1f}s  {r.ci_job}")
        if r.detail:
            print(f"        {r.detail}")
        for note in r.parity:
            print(f"        note: {note}")

    failed = [r for r in results if r.blocking and r.status == FAIL]
    skipped = [r for r in results if r.blocking and r.status == SKIP]
    degraded = [r for r in results if r.blocking and r.degraded]
    not_selected = [c for c in CHECKS if c.blocking and c not in selected]
    print()
    if not tree_known:
        print("Could not read the git working tree state, so uncommitted changes were not checked.")
    elif modified or untracked:
        print(f"Working tree differs from HEAD ({len(modified)} modified, {len(untracked)} untracked "
              "file(s)). These checks read the files on disk; CI checks out only the commit.")
    if failed:
        print(f"{len(failed)} blocking check(s) FAILED: {', '.join(r.name for r in failed)}")
    if skipped:
        print(f"{len(skipped)} blocking check(s) did NOT run here: "
              f"{', '.join(r.name for r in skipped)}. This is not the same as green CI.")
    if degraded:
        print(f"{len(degraded)} blocking check(s) passed with weaker coverage than CI (PASS*): "
              f"{', '.join(r.name for r in degraded)}.")
    if not_selected:
        print(f"Partial run: {len(not_selected)} blocking check(s) not selected: "
              f"{', '.join(c.name for c in not_selected)}.")
    if not (failed or skipped or degraded or not_selected):
        print("All blocking checks passed with CI's coverage.")
    elif not failed:
        print("No selected blocking check failed.")
    print("CI jobs that never run locally are listed by --list.")
    incomplete = bool(skipped or degraded or not_selected)
    return 1 if failed or (args.strict and incomplete) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
