"""The frontier ratchet — the core did not move, and the SDK is not in it.

ADR 0004's promise ("the core never grows") is only worth what a witness can
check. This one interrogates the thing itself: the *bytes* of every file that
existed at v0.1, compared against the v0.1 commit; the *declared dependencies* in
pyproject; and the *imports* of every module outside the transport. Not the
neighbourhood — not "the tests still pass", which would be green over a core
rewrite (ADR 0026).
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]

#: The v0.1 tip. Everything outside the allowlist must still be byte-identical to it.
V0_1_COMMIT = "86bf21dd38eef1cb683a0a124102b6df08381ec7"

#: Paths v0.2 is allowed to add or change: the transport, its tests, its docs,
#: the entry points and the packaging metadata that declare them.
ALLOWED = (
    "src/limes/transports/mcp/",
    "tests/unit/mcp/",
    "tests/integration/mcp/",
    "docs/decisions/0005-mcp-proxy-transport.md",
    "docs/design/mcp-proxy-v0.2.md",
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "uv.lock",
)

#: Core modules whose *prose* had to be corrected (they said "v0.1 ships no MCP
#: proxy"). Their CODE must still be identical — asserted below, not trusted.
DOCSTRING_ONLY = (
    "src/limes/__init__.py",
    "src/limes/transports/__init__.py",
)

CORE_PACKAGE = REPO / "src" / "limes"
TRANSPORT = CORE_PACKAGE / "transports" / "mcp"


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=REPO, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        pytest.skip(f"git could not answer `{' '.join(arguments)}`: {result.stderr.strip()}")
    return result.stdout


def _v0_1_paths() -> set[str]:
    return {
        line
        for line in _git("ls-tree", "-r", "--name-only", V0_1_COMMIT).splitlines()
        if line.strip()
    }


def _working_paths() -> set[str]:
    tracked = _git("ls-files").splitlines()
    untracked = _git("ls-files", "--others", "--exclude-standard").splitlines()
    return {line for line in [*tracked, *untracked] if line.strip()}


def _v0_1_bytes(path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{V0_1_COMMIT}:{path}"], cwd=REPO, capture_output=True, check=False
    )
    assert result.returncode == 0, f"could not read {path} at v0.1"
    return result.stdout


def _is_allowed(path: str) -> bool:
    return any(path == entry or path.startswith(entry) for entry in ALLOWED)


def _code_without_docstring(source: bytes) -> str:
    tree = ast.parse(source)
    first = tree.body[0] if tree.body else None
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        tree.body = tree.body[1:]
    return ast.dump(tree)


def _imported_roots(source: bytes) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_every_v0_1_file_outside_the_transport_is_byte_identical():
    changed = []
    for path in sorted(_v0_1_paths()):
        if _is_allowed(path) or path in DOCSTRING_ONLY:
            continue
        current = REPO / path
        assert current.exists(), f"v0.1 file {path} was deleted"
        if current.read_bytes() != _v0_1_bytes(path):
            changed.append(path)
    assert changed == [], (
        "the MCP proxy is a TRANSPORT (ADR 0004): it may not change the core, the "
        f"detectors, or their tests. These moved: {changed}"
    )


def test_no_new_file_landed_outside_the_transport():
    added = sorted(path for path in _working_paths() - _v0_1_paths() if not _is_allowed(path))
    assert added == [], f"v0.2 added files outside its perimeter: {added}"


@pytest.mark.parametrize("path", DOCSTRING_ONLY)
def test_a_touched_core_module_changed_only_its_docstring(path):
    before = _code_without_docstring(_v0_1_bytes(path))
    after = _code_without_docstring((REPO / path).read_bytes())
    assert before == after, f"{path} was supposed to change only its prose, but its CODE moved"


def test_the_mcp_sdk_is_an_optional_extra_and_never_a_core_dependency():
    manifest = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    core = manifest["project"]["dependencies"]
    assert [name for name in core if name.split(">")[0].strip() == "mcp"] == [], (
        f"`mcp` must never be a core dependency; `pip install limes` stays light. Found: {core}"
    )
    extra = manifest["project"]["optional-dependencies"]["mcp"]
    assert any(name.startswith("mcp") for name in extra), extra
    scripts = manifest["project"]["scripts"]
    assert scripts["limes"].startswith("limes.transports.mcp.")
    assert scripts["limes-proxy"].startswith("limes.transports.mcp.")


def test_no_module_outside_the_transport_imports_the_sdk():
    offenders = {}
    for module in sorted(CORE_PACKAGE.rglob("*.py")):
        if TRANSPORT in module.parents:
            continue
        forbidden = _imported_roots(module.read_bytes()) & {"mcp", "anyio"}
        if forbidden:
            offenders[str(module.relative_to(REPO))] = sorted(forbidden)
    assert offenders == {}, (
        f"the core must import without the `mcp` extra installed; these do not: {offenders}"
    )


def test_the_sdk_is_not_shadowed_by_the_transport_package_name():
    # `limes.transports.mcp` and the SDK's `mcp` share a name. Absolute imports
    # are supposed to resolve to the SDK — this asserts they actually do, rather
    # than trusting the rule.
    import mcp.types

    from limes.transports.mcp import bridge

    resolved = vars(bridge)["types"]
    assert resolved is mcp.types, (
        "`import mcp.types` inside limes.transports.mcp must resolve to the SDK, "
        "not to the package that shares its name"
    )
    assert not (resolved.__file__ or "").startswith(str(TRANSPORT))
    assert isinstance(resolved.LATEST_PROTOCOL_VERSION, str)


def test_the_console_scripts_are_installed_and_answer():
    bindir = Path(sys.executable).parent
    for script in ("limes", "limes-proxy"):
        executable = shutil.which(script) or str(bindir / script)
        assert Path(executable).exists(), f"console script {script} was not installed"
    listing = subprocess.run(
        [shutil.which("limes-proxy") or str(bindir / "limes-proxy"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert listing.returncode == 0, listing.stderr
    assert "-- <server command...>" in listing.stdout
