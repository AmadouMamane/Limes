"""The frontier ratchet — the core did not move, and the SDK is not in it.

ADR 0004's promise ("the core never grows") is only worth what a witness can
check. This one interrogates the thing itself: the *bytes* of every file that
existed at v0.1, compared against the v0.1 commit; the *declared dependencies* in
pyproject; and the *imports* of every module outside the transports. Not the
neighbourhood — not "the tests still pass", which would be green over a core
rewrite (ADR 0026).

It is deliberately written as a **complement**: everything the transports are
allowed to touch is listed in :data:`ALLOWED`, and *everything else* must be
byte-identical. An allowlist ratchet has one classic failure mode, though —
somebody widens the allowlist and the ratchet reports green over the very file it
was protecting. So the load-bearing modules are *also* named positively, in
:data:`CORE`, and two things are asserted about them: they are byte-identical,
and they are **not covered by ALLOWED**. Widening the list no longer buys silence.

Transports may move. ``limes/transports/in_process.py`` gained an egress leg in
v0.3 (ADR 0006) and ``limes/transports/redaction.py`` is new; that is what a
transport layer is for. The core, the pipeline, the detectors and their tests are
what may not move — and have not, since v0.1.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: The v0.1 tip. Everything outside the allowlist must still be byte-identical to it.
V0_1_COMMIT = "86bf21dd38eef1cb683a0a124102b6df08381ec7"

#: Paths the transports are allowed to add or change: the transport modules, their
#: tests, their docs, the entry points and the packaging metadata that declare them.
ALLOWED = (
    "src/limes/transports/mcp/",
    "src/limes/transports/redaction.py",
    "src/limes/transports/in_process.py",
    "tests/unit/mcp/",
    "tests/unit/redaction/",
    "tests/unit/test_frontier.py",
    "tests/integration/mcp/",
    "docs/decisions/0005-mcp-proxy-transport.md",
    "docs/decisions/0006-egress-redaction.md",
    "docs/design/mcp-proxy-v0.2.md",
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "uv.lock",
)

#: The load-bearing modules, named rather than merely implied. Whatever ALLOWED
#: says, these are byte-identical to v0.1 — that is the ADR 0004 claim, and it is
#: what a reader of this file should be able to check without reconstructing a
#: set difference in their head.
CORE = (
    "src/limes/guard.py",
    "src/limes/verdict.py",
    "src/limes/spans.py",
    "src/limes/detector.py",
    "src/limes/record.py",
    "src/limes/policy.py",
    "src/limes/registry.py",
    "src/limes/detectors/__init__.py",
    "src/limes/detectors/injection.py",
    "src/limes/detectors/policy.yaml",
    "src/limes/eval/harness.py",
    "src/limes/eval/corpus.py",
    "src/limes/eval/power.py",
    "src/limes/baselines/tessera_regex.py",
    "tests/unit/test_verdict.py",
    "tests/unit/test_record_chain.py",
    "tests/unit/test_detector_protocol.py",
    "tests/unit/test_injection_detector.py",
    "tests/unit/test_admission_rule.py",
    "tests/unit/test_power.py",
    "tests/unit/test_corpus_provenance.py",
    "tests/unit/ratchets/test_allow_needs_evidence_mypy.py",
    "tests/unit/ratchets/test_exceptions_frozen_at_zero.py",
    "tests/unit/ratchets/test_guard_refuses_unknown.py",
    "tests/unit/ratchets/test_null_result_carries_power.py",
)

#: Core modules whose *prose* had to be corrected as the transports grew (they
#: said "v0.1 ships no MCP proxy"). Their CODE must still be identical — asserted
#: below, not trusted. They are deliberately absent from CORE, which asserts
#: byte-identity: a file cannot be in both lists, and this one is the weaker claim.
DOCSTRING_ONLY = (
    "src/limes/__init__.py",
    "src/limes/transports/__init__.py",
)

CORE_PACKAGE = REPO / "src" / "limes"
TRANSPORTS = CORE_PACKAGE / "transports"
MCP_TRANSPORT = TRANSPORTS / "mcp"


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


# --- the named core ---------------------------------------------------------


def test_every_path_this_ratchet_claims_to_protect_actually_exists():
    # A ratchet that names a file which is not there protects nothing and reports
    # green about it (ADR 0026). CORE is checked against the v0.1 tree it freezes.
    missing = sorted(set(CORE) - _v0_1_paths())
    assert missing == [], f"CORE names paths that never existed at v0.1: {missing}"


def test_the_named_core_is_not_covered_by_the_allowlist():
    # This is the anti-widening check. Adding "src/limes/" to ALLOWED to make a
    # red go away would leave this one red.
    escaped = sorted(path for path in CORE if _is_allowed(path))
    assert escaped == [], (
        "these core paths were made writable by widening ALLOWED; the allowlist is "
        f"for transports, and the core is not one: {escaped}"
    )


@pytest.mark.parametrize("path", CORE)
def test_the_named_core_is_byte_identical_to_v0_1(path):
    assert (REPO / path).read_bytes() == _v0_1_bytes(path), (
        f"{path} is the core, the pipeline or a detector (ADR 0004). A transport "
        "behaviour may not change it — and egress redaction did not need to: the "
        "offsets it masks by were already in the evidence."
    )


# --- the complement ---------------------------------------------------------


def test_every_v0_1_file_outside_the_transports_is_byte_identical():
    changed = []
    for path in sorted(_v0_1_paths()):
        if _is_allowed(path) or path in DOCSTRING_ONLY:
            continue
        current = REPO / path
        assert current.exists(), f"v0.1 file {path} was deleted"
        if current.read_bytes() != _v0_1_bytes(path):
            changed.append(path)
    assert changed == [], (
        "a transport (ADR 0004) may not change the core, the detectors, or their "
        f"tests. These moved: {changed}"
    )


def test_no_new_file_landed_outside_the_transports():
    added = sorted(path for path in _working_paths() - _v0_1_paths() if not _is_allowed(path))
    assert added == [], f"files landed outside the transport perimeter: {added}"


@pytest.mark.parametrize("path", DOCSTRING_ONLY)
def test_a_touched_core_module_changed_only_its_docstring(path):
    before = _code_without_docstring(_v0_1_bytes(path))
    after = _code_without_docstring((REPO / path).read_bytes())
    assert before == after, f"{path} was supposed to change only its prose, but its CODE moved"


# --- the dependency frontier ------------------------------------------------


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


def test_no_module_outside_the_mcp_transport_imports_the_sdk():
    offenders = {}
    for module in sorted(CORE_PACKAGE.rglob("*.py")):
        if MCP_TRANSPORT in module.parents:
            continue
        forbidden = _imported_roots(module.read_bytes()) & {"mcp", "anyio"}
        if forbidden:
            offenders[str(module.relative_to(REPO))] = sorted(forbidden)
    assert offenders == {}, (
        f"the core must import without the `mcp` extra installed; these do not: {offenders}"
    )


def test_the_shared_redaction_module_is_reachable_without_the_sdk():
    # It is imported by both transports, so it must sit on the light side of the
    # extra. Asked of the module itself rather than of its import list.
    from limes.transports import redaction

    assert redaction.__file__ is not None
    assert not redaction.__file__.startswith(str(MCP_TRANSPORT))
    assert "mcp" not in _imported_roots(Path(redaction.__file__).read_bytes())


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
    assert not (resolved.__file__ or "").startswith(str(MCP_TRANSPORT))
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
