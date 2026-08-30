"""The frontier ratchet — the core did not move, and the SDK is not in it.

ADR 0004's promise ("the core never grows") is only worth what a witness can
check. This one interrogates the thing itself: the *bytes* of every file that
existed at v0.1, compared against the v0.1 commit; the *declared dependencies* in
pyproject; and the *imports* of every module outside the transports. Not the
neighbourhood — not "the tests still pass", which would be green over a core
rewrite (ADR 0026).

ADR 0004 names **three** places a capability may land — a detector, a policy, or
a transport — so this file names three perimeters, and *everything else* must be
byte-identical:

* :data:`ALLOWED` — the transports and the CLI usage surface (v0.2 → v0.4).
* :data:`DETECTOR_PERIMETER` — where an admitted detector lives: its rules, its
  checksums, its corpus, its harness, its baseline, its matrix, its tests. Every
  entry is an exact path or a directory that did not exist at v0.1, never a
  prefix that could swallow a core module.
* :data:`ADMISSION_SURFACE` — the two files that *must* move when a detector is
  admitted: the registry tuple and its enforcer. Byte-identity is the wrong
  witness for them (a registry that can never gain an entry makes ADR 0003's
  admission procedure unreachable), so each has a stronger, specific one below.

An allowlist ratchet has one classic failure mode: somebody widens the list and
the ratchet reports green over the very file it was protecting. So the
load-bearing modules are *also* named positively, in :data:`CORE`, and two things
are asserted about them — they are byte-identical, and they are **not covered by
any perimeter**. Widening a list no longer buys silence.

One core file has moved once, by decision rather than by drift: ADR 0011 made
the content digest total, and :data:`AMENDED` pins ``guard.py`` to the sha256 of
its post-ADR bytes. The witness is the same shape — these exact bytes, nothing
else — with a different, named reference.
"""

from __future__ import annotations

import ast
import hashlib
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: The v0.1 tip. Everything outside the perimeters must still be byte-identical to it.
V0_1_COMMIT = "86bf21dd38eef1cb683a0a124102b6df08381ec7"

#: The perimeter the core is NOT in: the transport modules, the CLI usage surface,
#: their tests, their docs, and the entry points and packaging metadata that
#: declare them.
ALLOWED = (
    "src/limes/transports/mcp/",
    "src/limes/transports/redaction.py",
    "src/limes/transports/in_process.py",
    "src/limes/cli.py",
    "tests/unit/mcp/",
    "tests/unit/redaction/",
    "tests/unit/cli/",
    "tests/unit/test_frontier.py",
    "tests/integration/mcp/",
    "docs/decisions/0005-mcp-proxy-transport.md",
    "docs/decisions/0006-egress-redaction.md",
    "docs/decisions/0007-mcp-streamable-http-transport.md",
    "docs/decisions/0008-mask-styles.md",
    "docs/decisions/0011-a-crash-is-not-a-verdict.md",
    "docs/design/mcp-proxy-v0.2.md",
    "docs/images/",
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "uv.lock",
)

#: Where a detector lands (ADR 0004's second bucket). Exact paths, and two
#: directories that did not exist at v0.1 — deliberately NOT the prefix
#: ``src/limes/detectors/``, which would cover ``injection.py`` and ``policy.yaml``
#: and quietly unfreeze the detector this project was built around.
DETECTOR_PERIMETER = (
    "src/limes/detectors/checksums.py",
    "src/limes/detectors/egress_policy.py",
    "src/limes/detectors/egress_scan.py",
    "src/limes/detectors/egress.yaml",
    "src/limes/detectors/pii_egress.py",
    "src/limes/detectors/secrets_egress.py",
    "src/limes/detectors/injection_egress.py",
    "src/limes/corpus/egress/",
    "src/limes/eval/egress_corpus.py",
    "src/limes/eval/egress_harness.py",
    "src/limes/baselines/tessera_pii.py",
    "tests/unit/egress/",
    "tests/integration/egress/",
    # The rendered admission reports. They are *generated* from code that is
    # itself frozen (harness, corpus, detector, policy are all in CORE), so
    # freezing the rendering too would add no guarantee and would make `make eval`
    # break the ratchet by refreshing a date line.
    "eval/matrices/",
    "docs/decisions/0009-egress-corpus-synthetic-only.md",
    "docs/decisions/0010-vendor-key-vectors-are-stored-assembled.md",
    "docs/decisions/0012-the-egress-leg-scans-for-injection.md",
    "docs/decisions/0013-a-classifier-layer-enters-by-the-same-gate.md",
    "docs/design/detecteurs-egress-reels.md",
    "Makefile",
)

#: The two files an admission necessarily touches. They are not in CORE — a file
#: cannot be in both lists — and what replaces byte-identity for them is asserted
#: below, one test each. Weaker than "did not change"; stronger than nothing.
ADMISSION_SURFACE = (
    "src/limes/detectors/__init__.py",
    "tests/unit/test_admission_rule.py",
)

#: The load-bearing modules, named rather than merely implied. Whatever the
#: perimeters say, these are byte-identical to v0.1 — that is the ADR 0004 claim,
#: and it is what a reader of this file should be able to check without
#: reconstructing a set difference in their head.
CORE = (
    "src/limes/guard.py",
    "src/limes/verdict.py",
    "src/limes/spans.py",
    "src/limes/detector.py",
    "src/limes/record.py",
    "src/limes/policy.py",
    "src/limes/registry.py",
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
    "tests/unit/test_power.py",
    "tests/unit/test_corpus_provenance.py",
    "tests/unit/ratchets/test_allow_needs_evidence_mypy.py",
    "tests/unit/ratchets/test_exceptions_frozen_at_zero.py",
    "tests/unit/ratchets/test_guard_refuses_unknown.py",
    "tests/unit/ratchets/test_null_result_carries_power.py",
)

#: ADR 0011's single authorised amendment: the content digest became total
#: (`surrogatepass`), so `guard.py` left byte-identity to v0.1 and is pinned to
#: the sha256 of its post-ADR bytes instead. The ratchet's strength is intact —
#: any further drift of the file is red — what changed is the reference bytes,
#: once, with the authorisation written down. Every key here must be in CORE
#: and must actually differ from v0.1 (asserted below): an entry that covers a
#: non-core file would widen a perimeter by another name, and one that covers
#: an unchanged file would be a phantom nobody can audit (ADR 0026).
AMENDED = {
    "src/limes/guard.py": "5a0f155ab741a5f1de2c2b55e277099b793cbf22f09b1a75f6129b4d4d408d86",
}

#: Core modules whose *prose* had to be corrected as the transports grew (they
#: said "v0.1 ships no MCP proxy"). Their CODE must still be identical — asserted
#: below, not trusted.
DOCSTRING_ONLY = (
    "src/limes/__init__.py",
    "src/limes/transports/__init__.py",
)

CORE_PACKAGE = REPO / "src" / "limes"
TRANSPORTS = CORE_PACKAGE / "transports"
MCP_TRANSPORT = TRANSPORTS / "mcp"

#: The project scaffolding — files that existed at v0.1 and are frozen by the
#: complement below, but that carry no capability at all: how the project is
#: built, tested, published, and how a vulnerability reaches its maintainer.
#: Freezing them was a side effect of "everything outside the perimeters is
#: byte-identical", not a promise anybody made — and it had a cost: SECURITY.md
#: still described a v0.1 with one inbound detector and no proxy, which told a
#: security researcher that three transports and three detectors were out of
#: scope. A CI matrix, a publish workflow, a scanner allowlist or a security
#: policy cannot grow the core (ADR 0004), and widening here buys no silence:
#: CORE is named positively and `test_the_named_core_is_not_covered_by_any_perimeter`
#: still refuses any entry that reaches src/limes.
PROJECT_SCAFFOLDING = (
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".gitleaks.toml",
    "SECURITY.md",
)

PERIMETERS = ALLOWED + DETECTOR_PERIMETER + ADMISSION_SURFACE + PROJECT_SCAFFOLDING


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=REPO, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        pytest.skip(f"git could not answer `{' '.join(arguments)}`: {result.stderr.strip()}")
    return result.stdout


def _git_state() -> str:
    """Report what this checkout can actually show of its own history.

    Returns:
        ``"absent"`` when there is no repository at all, ``"shallow"`` when the
        history is truncated, ``"full"`` when v0.1's bytes are readable.
    """
    inside = subprocess.run(
        ["git", "rev-parse", "--git-dir"], cwd=REPO, capture_output=True, text=True, check=False
    )
    if inside.returncode != 0:
        return "absent"
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    return "shallow" if shallow.stdout.strip() == "true" else "full"


#: What this checkout can see of v0.1. Read once: the answer cannot change mid-run.
GIT_STATE = _git_state()


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
    # `_git` above already answers "I could not look" with a skip; this reader did
    # not, and the difference cost six weeks of red CI and 27 meaningless reds from
    # the sdist. A witness that cannot see reports a blind spot, never a verdict
    # (ADR 0026) — but only when it genuinely cannot see. With the history present,
    # a v0.1 object git refuses to produce stays RED: that would mean the pins name
    # a history this repository no longer has, which is the very thing to catch.
    if GIT_STATE != "full":
        detail = (
            "no git history at all (an sdist ships none)"
            if GIT_STATE == "absent"
            else "a shallow git history (`--depth`, or checkout's default fetch-depth: 1)"
        )
        pytest.skip(f"cannot read {path} at v0.1: this checkout has {detail}")
    result = subprocess.run(
        ["git", "show", f"{V0_1_COMMIT}:{path}"], cwd=REPO, capture_output=True, check=False
    )
    assert result.returncode == 0, f"could not read {path} at v0.1"
    return result.stdout


def _is_allowed(path: str) -> bool:
    return any(path == entry or path.startswith(entry) for entry in PERIMETERS)


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


def test_the_ratchet_can_actually_see_the_v0_1_bytes():
    # ADR 0026 turned on this file itself. Everything here is a comparison against
    # v0.1's bytes, so a checkout that cannot produce them makes every assertion
    # below unfalsifiable — and the skips that follow would read, to a CI summary,
    # as "nothing wrong". Twice this went the other way: `actions/checkout` fetches
    # depth 1 by default, so from v0.1 to v0.8 this ratchet never once ran on CI —
    # 16 red runs whose single cause was the checkout, and one green run, on the
    # v0.1 commit itself, where the comparison was trivially true.
    #
    # An sdist legitimately has no history and is allowed to declare itself blind.
    # A *truncated* one is a misconfiguration, and it gets a red that names the fix.
    assert GIT_STATE != "shallow", (
        "this checkout's git history is truncated, so the frontier ratchet cannot read "
        "v0.1's bytes and every assertion in this file would skip. Fetch the full "
        "history — on GitHub Actions: `actions/checkout` with `fetch-depth: 0`."
    )


def test_no_perimeter_entry_names_a_path_that_does_not_exist():
    # A perimeter that names a phantom is a perimeter nobody can audit: the entry
    # reads as "this is covered" and covers nothing, and the next reader cannot
    # tell a deliberate reservation from a typo (ADR 0026). Every entry is either
    # a v0.1 path or one that landed since.
    known = _v0_1_paths() | _working_paths()
    phantoms = sorted(
        entry
        for entry in PERIMETERS
        if entry not in known and not any(path.startswith(entry) for path in known)
    )
    assert phantoms == [], f"perimeter entries naming nothing on disk or at v0.1: {phantoms}"


def test_the_named_core_is_not_covered_by_any_perimeter():
    # This is the anti-widening check, and it now polices four lists rather than
    # one. Adding "src/limes/detectors/" to DETECTOR_PERIMETER to make a red go
    # away would leave this one red, naming injection.py and its policy.
    escaped = sorted(path for path in CORE if _is_allowed(path))
    assert escaped == [], (
        "these core paths were made writable by widening a perimeter; the perimeters are "
        f"for transports, detectors and the admission surface, and the core is none of "
        f"them: {escaped}"
    )


def test_the_admission_surface_is_not_also_claimed_as_core():
    # A file cannot be in both lists: CORE asserts byte-identity, ADMISSION_SURFACE
    # asserts something weaker. Claiming both would let the weaker one hide behind
    # the stronger one's name.
    overlap = sorted(set(ADMISSION_SURFACE) & set(CORE))
    assert overlap == [], f"claimed as both frozen and admission surface: {overlap}"


@pytest.mark.parametrize("path", CORE)
def test_the_named_core_is_byte_identical_to_its_pin(path):
    current = (REPO / path).read_bytes()
    if path in AMENDED:
        assert hashlib.sha256(current).hexdigest() == AMENDED[path], (
            f"{path} may differ from v0.1 exactly as ADR 0011 wrote it and no further: it is "
            "pinned to the digest recorded in AMENDED, and this drift is a new, unauthorised "
            "core edit."
        )
        return
    assert current == _v0_1_bytes(path), (
        f"{path} is the core, the pipeline, the injection detector or its measurement "
        "(ADR 0004). Neither a transport behaviour nor a new detector may change it — and "
        "the egress detectors did not need to: they are a plugin, a policy file and a corpus."
    )


def test_every_amended_entry_is_core_and_actually_moved():
    # AMENDED is not a fourth perimeter: it may only re-pin a file the ratchet
    # already names as core, and only one that genuinely differs from v0.1. An
    # entry violating either half would be a widening or a phantom.
    not_core = sorted(set(AMENDED) - set(CORE))
    assert not_core == [], f"AMENDED entries that are not core files: {not_core}"
    unmoved = sorted(path for path in AMENDED if (REPO / path).read_bytes() == _v0_1_bytes(path))
    assert unmoved == [], f"AMENDED entries whose file is still byte-identical to v0.1: {unmoved}"


# --- the admission surface --------------------------------------------------


def _admitted_names(source: bytes) -> list[str]:
    """The names in the ADMITTED tuple, read from the source rather than imported."""
    for node in ast.parse(source).body:
        target = getattr(node, "target", None)
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(target, ast.Name)
            and target.id == "ADMITTED"
            and isinstance(node.value, ast.Tuple)
        ):
            return [element.id for element in node.value.elts if isinstance(element, ast.Name)]
    raise AssertionError("no ADMITTED tuple found")


def test_the_registry_only_ever_gained_detectors():
    path = "src/limes/detectors/__init__.py"
    before = _admitted_names(_v0_1_bytes(path))
    after = _admitted_names((REPO / path).read_bytes())
    assert before, "v0.1 admitted nothing, which cannot be right"
    lost = sorted(set(before) - set(after))
    assert lost == [], f"the registry LOST detectors, which is not a growth: {lost}"


def test_the_registry_is_still_a_registry_and_not_a_program():
    # What replaces byte-identity: this file may gain an import and a tuple entry,
    # and nothing else. No branch, no call, no function, no try — a registry with
    # logic in it is a place a detector can be admitted conditionally, which is a
    # place ADR 0003's enforcer cannot see.
    tree = ast.parse((REPO / "src/limes/detectors/__init__.py").read_bytes())
    allowed_nodes = (ast.Expr, ast.ImportFrom, ast.Import, ast.AnnAssign, ast.Assign)
    offenders = [type(node).__name__ for node in tree.body if not isinstance(node, allowed_nodes)]
    assert offenders == [], f"the registry grew logic: {offenders}"
    assigned = [
        target.id
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        for target in [node.target]
    ] + [
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    ]
    assert sorted(assigned) == ["ADMITTED", "__all__"]


def test_the_admission_enforcer_still_measures_every_admitted_detector():
    # The enforcer's own contract, asked of the file: it parametrises over
    # ADMITTED rather than naming detectors one by one, so a detector added to the
    # tuple is measured without anybody remembering to add a test.
    source = (REPO / "tests/unit/test_admission_rule.py").read_text(encoding="utf-8")
    assert 'parametrize("detector_cls", ADMITTED' in source, (
        "the admission enforcer must iterate ADMITTED; a hand-written list of detectors "
        "is exactly the thing that goes stale the day one is added"
    )


# --- the complement ---------------------------------------------------------


def test_every_v0_1_file_outside_the_perimeters_is_byte_identical():
    changed = []
    for path in sorted(_v0_1_paths()):
        # AMENDED files are policed by their pinned digest above, not skipped.
        if _is_allowed(path) or path in DOCSTRING_ONLY or path in AMENDED:
            continue
        current = REPO / path
        assert current.exists(), f"v0.1 file {path} was deleted"
        if current.read_bytes() != _v0_1_bytes(path):
            changed.append(path)
    assert changed == [], (
        "a transport or a detector (ADR 0004) may not change the core, the injection "
        f"detector, or their tests. These moved: {changed}"
    )


def test_no_new_file_landed_outside_the_perimeters():
    added = sorted(path for path in _working_paths() - _v0_1_paths() if not _is_allowed(path))
    assert added == [], f"files landed outside every declared perimeter: {added}"


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
    assert scripts["limes"] == "limes.cli:main", (
        "`limes` dispatches from the core CLI, which must import without the mcp extra "
        "(`limes check` is core only); the proxy is reached lazily on the `proxy` path"
    )
    assert scripts["limes-proxy"].startswith("limes.transports.mcp.")


def test_the_detectors_add_no_dependency_at_all():
    # A detector is a plugin, and this one is rules plus arithmetic. If admitting
    # it had cost a dependency, `pip install limes` would have grown for everyone
    # — including the users who only ever run `limes check`.
    manifest = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    # The floor moved once, by measurement rather than by drift: PyYAML 6.0 ships
    # no wheel for any Python limes supports and its sdist fails to build under
    # Cython 3, so `pyyaml>=6.0` named a version nobody could install. The shape
    # this test defends is unchanged — exactly one runtime dependency, and it is
    # PyYAML — and it is still an exact string, so the next move is deliberate too.
    assert manifest["project"]["dependencies"] == ["pyyaml>=6.0.1"]


def test_every_admitted_entry_point_resolves_to_the_detector_perimeter_or_the_core():
    manifest = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    for name, target in manifest["project"]["entry-points"]["limes.detectors"].items():
        module = target.split(":")[0].replace(".", "/") + ".py"
        assert (REPO / "src" / module).exists(), f"entry point {name} names a missing module"


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


def test_the_detectors_do_not_import_a_transport():
    # The dependency runs one way: a transport consumes detectors, never the
    # reverse. A detector that imported `limes.transports` would make the egress
    # rules unusable from `limes check`, which has no transport at all.
    offenders = {}
    for module in sorted((CORE_PACKAGE / "detectors").rglob("*.py")):
        imported = _imported_roots(module.read_bytes())
        if "limes" in imported:
            source = module.read_text(encoding="utf-8")
            if "limes.transports" in source:
                offenders[str(module.relative_to(REPO))] = "imports limes.transports"
    assert offenders == {}, offenders


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
