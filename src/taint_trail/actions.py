"""Resolving ``uses:`` references and reading action manifests.

The resolver is a callable so the analyser never decides where files come
from. The default looks in a local directory laid out as
``owner/repo/ref/action.yml`` (``--actions-dir`` or ``TAINT_TRAIL_ACTIONS``)
and at ``./path`` inside the repository being scanned. Nothing here touches
the network; ``fetch.py`` is the explicit opt-in that populates the directory.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from .workflow import Step, parse_steps
from .yamlload import LineDict, LineStr, YamlError, as_dict, as_text, load_yaml_file

ActionKind = Literal["repo", "local", "docker", "invalid"]


@dataclass(frozen=True)
class ActionRef:
    kind: ActionKind
    raw: str
    owner: str = ""
    repo: str = ""
    path: str = ""
    ref: str = ""

    @property
    def slug(self) -> str:
        if self.kind == "repo":
            base = f"{self.owner}/{self.repo}"
            if self.path:
                base += f"/{self.path}"
            return f"{base}@{self.ref}"
        return self.raw

    @property
    def is_github_script(self) -> bool:
        return self.kind == "repo" and (self.owner, self.repo) == ("actions", "github-script")


_REPO_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.][A-Za-z0-9_.-]*)/(?P<repo>[A-Za-z0-9_.][A-Za-z0-9_.-]*)"
    r"(?P<path>(?:/[^@\s]+)?)@(?P<ref>[^@\s]+)$"
)
# Owner and repo never start with "-" (a git option). A ref may contain "/"
# (``releases/v1`` is a documented form) but never "..", a leading "-" or a
# leading "/" (an absolute path), and no backslash.
_REF_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*$")


def _safe_segments(path: str) -> bool:
    """Relative, no ``..``, no backslash, no empty or ``.`` segment."""
    if "\\" in path:
        return False
    return all(
        segment not in ("", ".", "..") and ".." not in segment for segment in path.split("/")
    )


def parse_uses(uses: str) -> ActionRef:
    """Split a ``uses:`` string. Anything that could name a file outside the
    actions directory or the repository is ``invalid`` and is never resolved."""
    text = uses.strip()
    if text.startswith("docker://"):
        return ActionRef("docker", text)
    if text.startswith("./"):
        path = text[2:].rstrip("/")
        if path and not _safe_segments(path):
            return ActionRef("invalid", text)
        return ActionRef("local", text, path=path)
    m = _REPO_RE.match(text)
    if m is None:
        return ActionRef("invalid", text)
    owner, repo, ref = m.group("owner"), m.group("repo"), m.group("ref")
    path = m.group("path").strip("/")
    if ".." in owner or ".." in repo:
        return ActionRef("invalid", text)
    if path and not _safe_segments(path):
        return ActionRef("invalid", text)
    if _REF_RE.match(ref) is None or ".." in ref or ref.endswith("/"):
        return ActionRef("invalid", text)
    return ActionRef("repo", text, owner=owner, repo=repo, path=path, ref=ref)


class Resolver(Protocol):
    """Where files come from. The analyser never decides this itself."""

    def action(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        """The directory holding the action's ``action.yml``, or None."""

    def workflow(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        """The reusable workflow file for ``ref``, or None."""


def _manifest_candidate(directory: Path) -> Path | None:
    """``action.yml`` or ``action.yaml`` present in ``directory``, wherever it resolves."""
    for name in ("action.yml", "action.yaml"):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def find_manifest(directory: Path) -> Path | None:
    """The manifest to read: present in ``directory`` and resolving inside it.

    A symlinked ``action.yml`` that points elsewhere is not returned."""
    candidate = _manifest_candidate(directory)
    if candidate is None:
        return None
    return inside(candidate, directory)


def inside(candidate: Path, root: Path) -> Path | None:
    """``candidate`` if it resolves (symlinks included) under ``root``, else None."""
    try:
        if candidate.resolve().is_relative_to(root.resolve()):
            return candidate
    except OSError:
        pass
    return None


class LocalDirResolver:
    """``owner/repo/ref/[path/]action.yml`` under ``actions_dir``; ``./x`` under the repo.

    Nothing outside those two roots is ever returned, even when a symlink
    inside them points elsewhere.
    """

    def __init__(self, actions_dir: Path | None) -> None:
        self.actions_dir = actions_dir

    def _base(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        if ref.kind == "local":
            return None if repo_root is None else inside(repo_root / ref.path, repo_root)
        if ref.kind == "repo" and self.actions_dir is not None:
            base = self.actions_dir / ref.owner / ref.repo / ref.ref
            return inside(base / ref.path if ref.path else base, self.actions_dir)
        return None

    def action(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        directory = self._base(ref, repo_root)
        if directory is None or _manifest_candidate(directory) is None:
            return None
        return directory

    def workflow(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        path = self._base(ref, repo_root)
        return path if path is not None and path.is_file() else None


class NoResolver:
    """Resolves nothing: every ``uses:`` becomes UNKNOWN."""

    def action(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        return None

    def workflow(self, ref: ActionRef, repo_root: Path | None) -> Path | None:
        return None


@dataclass
class ActionInput:
    name: str
    line: int
    default: LineStr | None


@dataclass
class ActionOutput:
    name: str
    line: int
    value: LineStr | None


@dataclass
class ActionManifest:
    path: Path
    directory: Path
    using: str
    inputs: dict[str, ActionInput]
    outputs: dict[str, ActionOutput]
    steps: list[Step]
    main: str | None
    raw: LineDict

    @property
    def kind(self) -> str:
        using = self.using.lower()
        if using == "composite":
            return "composite"
        if using.startswith("node"):
            return "node"
        if using == "docker":
            return "docker"
        return "unknown"


class ActionError(ValueError):
    pass


def load_action(directory: Path) -> ActionManifest:
    manifest = find_manifest(directory)
    if manifest is None:
        if _manifest_candidate(directory) is not None:
            raise ActionError(
                f"{directory}: action.yml resolves outside the action directory (symlink) and "
                "is not read"
            )
        raise ActionError(f"{directory}: no action.yml or action.yaml")
    try:
        raw = load_yaml_file(manifest)
    except YamlError as exc:
        raise ActionError(str(exc)) from exc
    data = as_dict(raw)
    runs = as_dict(data.get("runs"))
    using = as_text(runs.get("using"))
    inputs_raw = as_dict(data.get("inputs"))
    inputs = {
        str(name).lower(): ActionInput(
            str(name), inputs_raw.key_line(name), as_text(as_dict(spec).get("default"))
        )
        for name, spec in inputs_raw.items()
    }
    outputs_raw = as_dict(data.get("outputs"))
    outputs = {
        str(name): ActionOutput(
            str(name), outputs_raw.key_line(name), as_text(as_dict(spec).get("value"))
        )
        for name, spec in outputs_raw.items()
    }
    main = as_text(runs.get("main"))
    return ActionManifest(
        path=manifest,
        directory=directory,
        using=str(using) if using is not None else "",
        inputs=inputs,
        outputs=outputs,
        steps=parse_steps(runs.get("steps")),
        main=str(main) if main is not None else None,
        raw=data,
    )


# ---------------------------------------------------------------------------
# JavaScript heuristic
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JsVerdict:
    kind: Literal["SUSPECT", "DIES", "UNKNOWN"]
    reason: str
    line: int
    reference_line: int | None
    carrier: str


_SHELL_TRUE_RE = re.compile(r"\bshell\s*:\s*true\b")
_EXEC_SYNC_RE = re.compile(r"\bexecSync\s*\(")
_EXEC_RE = re.compile(r"(?<![\w.$])exec\s*\(")
_SPAWN_ARRAY_RE = re.compile(r"\b(?:spawn|execFile|execFileSync|spawnSync)\s*\(\s*[^,]+,\s*\[")
_TEMPLATE_RE = re.compile(r"`(?:[^`\\]|\\.)*?\$\{([^}]*)\}(?:[^`\\]|\\.)*`", re.DOTALL)
_BIND_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")
_ENV_ALIAS_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env\s*(?:;|$)", re.MULTILINE
)


def _env_aliases(text: str) -> list[str]:
    """Identifiers bound to ``process.env`` itself (``const env = process.env``)."""
    return sorted(set(_ENV_ALIAS_RE.findall(text)))


def _reference_patterns(
    input_names: Iterable[str], env_names: Iterable[str], aliases: Iterable[str] = ()
) -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for name in input_names:
        upper = re.escape(str(name).upper().replace("-", "_").replace(" ", "_"))
        escaped = re.escape(str(name))
        patterns.append(
            (
                f"getInput('{name}')",
                re.compile(
                    rf"getInput\s*\(\s*['\"]{escaped}['\"]|process\.env(?:\.INPUT_{upper}\b|"
                    rf"\[\s*['\"]INPUT_{upper}['\"]\s*\])",
                    re.IGNORECASE,
                ),
            )
        )
    holders = "|".join(["process\\.env", *(re.escape(alias) for alias in aliases)])
    for name in env_names:
        escaped = re.escape(str(name))
        patterns.append(
            (
                f"process.env.{name}",
                re.compile(
                    rf"\b(?:{holders})(?:\.{escaped}\b|\[\s*['\"]{escaped}['\"]\s*\])|"
                    rf"\{{[^}}]*\b{escaped}\b[^}}]*\}}\s*=\s*process\.env\b"
                ),
            )
        )
    return patterns


def js_references_env(text: str, name: str) -> int | None:
    """1-based line where a JS file reads ``process.env.<name>``, directly, through
    an alias of ``process.env`` or by destructuring; None when it never does."""
    for _label, pattern in _reference_patterns((), (name,), _env_aliases(text)):
        for number, source_line in enumerate(text.split("\n"), start=1):
            if pattern.search(source_line):
                return number
    return None


def js_heuristic(
    text: str,
    input_names: Iterable[str] = (),
    env_names: Iterable[str] = (),
    argv: bool = False,
    where: str = "",
) -> JsVerdict:
    """Decide what a JavaScript file does with the tainted inputs, by pattern.

    There is no dataflow analysis here. The verdict is a heuristic and is
    labelled as such by the caller; the reason always names the line matched
    (``where`` is the file label used in that reason).
    """
    lines = text.split("\n")
    bound: set[str] = set()
    reference_line: int | None = None
    carrier = ""
    aliases = _env_aliases(text)
    patterns = _reference_patterns(input_names, env_names, aliases)
    alias_re = (
        re.compile(r"\b(?:" + "|".join(re.escape(a) for a in aliases) + r")\b") if aliases else None
    )
    if argv:
        patterns.append(("process.argv", re.compile(r"process\.argv\b")))
    for number, source_line in enumerate(lines, start=1):
        for label, pattern in patterns:
            if pattern.search(source_line):
                if reference_line is None:
                    reference_line = number
                    carrier = label
                binding = _BIND_RE.search(source_line)
                if binding is not None:
                    bound.add(binding.group(1))
    tied_re = None
    if bound:
        tied_re = re.compile(r"\b(?:" + "|".join(re.escape(b) for b in sorted(bound)) + r")\b")

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    def at(number: int) -> str:
        return f"at {where}:{number}" if where else f"at line {number}"

    def verdict(kind: Literal["SUSPECT", "DIES", "UNKNOWN"], reason: str, line: int) -> JsVerdict:
        return JsVerdict(kind, reason, line, reference_line, carrier)

    m = _SHELL_TRUE_RE.search(text)
    if m is not None:
        line = line_of(m.start())
        return verdict("SUSPECT", f"shell: true {at(line)}", line)
    m = _EXEC_SYNC_RE.search(text)
    if m is not None:
        line = line_of(m.start())
        return verdict("SUSPECT", f"execSync( {at(line)} builds a command string", line)
    exec_match = _EXEC_RE.search(text)
    if exec_match is not None:
        line = line_of(exec_match.start())
        window = text[exec_match.end() : exec_match.end() + 600]
        for template in _TEMPLATE_RE.finditer(window):
            interpolated = re.findall(r"\$\{([^}]*)\}", template.group(0))
            tied = any(
                (tied_re is not None and tied_re.search(expr))
                or "process.env" in expr
                or (alias_re is not None and alias_re.search(expr))
                or "getInput" in expr
                for expr in interpolated
            )
            if tied:
                return verdict(
                    "SUSPECT",
                    f"exec( {at(line)} with a template literal interpolating the input",
                    line,
                )
        return verdict(
            "UNKNOWN", f"exec( {at(line)} could not be tied to the input by pattern", line
        )
    m = _SPAWN_ARRAY_RE.search(text)
    if m is not None:
        line = line_of(m.start())
        callee = m.group(0).split("(")[0].strip()
        return verdict(
            "DIES",
            f"argv array via {callee}( {at(line)}; no shell: true, no exec(, no execSync(",
            line,
        )
    return verdict("UNKNOWN", "JavaScript action, no shell pattern matched", reference_line or 1)
