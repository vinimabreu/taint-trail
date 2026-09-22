"""The analyser: follows an untrusted value through a workflow and into actions.

Everything here is deterministic. Each hop appends a file:line and a carrier
to the taint in flight; each sink turns the taint into a chain with a verdict.
When the analyser cannot follow (no local copy of the action, a docker action,
a script it cannot locate, the depth limit, a cycle) it emits UNKNOWN with the
reason, and never a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .actions import (
    ActionError,
    ActionManifest,
    ActionRef,
    JsVerdict,
    NoResolver,
    Resolver,
    inside,
    js_heuristic,
    js_references_env,
    load_action,
    parse_uses,
)
from .model import Chain, Hop, Source, Taint, Trust, Verdict, VerdictKind
from .sinks import HitKind, ShellHit, ShellScan, scan_shell
from .sources import classify, find_expressions, references
from .workflow import UNDETERMINED_SHELL, Job, Step, Workflow, WorkflowError, load_workflow
from .yamlload import LineDict, LineList, LineStr, YamlError, as_dict, as_text

TaintMap = dict[str, list[Taint]]

SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})
MAX_SCRIPT_BYTES = 2_000_000
_ACTION_PATH_RE = re.compile(r"\$\{\{\s*github\.action_path\s*\}\}")
_WORKSPACE_RE = re.compile(r"\$\{\{\s*github\.workspace\s*\}\}")
_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_POSITIONAL = frozenset({"@", "*"})
_WRITES_RUNNER_FILE_RE = re.compile(r"GITHUB_OUTPUT|GITHUB_ENV|::set-output")
_JS_WRITES_RE = re.compile(r"GITHUB_OUTPUT|GITHUB_ENV|\bsetOutput\s*\(|\bexportVariable\s*\(")
OUTPUTS_OVER_APPROXIMATION = (
    "run writes $GITHUB_OUTPUT or $GITHUB_ENV while a tainted variable is in env; "
    "every output of the step is treated as tainted (over-approximation)"
)


def _scalars(value: object) -> list[LineStr]:
    """Every string leaf under a YAML value, in document order."""
    text = as_text(value)
    if text is not None:
        return [text]
    if isinstance(value, LineDict):
        return [leaf for item in value.values() for leaf in _scalars(item)]
    if isinstance(value, LineList):
        return [leaf for item in value for leaf in _scalars(item)]
    return []


@dataclass
class Scope:
    """What is visible from one place: a job, a composite action, a script."""

    file: Path
    job: str
    workflow: str
    env: TaintMap = field(default_factory=dict)
    inputs: TaintMap = field(default_factory=dict)
    steps: dict[str, TaintMap] = field(default_factory=dict)
    needs: dict[str, TaintMap] = field(default_factory=dict)
    matrix: list[Taint] = field(default_factory=list)
    top_level: bool = True
    repo_root: Path | None = None
    action_dir: Path | None = None
    depth: int = 0
    stack: tuple[str, ...] = ()

    def tainted_env(self) -> TaintMap:
        """Real environment variables (not positional parameters) that carry taint."""
        return {
            name: taints
            for name, taints in self.env.items()
            if taints and name not in _POSITIONAL and not name.isdigit()
        }

    def child(self, file: Path, **changes: object) -> Scope:
        data = {
            "file": file,
            "job": self.job,
            "workflow": self.workflow,
            "env": {},
            "inputs": {},
            "steps": {},
            "needs": {},
            "matrix": [],
            "top_level": False,
            "repo_root": self.repo_root,
            "action_dir": self.action_dir,
            "depth": self.depth,
            "stack": self.stack,
        }
        data.update(changes)
        return Scope(**data)  # type: ignore[arg-type]


class Analyzer:
    def __init__(
        self,
        resolver: Resolver | None = None,
        max_depth: int = 5,
        cwd: Path | None = None,
    ) -> None:
        self.resolver: Resolver = resolver if resolver is not None else NoResolver()
        self.max_depth = max_depth
        self.cwd = (cwd or Path.cwd()).resolve()
        self._chains: list[Chain] = []
        self._definitions: dict[int, tuple[Taint, Scope]] = {}
        self._emitted: set[int] = set()
        self._opaque: dict[int, list[str]] = {}
        self._occurrence = 0

    # -- public ------------------------------------------------------------

    def analyse_file(self, path: Path) -> list[Chain]:
        return self.analyse_workflow(load_workflow(path))

    def analyse_workflow(self, workflow: Workflow) -> list[Chain]:
        self._chains = []
        self._definitions = {}
        self._emitted = set()
        self._opaque = {}
        self._occurrence = 0
        self._workflow(workflow, initial_inputs=None, level=0)
        self._never_read()
        return list(self._chains)

    # -- bookkeeping -------------------------------------------------------

    def display(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.cwd))
        except ValueError:
            return str(path)

    def _new_taint(self, source: Source) -> Taint:
        self._occurrence += 1
        return Taint(source, self._occurrence)

    def _carry(self, taints: list[Taint], hop: Hop, scope: Scope) -> list[Taint]:
        carried = [taint.extend(hop) for taint in taints]
        for taint in carried:
            known = self._definitions.get(taint.occurrence)
            if known is None or len(known[0].hops) < len(taint.hops):
                self._definitions[taint.occurrence] = (taint, scope)
        return carried

    def _mark_opaque(self, scope: Scope, slug: str) -> None:
        """Record that ``slug`` runs with every tainted env var of ``scope`` in its process."""
        for taints in scope.tainted_env().values():
            for taint in taints:
                self._opaque.setdefault(taint.occurrence, []).append(slug)

    def _emit(self, taint: Taint, hops: list[Hop], verdict: Verdict, scope: Scope) -> None:
        self._emitted.add(taint.occurrence)
        self._chains.append(
            Chain(
                source=taint.source,
                hops=[*taint.hops, *hops],
                verdict=verdict,
                workflow=scope.workflow,
                job=scope.job,
                occurrence=taint.occurrence,
            )
        )

    def _emit_all(
        self, taints: list[Taint], hops: list[Hop], verdict: Verdict, scope: Scope
    ) -> None:
        for taint in taints:
            self._emit(taint, hops, verdict, scope)

    # -- expressions -------------------------------------------------------

    def _taints_of(self, text: str, scope: Scope) -> list[tuple[Taint, str]]:
        """Taints carried by every ``${{ }}`` in ``text``, with the reference that carried each."""
        found: list[tuple[Taint, str]] = []
        seen: set[int] = set()
        for expression in find_expressions(text):
            for taint, ref in self._taints_of_expression(expression.body, scope):
                if taint.occurrence not in seen:
                    seen.add(taint.occurrence)
                    found.append((taint, ref))
        return found

    def _taints_of_expression(self, body: str, scope: Scope) -> list[tuple[Taint, str]]:
        found: list[tuple[Taint, str]] = []
        for ref in references(body):
            parts = ref.split(".")
            head = parts[0].lower()
            if head == "env" and len(parts) >= 2:
                found.extend((t, ref) for t in scope.env.get(parts[1], []))
            elif head == "inputs" and len(parts) >= 2:
                key = parts[1].lower()
                if key in scope.inputs:
                    found.extend((t, ref) for t in scope.inputs[key])
                elif scope.top_level:
                    source = classify(ref)
                    if source is not None:
                        found.append((self._new_taint(source), ref))
            elif head == "steps" and len(parts) >= 4 and parts[2].lower() == "outputs":
                found.extend(self._output_taints(scope.steps.get(parts[1], {}), parts[3], ref))
            elif head == "needs" and len(parts) >= 4 and parts[2].lower() == "outputs":
                found.extend(self._output_taints(scope.needs.get(parts[1], {}), parts[3], ref))
            elif head == "matrix":
                found.extend((t, ref) for t in scope.matrix)
            elif head == "github":
                source = classify(ref)
                if source is not None:
                    found.append((self._new_taint(source), ref))
        return found

    @staticmethod
    def _output_taints(outputs: TaintMap, name: str, ref: str) -> list[tuple[Taint, str]]:
        """The taints behind ``outputs.<name>``: the named output first, then ``*``
        (every name) for occurrences the named output did not already carry."""
        named = outputs.get(name, [])
        carried = {taint.occurrence for taint in named}
        star = [taint for taint in outputs.get("*", []) if taint.occurrence not in carried]
        return [(taint, ref) for taint in [*named, *star]]

    @staticmethod
    def _detail(ref: str, taint: Taint) -> str:
        return "" if ref == taint.source.path else ref

    def _env_taints(self, env: LineDict, scope: Scope, file: Path) -> TaintMap:
        result: TaintMap = {}
        for key, value in env.items():
            text = as_text(value)
            if text is None:
                continue
            result[str(key)] = []
            for taint, ref in self._taints_of(text, scope):
                hop = Hop(
                    self.display(file), env.key_line(key), f"env {key}", self._detail(ref, taint)
                )
                result.setdefault(str(key), []).extend(self._carry([taint], hop, scope))
        return result

    # -- workflow ----------------------------------------------------------

    def _workflow(
        self, workflow: Workflow, initial_inputs: TaintMap | None, level: int
    ) -> dict[str, TaintMap]:
        file = workflow.path
        shown = self.display(file)
        base = Scope(
            file=file,
            job="",
            workflow=shown,
            inputs=initial_inputs or {},
            top_level=initial_inputs is None,
            repo_root=workflow.repo_root,
        )
        workflow_env = self._env_taints(workflow.env, base, file)
        job_outputs: dict[str, TaintMap] = {}
        for job in self._ordered(workflow.jobs):
            scope = Scope(
                file=file,
                job=job.id,
                workflow=shown,
                env=dict(workflow_env),
                inputs=initial_inputs or {},
                needs={dep: job_outputs.get(dep, {}) for dep in job.needs},
                top_level=initial_inputs is None,
                repo_root=workflow.repo_root,
            )
            scope.env.update(self._env_taints(job.env, scope, file))
            for matrix in _scalars(job.matrix):
                for taint, ref in self._taints_of(matrix, scope):
                    hop = Hop(shown, matrix.line, "strategy.matrix", self._detail(ref, taint))
                    scope.matrix.extend(self._carry([taint], hop, scope))
            if job.uses is not None:
                called = self._reusable(job, scope, level)
                job_outputs[job.id] = called
                continue
            self._steps(job.steps, scope)
            outputs: TaintMap = {}
            for name, value in job.outputs.items():
                text = as_text(value)
                if text is None:
                    continue
                for taint, ref in self._taints_of(text, scope):
                    hop = Hop(
                        shown,
                        job.outputs.key_line(name),
                        f"jobs.{job.id}.outputs.{name}",
                        self._detail(ref, taint),
                    )
                    outputs.setdefault(str(name), []).extend(self._carry([taint], hop, scope))
            job_outputs[job.id] = outputs
        return job_outputs

    @staticmethod
    def _ordered(jobs: list[Job]) -> list[Job]:
        """Jobs in an order where dependencies come first (file order otherwise)."""
        remaining = list(jobs)
        done: set[str] = set()
        ordered: list[Job] = []
        while remaining:
            progress = [job for job in remaining if all(dep in done for dep in job.needs)]
            if not progress:
                progress = [remaining[0]]
            for job in progress:
                ordered.append(job)
                done.add(job.id)
                remaining.remove(job)
        return ordered

    # -- steps -------------------------------------------------------------

    def _steps(self, steps: list[Step], scope: Scope) -> None:
        for step in steps:
            step_env = dict(scope.env)
            step_env.update(self._env_taints(step.env, scope, scope.file))
            step_scope = scope.child(
                scope.file,
                env=step_env,
                inputs=scope.inputs,
                steps=scope.steps,
                needs=scope.needs,
                matrix=scope.matrix,
                top_level=scope.top_level,
            )
            if step.run is not None:
                self._run_step(step, step_scope)
            elif step.uses is not None:
                self._uses_step(step, step_scope)

    @staticmethod
    def _neutralise(script: str) -> str:
        """Turn ``${{ }}`` into shell-visible tokens so the scanner can read paths."""
        text = _ACTION_PATH_RE.sub("$GITHUB_ACTION_PATH", script)
        text = _WORKSPACE_RE.sub("$GITHUB_WORKSPACE", text)
        return _EXPR_RE.sub(lambda m: "__EXPR__" + "\n" * m.group(0).count("\n"), text)

    def _run_step(self, step: Step, scope: Scope) -> None:
        run = step.run
        assert run is not None
        shown = self.display(scope.file)
        interpolated: list[Taint] = []
        for expression in find_expressions(run):
            line = run.body_line + run[: expression.start].count("\n")
            for taint, _ref in self._taints_of_expression(expression.body, scope):
                hop = Hop(shown, line, "run", f"{expression.text} interpolated into the script")
                self._emit(
                    taint,
                    [hop],
                    Verdict(
                        VerdictKind.SHELL,
                        "expression expanded into the shell script before it runs "
                        "(the classic injection)",
                    ),
                    scope,
                )
                interpolated.append(taint.extend(hop))
        if interpolated and step.id and _WRITES_RUNNER_FILE_RE.search(run) is not None:
            self._taint_step_outputs(
                step,
                scope,
                interpolated,
                "an expression is expanded into a script that writes $GITHUB_OUTPUT or "
                "$GITHUB_ENV; every output of the step is treated as tainted (over-approximation)",
            )
        tainted = scope.tainted_env()
        if not tainted:
            return
        shell = Path((step.shell or "bash").split()[0]).name.lower()
        text = self._neutralise(run)
        if shell not in SHELLS:
            reason = (
                "the runner does not fix the default shell (a runs-on expression that may "
                "select Windows, or a self-hosted runner with no OS label); the step is not "
                "analysed"
                if shell == UNDETERMINED_SHELL
                else f"shell: {shell} steps are not analysed"
            )
            for name, taints in tainted.items():
                if name in text:
                    hop = Hop(shown, run.line, "run", f"shell: {shell}")
                    self._emit_all(taints, [hop], Verdict(VerdictKind.UNKNOWN, reason), scope)
            if step.id and _WRITES_RUNNER_FILE_RE.search(run) is not None:
                flat = [taint for taints in tainted.values() for taint in taints]
                self._taint_step_outputs(
                    step,
                    scope,
                    flat,
                    f"shell: {shell} step writes $GITHUB_OUTPUT or $GITHUB_ENV while a tainted "
                    "variable is in env; every output of the step is treated as tainted "
                    "(over-approximation)",
                )
            return
        scan = scan_shell(text, tainted.keys())
        writes = self._apply_scan(scan, scope, scope.file, run.body_line, None, "run", step)
        if writes and step.id:
            flat = [taint for taints in tainted.values() for taint in taints]
            self._taint_step_outputs(step, scope, flat, OUTPUTS_OVER_APPROXIMATION)

    def _taint_step_outputs(
        self, step: Step, scope: Scope, taints: list[Taint], detail: str
    ) -> None:
        """Every output of ``step`` (``steps.<id>.outputs.*``) now carries ``taints``."""
        assert step.id
        hop = Hop(self.display(scope.file), step.line, f"steps.{step.id}.outputs.*", detail)
        scope.steps.setdefault(step.id, {}).setdefault("*", []).extend(
            self._carry(taints, hop, scope)
        )

    def _taint_action_outputs(
        self, step: Step, scope: Scope, manifest: ActionManifest, taints: list[Taint], what: str
    ) -> None:
        """A JavaScript action that received the value: its declared outputs carry the
        taint, and so does every other name (``*``), because ``core.setOutput`` can
        set an output the manifest never declares. Nothing in the JavaScript is followed."""
        assert step.id
        shown = self.display(manifest.path)
        outputs = scope.steps.setdefault(step.id, {})
        detail = (
            f"{what} received the value; every declared output is treated as tainted "
            "(over-approximation)"
        )
        for name, out in manifest.outputs.items():
            hop = Hop(shown, out.line, f"outputs.{name}", detail)
            outputs.setdefault(name, []).extend(self._carry(taints, hop, scope))
        detail = (
            f"{what} received the value; any output it sets without declaring it is treated "
            "as tainted too (over-approximation)"
            if manifest.outputs
            else f"{what} received the value and declares no outputs; every output name is "
            "treated as tainted (over-approximation)"
        )
        hop = Hop(shown, manifest.raw.line, "outputs.*", detail)
        outputs.setdefault("*", []).extend(self._carry(taints, hop, scope))

    def _apply_scan(
        self,
        scan: ShellScan,
        scope: Scope,
        file: Path,
        base_line: int,
        script_dir: Path | None,
        carrier: str,
        step: Step | None,
    ) -> bool:
        """Turn scanner hits into chains. Returns whether $GITHUB_OUTPUT/ENV is written."""
        shown = self.display(file)
        findings: set[str] = set()
        value_hits: dict[str, tuple[Hop, ShellHit]] = {}
        writes = scan.writes_output
        for hit in scan.hits:
            line = base_line + hit.line
            if hit.kind is HitKind.INVOKE:
                writes = (
                    self._follow(hit, scope, file, line, scan, script_dir, carrier, step) or writes
                )
                continue
            assert hit.var is not None
            hop = Hop(shown, line, carrier, hit.text)
            for origin in sorted(scan.origins(hit.var)):
                taints = scope.env.get(origin, [])
                if not taints:
                    continue
                if hit.kind is HitKind.VALUE:
                    value_hits.setdefault(origin, (hop, hit))
                    continue
                findings.add(origin)
                kind = {
                    HitKind.SHELL: VerdictKind.SHELL,
                    HitKind.SPOOF: VerdictKind.SPOOF,
                    HitKind.UNKNOWN: VerdictKind.UNKNOWN,
                }[hit.kind]
                self._emit_all(taints, [hop], Verdict(kind, hit.reason), scope)
        for origin, (hop, hit) in value_hits.items():
            if origin in findings:
                continue
            self._emit_all(
                scope.env.get(origin, []), [hop], Verdict(VerdictKind.DIES, hit.reason), scope
            )
        return writes

    # -- following scripts -------------------------------------------------

    def _resolve_script(
        self, target: str, scope: Scope, scan: ShellScan, script_dir: Path | None, step: Step | None
    ) -> tuple[Path | None, str]:
        """Locate a script the shell invokes. Returns the file, or None and the reason.

        Every candidate is checked against the scanned roots (the workspace, the
        invoking script's directory, the action directory) after resolving
        symlinks; a literal absolute path is never followed; a
        ``working-directory`` that resolves outside the workspace is never entered."""
        not_found = (
            f"script {target} could not be located (tried the workspace, the invoking "
            "script's directory and the action directory)"
        )
        token = target.strip("\"'")
        replacements: dict[str, Path | None] = {
            "GITHUB_ACTION_PATH": scope.action_dir,
            "GITHUB_WORKSPACE": scope.repo_root,
        }
        for name in scan.self_dir_vars:
            replacements[name] = script_dir
        substituted = False
        for name, base in replacements.items():
            for form in (f"${{{name}}}", f"${name}"):
                if form in token:
                    if base is None:
                        return None, not_found
                    token = token.replace(form, str(base.resolve()))
                    substituted = True
        if "$" in token or "__EXPR__" in token:
            return None, not_found
        path = Path(token)
        roots = [
            base.resolve()
            for base in (scope.repo_root, script_dir, scope.action_dir)
            if base is not None
        ]
        candidates: list[Path] = []
        if path.is_absolute():
            if not substituted:
                return None, (
                    f"script {target} is an absolute path; only paths under the workspace, "
                    "the invoking script's directory and the action directory are followed"
                )
            candidates.append(path)
        else:
            if step is not None and step.working_directory is not None:
                wd_token = self._neutralise(str(step.working_directory))
                for name, base in replacements.items():
                    for form in (f"${{{name}}}", f"${name}"):
                        if form in wd_token and base is not None:
                            wd_token = wd_token.replace(form, str(base.resolve()))
                if "$" not in wd_token and "__EXPR__" not in wd_token:
                    root = scope.repo_root or Path(".")
                    directory = root / wd_token
                    if inside(directory, root) is None:
                        return None, (
                            f"working-directory {step.working_directory} resolves outside the "
                            "repository; the script is not opened"
                        )
                    candidates.append(directory / path)
            for base in (scope.repo_root, script_dir, scope.action_dir):
                if base is not None:
                    candidates.append(base / path)
        outside = False
        for candidate in candidates:
            resolved = candidate.resolve()
            if not resolved.is_file():
                continue
            if any(resolved.is_relative_to(root) for root in roots):
                return resolved, ""
            outside = True
        if outside:
            return None, (
                f"script {target} resolves outside the scanned roots (the workspace, the "
                "invoking script's directory and the action directory); not read"
            )
        return None, not_found

    def _follow(
        self,
        hit: ShellHit,
        scope: Scope,
        file: Path,
        line: int,
        scan: ShellScan,
        script_dir: Path | None,
        carrier: str,
        step: Step | None,
    ) -> bool:
        invocation = hit.invocation
        assert invocation is not None
        env_taints = scope.tainted_env()
        arg_taints: TaintMap = {}
        for position, names in invocation.tainted_args:
            for name in names:
                for origin in scan.origins(name):
                    arg_taints.setdefault(position, []).extend(scope.env.get(origin, []))
        if not env_taints and not arg_taints:
            return False
        seen: dict[int, Taint] = {}
        for taints in [*env_taints.values(), *arg_taints.values()]:
            for taint in taints:
                seen.setdefault(taint.occurrence, taint)
        involved = list(seen.values())
        hop = Hop(self.display(file), line, carrier, hit.text)
        resolved, why = self._resolve_script(invocation.target, scope, scan, script_dir, step)
        if resolved is None:
            self._emit_all(involved, [hop], Verdict(VerdictKind.UNKNOWN, why), scope)
            return False
        if scope.depth + 1 > self.max_depth:
            self._emit_all(
                involved,
                [hop],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"depth limit {self.max_depth} reached at {self.display(resolved)}",
                ),
                scope,
            )
            return False
        key = str(resolved)
        if key in scope.stack:
            trail = " -> ".join([*scope.stack, key])
            self._emit_all(involved, [hop], Verdict(VerdictKind.UNKNOWN, f"cycle: {trail}"), scope)
            return False
        try:
            if resolved.stat().st_size > MAX_SCRIPT_BYTES:
                raise OSError("file too large")
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._emit_all(
                involved,
                [hop],
                Verdict(VerdictKind.UNKNOWN, f"script {self.display(resolved)} unreadable: {exc}"),
                scope,
            )
            return False
        kind = self._script_kind(resolved, invocation.interpreter, text)
        child_env: TaintMap = {
            name: self._carry(taints, hop, scope) for name, taints in env_taints.items()
        }
        for position, taints in arg_taints.items():
            child_env[position] = self._carry(taints, hop, scope)
        child = scope.child(
            resolved, env=child_env, depth=scope.depth + 1, stack=(*scope.stack, key)
        )
        if kind == "shell":
            sub = scan_shell(text, child_env.keys())
            return self._apply_scan(
                sub, child, resolved, 1, resolved.parent, f"script {resolved.name}", None
            )
        if kind == "js":
            verdict = js_heuristic(
                text,
                env_names=env_taints.keys(),
                argv=bool(arg_taints),
                where=self.display(resolved),
            )
            targets: list[Taint] = [t for ts in arg_taints.values() for t in ts]
            for name, taints in env_taints.items():
                if js_references_env(text, name) is not None:
                    targets.extend(taints)
            unique = {t.occurrence: t for t in targets}
            self._emit_js(list(unique.values()), [hop], resolved, verdict, child)
            return _JS_WRITES_RE.search(text) is not None
        self._emit_all(
            involved,
            [hop],
            Verdict(
                VerdictKind.UNKNOWN,
                f"{self.display(resolved)} is not a shell or JavaScript file; not followed",
            ),
            scope,
        )
        return False

    @staticmethod
    def _script_kind(path: Path, interpreter: str | None, text: str) -> str:
        suffix = path.suffix.lower()
        if interpreter in ("node",) or suffix in (".js", ".mjs", ".cjs"):
            return "js"
        if interpreter in ("python", "python3") or suffix == ".py":
            return "other"
        if interpreter in ("bash", "sh", "zsh", "dash", "ksh", "source", ".") or suffix in (
            ".sh",
            ".bash",
        ):
            return "shell"
        first = text.split("\n", 1)[0]
        if first.startswith("#!") and ("sh" in first):
            return "shell"
        if first.startswith("#!") and "node" in first:
            return "js"
        return "other"

    def _emit_js(
        self, taints: list[Taint], hops: list[Hop], path: Path, verdict: JsVerdict, scope: Scope
    ) -> None:
        if not taints:
            return
        carrier = verdict.carrier or "javascript"
        js_hop = Hop(self.display(path), verdict.reference_line or verdict.line, carrier)
        kind = {
            "SUSPECT": VerdictKind.SUSPECT,
            "DIES": VerdictKind.DIES,
            "UNKNOWN": VerdictKind.UNKNOWN,
        }[verdict.kind]
        heuristic = verdict.kind != "UNKNOWN"
        self._emit_all(taints, [*hops, js_hop], Verdict(kind, verdict.reason, heuristic), scope)

    # -- uses: -------------------------------------------------------------

    def _with_taints(
        self, with_: LineDict, scope: Scope, file: Path, slug: str
    ) -> dict[str, list[Taint]]:
        result: dict[str, list[Taint]] = {}
        for key, value in with_.items():
            text = as_text(value)
            if text is None:
                continue
            for taint, ref in self._taints_of(text, scope):
                detail = self._detail(ref, taint)
                detail = f"{detail} -> {slug}" if detail else f"-> {slug}"
                hop = Hop(self.display(file), with_.key_line(key), f"with {key}", detail)
                result.setdefault(str(key).lower(), []).extend(self._carry([taint], hop, scope))
        return result

    def _uses_step(self, step: Step, scope: Scope) -> None:
        assert step.uses is not None
        ref = parse_uses(str(step.uses))
        file = scope.file
        if ref.is_github_script:
            self._github_script(step, scope)
            return
        with_taints = self._with_taints(step.with_, scope, file, ref.slug)
        env_taints = scope.tainted_env()
        flat = [t for ts in with_taints.values() for t in ts]
        if ref.kind == "docker":
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(VerdictKind.UNKNOWN, "docker action, args reach entrypoint"),
                scope,
            )
            return
        if ref.kind == "invalid":
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(VerdictKind.UNKNOWN, f"uses reference {ref.raw!r} could not be parsed"),
                scope,
            )
            return
        directory = self.resolver.action(ref, scope.repo_root)
        if directory is None:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"action {ref.slug} not available locally (vendor it under --actions-dir as "
                    "owner/repo/ref/action.yml, or run with --fetch)",
                ),
                scope,
            )
            return
        try:
            manifest = load_action(directory)
        except ActionError as exc:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(flat, [], Verdict(VerdictKind.UNKNOWN, str(exc)), scope)
            return
        if manifest.kind == "docker":
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(VerdictKind.UNKNOWN, "docker action, args reach entrypoint"),
                scope,
            )
            return
        if manifest.kind == "composite":
            self._composite(step, scope, ref, manifest, with_taints)
            return
        if manifest.kind == "node":
            self._node(step, scope, ref, manifest, with_taints, env_taints)
            return
        self._mark_opaque(scope, ref.slug)
        self._emit_all(
            flat,
            [],
            Verdict(VerdictKind.UNKNOWN, f"runs.using {manifest.using!r} is not supported"),
            scope,
        )

    def _composite(
        self,
        step: Step,
        scope: Scope,
        ref: ActionRef,
        manifest: ActionManifest,
        with_taints: dict[str, list[Taint]],
    ) -> None:
        flat = [t for ts in with_taints.values() for t in ts]
        depth = scope.depth + 1
        if depth > self.max_depth:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(VerdictKind.UNKNOWN, f"depth limit {self.max_depth} reached at {ref.slug}"),
                scope,
            )
            return
        if ref.slug in scope.stack:
            self._mark_opaque(scope, ref.slug)
            trail = " -> ".join([*scope.stack, ref.slug])
            self._emit_all(flat, [], Verdict(VerdictKind.UNKNOWN, f"cycle: {trail}"), scope)
            return
        shown = self.display(manifest.path)
        inputs: TaintMap = {}
        for key, spec in manifest.inputs.items():
            hop = Hop(shown, spec.line, f"inputs.{spec.name}")
            if key in with_taints:
                inputs[key] = self._carry(with_taints[key], hop, scope)
            elif spec.default is not None:
                defaults = [t for t, _ in self._taints_of(spec.default, scope)]
                if defaults:
                    inputs[key] = self._carry(
                        defaults, Hop(shown, spec.line, f"inputs.{spec.name}", "default"), scope
                    )
        for key, taints in with_taints.items():
            if key not in manifest.inputs:
                inputs[key] = self._carry(
                    taints,
                    Hop(shown, manifest.raw.line, f"inputs.{key}", "undeclared input"),
                    scope,
                )
        inner = scope.child(
            manifest.path,
            env=dict(scope.tainted_env()),
            inputs=inputs,
            action_dir=manifest.directory,
            depth=depth,
            stack=(*scope.stack, ref.slug),
        )
        self._steps(manifest.steps, inner)
        outputs: TaintMap = {}
        for name, out in manifest.outputs.items():
            if out.value is None:
                continue
            for taint, out_ref in self._taints_of(out.value, inner):
                hop = Hop(shown, out.line, f"outputs.{name}", self._detail(out_ref, taint))
                outputs.setdefault(name, []).extend(self._carry([taint], hop, inner))
        if step.id and outputs:
            scope.steps.setdefault(step.id, {}).update(outputs)

    def _node(
        self,
        step: Step,
        scope: Scope,
        ref: ActionRef,
        manifest: ActionManifest,
        with_taints: dict[str, list[Taint]],
        env_taints: TaintMap,
    ) -> None:
        flat = [t for ts in with_taints.values() for t in ts]
        shown = self.display(manifest.path)
        if manifest.main is None:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(VerdictKind.UNKNOWN, f"{ref.slug}: node action without runs.main"),
                scope,
            )
            return
        main = manifest.directory / manifest.main
        if inside(main, manifest.directory) is None:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"{ref.slug}: main file {manifest.main} resolves outside the action "
                    "directory; not read",
                ),
                scope,
            )
            return
        if not main.is_file():
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"{ref.slug}: main file {manifest.main} not found in the vendored action",
                ),
                scope,
            )
            return
        text = main.read_text(encoding="utf-8", errors="replace")
        input_names = [manifest.inputs[k].name if k in manifest.inputs else k for k in with_taints]
        verdict = js_heuristic(
            text, input_names=input_names, env_names=env_taints.keys(), where=self.display(main)
        )
        inner = scope.child(manifest.path, action_dir=manifest.directory, depth=scope.depth + 1)
        received: list[Taint] = []
        for key, taints in with_taints.items():
            spec = manifest.inputs.get(key)
            line = spec.line if spec is not None else manifest.raw.line
            name = spec.name if spec is not None else key
            carried = self._carry(taints, Hop(shown, line, f"inputs.{name}"), scope)
            self._emit_js(carried, [], main, verdict, inner)
            received.extend(carried)
        for name, taints in env_taints.items():
            at = js_references_env(text, name)
            if at is None:
                continue
            self._emit_js(taints, [], main, verdict, inner)
            received.extend(
                self._carry(taints, Hop(self.display(main), at, f"process.env.{name}"), scope)
            )
        if step.id and received:
            self._taint_action_outputs(step, scope, manifest, received, "JavaScript action")

    def _github_script(self, step: Step, scope: Scope) -> None:
        script = as_text(step.with_.get("script"))
        if script is None:
            return
        shown = self.display(scope.file)
        received: list[Taint] = []
        for expression in find_expressions(script):
            line = script.body_line + script[: expression.start].count("\n")
            for taint, _ref in self._taints_of_expression(expression.body, scope):
                hop = Hop(
                    shown, line, "with script", f"{expression.text} interpolated into JavaScript"
                )
                self._emit(
                    taint,
                    [hop],
                    Verdict(
                        VerdictKind.SHELL,
                        "expression expanded into the JavaScript that github-script evaluates",
                    ),
                    scope,
                )
                received.append(taint.extend(hop))
        for name, taints in scope.tainted_env().items():
            at = js_references_env(script, name)
            if at is None:
                continue
            verdict = js_heuristic(script, env_names=[name], where=shown)
            hop = Hop(shown, script.body_line + at - 1, "with script", f"process.env.{name}")
            kind = {
                "SUSPECT": VerdictKind.SUSPECT,
                "DIES": VerdictKind.DIES,
                "UNKNOWN": VerdictKind.UNKNOWN,
            }[verdict.kind]
            self._emit_all(
                taints, [hop], Verdict(kind, verdict.reason, verdict.kind != "UNKNOWN"), scope
            )
            received.extend(taint.extend(hop) for taint in taints)
        if step.id and received:
            self._taint_step_outputs(
                step,
                scope,
                received,
                "github-script received the value; its result and every setOutput are treated "
                "as tainted (over-approximation)",
            )

    # -- reusable workflows ------------------------------------------------

    def _reusable(self, job: Job, scope: Scope, level: int) -> TaintMap:
        assert job.uses is not None
        ref_text = str(job.uses)
        with_taints = self._with_taints(job.with_, scope, scope.file, ref_text)
        if not with_taints:
            return {}
        flat = [t for ts in with_taints.values() for t in ts]
        if level >= 1:
            self._emit_all(
                flat,
                [],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"nested reusable workflow {ref_text} beyond one level is not followed",
                ),
                scope,
            )
            return {}
        if ref_text.startswith("./"):
            ref = ActionRef("local", ref_text, path=ref_text[2:])
        else:
            ref = parse_uses(ref_text)
        path = self.resolver.workflow(ref, scope.repo_root)
        if path is None:
            self._mark_opaque(scope, ref.slug)
            self._emit_all(
                flat,
                [],
                Verdict(
                    VerdictKind.UNKNOWN,
                    f"reusable workflow {ref.slug} not available locally",
                ),
                scope,
            )
            return {}
        try:
            called = load_workflow(path)
        except (WorkflowError, YamlError) as exc:
            self._emit_all(flat, [], Verdict(VerdictKind.UNKNOWN, str(exc)), scope)
            return {}
        declared = as_dict(as_dict(as_dict(called.on).get("workflow_call")).get("inputs"))
        shown = self.display(path)
        inputs: TaintMap = {}
        for key, taints in with_taints.items():
            line = next((declared.key_line(k) for k in declared if str(k).lower() == key), 1)
            inputs[key] = self._carry(taints, Hop(shown, line, f"inputs.{key}"), scope)
        job_outputs = self._workflow(called, initial_inputs=inputs, level=level + 1)
        exported: TaintMap = {}
        outputs_decl = as_dict(as_dict(as_dict(called.on).get("workflow_call")).get("outputs"))
        for name, spec in outputs_decl.items():
            value = as_text(as_dict(spec).get("value"))
            if value is None:
                continue
            for body in (e.body for e in find_expressions(value)):
                for out_ref in references(body):
                    parts = out_ref.split(".")
                    if (
                        len(parts) >= 4
                        and parts[0].lower() == "jobs"
                        and parts[2].lower() == "outputs"
                    ):
                        for taint in job_outputs.get(parts[1], {}).get(parts[3], []):
                            hop = Hop(
                                shown, outputs_decl.key_line(name), f"outputs.{name}", out_ref
                            )
                            exported.setdefault(str(name), []).extend(
                                self._carry([taint], hop, scope)
                            )
        return exported

    # -- values that reach no sink ----------------------------------------

    def _never_read(self) -> None:
        for occurrence, (taint, scope) in sorted(self._definitions.items()):
            if occurrence in self._emitted:
                continue
            last = taint.hops[-1]
            opaque = list(dict.fromkeys(self._opaque.get(occurrence, [])))
            if opaque:
                verdict = Verdict(
                    VerdictKind.UNKNOWN,
                    f"{last.carrier} is never read by name in scope, but {len(opaque)} step(s) run "
                    f"opaque actions that inherit the environment: {', '.join(opaque)}",
                )
            else:
                verdict = Verdict(
                    VerdictKind.DIES,
                    f"{last.carrier} is never read by name by any run step, script or resolved "
                    "action in scope",
                )
            self._emit(taint, [], verdict, scope)


def load_line_str(value: object) -> LineStr | None:  # pragma: no cover - re-export helper
    return as_text(value)


__all__ = ["Analyzer", "Scope", "TaintMap", "Trust"]
