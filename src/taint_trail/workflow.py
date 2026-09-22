"""Workflow file model: jobs, steps, env, with, outputs, with line numbers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .yamlload import LineDict, LineList, LineStr, as_dict, as_list, as_text, load_yaml

UNDETERMINED_SHELL = "undetermined"
"""The default shell of a job whose ``runs-on`` expression may pick a Windows runner."""

_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_MATRIX_KEY_RE = re.compile(r"\s*matrix\.([A-Za-z_][\w-]*)\s*")


class WorkflowError(ValueError):
    pass


@dataclass
class Step:
    index: int
    line: int
    id: str | None
    name: str | None
    uses: LineStr | None
    run: LineStr | None
    shell: str | None
    working_directory: LineStr | None
    env: LineDict
    with_: LineDict
    raw: LineDict

    @property
    def label(self) -> str:
        if self.id:
            return self.id
        if self.name:
            return self.name
        return f"step {self.index + 1}"


@dataclass
class Job:
    id: str
    line: int
    env: LineDict
    steps: list[Step]
    uses: LineStr | None
    with_: LineDict
    outputs: LineDict
    needs: list[str]
    matrix: Any
    raw: LineDict
    default_shell: str | None = None


@dataclass
class Workflow:
    path: Path
    name: str | None
    on: Any
    env: LineDict
    jobs: list[Job] = field(default_factory=list)
    raw: LineDict = field(default_factory=LineDict)

    @property
    def triggers(self) -> list[str]:
        if isinstance(self.on, str):
            return [self.on]
        if isinstance(self.on, LineList):
            return [str(item) for item in self.on]
        if isinstance(self.on, LineDict):
            return [str(key) for key in self.on]
        return []

    @property
    def repo_root(self) -> Path:
        """The repository the workflow belongs to (parent of ``.github/workflows``)."""
        return repo_root_for(self.path)


def repo_root_for(path: Path) -> Path:
    resolved = path.resolve()
    parent = resolved.parent
    if parent.name == "workflows" and parent.parent.name == ".github":
        return parent.parent.parent
    return parent


def parse_step(index: int, raw: Any, default_shell: str | None = None) -> Step:
    """One step. ``default_shell`` is what the job or workflow ``defaults.run.shell``
    (or a Windows runner) supplies when the step names no ``shell:`` of its own."""
    data = as_dict(raw)
    run = as_text(data.get("run"))
    uses = as_text(data.get("uses"))
    shell = as_text(data.get("shell"))
    step_id = as_text(data.get("id"))
    name = as_text(data.get("name"))
    return Step(
        index=index,
        line=data.line or (raw.line if isinstance(raw, LineDict) else 0),
        id=str(step_id) if step_id is not None else None,
        name=str(name) if name is not None else None,
        uses=uses,
        run=run,
        shell=str(shell) if shell is not None else default_shell,
        working_directory=as_text(data.get("working-directory")),
        env=as_dict(data.get("env")),
        with_=as_dict(data.get("with")),
        raw=data,
    )


def parse_steps(raw: Any, default_shell: str | None = None) -> list[Step]:
    return [parse_step(index, item, default_shell) for index, item in enumerate(as_list(raw))]


def default_shell_for(data: LineDict, inherited: str | None) -> str | None:
    """``defaults.run.shell`` of a job or workflow mapping, else what was inherited."""
    shell = as_text(as_dict(as_dict(data.get("defaults")).get("run")).get("shell"))
    return str(shell) if shell is not None else inherited


def _runner_labels(value: Any) -> list[Any]:
    """The labels ``runs-on`` names: a string, a list, or the ``labels`` of a mapping."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, LineList):
        return list(value)
    if isinstance(value, LineDict):
        return _runner_labels(value.get("labels"))
    return []


def _is_windows(label: Any) -> bool:
    return isinstance(label, str) and label.lower().startswith("windows")


_OS_LABEL_PREFIXES = ("ubuntu", "macos", "mac", "linux", "windows", "win")


def _is_os_label(label: Any) -> bool:
    return isinstance(label, str) and label.lower().split("-")[0] in _OS_LABEL_PREFIXES


def _matrix_values(matrix: Any, key: str) -> list[Any] | None:
    """Every value ``matrix.<key>`` can take, or None when an expression decides it."""
    if not isinstance(matrix, LineDict):
        return None
    values: list[Any] = []
    axis = matrix.get(key)
    if isinstance(axis, str) and "${{" in axis:
        return None
    if isinstance(axis, LineList):
        values.extend(axis)
    elif axis is not None:
        values.append(axis)
    for section in ("include", "exclude"):
        items = matrix.get(section)
        if isinstance(items, str) and "${{" in items:
            return None
        if isinstance(items, LineList):
            values.extend(
                item.get(key) for item in items if isinstance(item, LineDict) and key in item
            )
    return values


def runner_shell(runs_on: Any, matrix: Any) -> str | None:
    """The default shell the runner implies: ``pwsh`` for a Windows label,
    ``undetermined`` when an expression in ``runs-on`` may select a Windows runner
    (a matrix key with a Windows value, a matrix that is itself an expression, a
    key that does not exist, or a reference that is not ``matrix.*``), or when a
    ``self-hosted`` runner carries no OS label to say which platform it is, None
    when the runner is known not to be Windows."""
    saw_self_hosted = False
    saw_os_label = False
    for label in _runner_labels(runs_on):
        if not isinstance(label, str):
            continue
        if "${{" not in label:
            if _is_windows(label):
                return "pwsh"
            if label.lower() == "self-hosted":
                saw_self_hosted = True
            elif _is_os_label(label):
                saw_os_label = True
            continue
        for body in _EXPRESSION_RE.findall(label):
            key = _MATRIX_KEY_RE.fullmatch(body)
            if key is None:
                return UNDETERMINED_SHELL
            values = _matrix_values(matrix, key.group(1))
            if not values:
                return UNDETERMINED_SHELL
            if any(_is_windows(v) or (isinstance(v, str) and "${{" in v) for v in values):
                return UNDETERMINED_SHELL
    if saw_self_hosted and not saw_os_label:
        return UNDETERMINED_SHELL
    return None


def parse_job(job_id: str, raw: Any, line: int, inherited_shell: str | None = None) -> Job:
    data = as_dict(raw)
    shell = default_shell_for(data, inherited_shell)
    strategy = as_dict(data.get("strategy"))
    if shell is None:
        shell = runner_shell(data.get("runs-on"), strategy.get("matrix"))
    needs_raw = data.get("needs")
    needs: list[str] = []
    if isinstance(needs_raw, str):
        needs = [str(needs_raw)]
    elif isinstance(needs_raw, LineList):
        needs = [str(item) for item in needs_raw]
    return Job(
        id=job_id,
        line=line,
        env=as_dict(data.get("env")),
        steps=parse_steps(data.get("steps"), shell),
        uses=as_text(data.get("uses")),
        with_=as_dict(data.get("with")),
        outputs=as_dict(data.get("outputs")),
        needs=needs,
        matrix=strategy.get("matrix"),
        raw=data,
        default_shell=shell,
    )


def parse_workflow(text: str, path: Path) -> Workflow:
    raw = load_yaml(text, str(path))
    if not isinstance(raw, LineDict):
        raise WorkflowError(f"{path}: not a YAML mapping")
    jobs_raw = as_dict(raw.get("jobs"))
    workflow_shell = default_shell_for(raw, None)
    jobs = [
        parse_job(str(job_id), job_raw, jobs_raw.key_line(job_id), workflow_shell)
        for job_id, job_raw in jobs_raw.items()
    ]
    name = as_text(raw.get("name"))
    return Workflow(
        path=path,
        name=str(name) if name is not None else None,
        on=raw.get("on"),
        env=as_dict(raw.get("env")),
        jobs=jobs,
        raw=raw,
    )


def load_workflow(path: Path) -> Workflow:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WorkflowError(f"{path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise WorkflowError(f"{path}: not valid UTF-8 ({exc.reason} at byte {exc.start})") from exc
    return parse_workflow(text, path)


def uses_refs(workflow: Workflow) -> list[str]:
    """Every ``uses:`` string in the workflow, jobs and steps, in order."""
    refs: list[str] = []
    for job in workflow.jobs:
        if job.uses is not None:
            refs.append(str(job.uses))
        for step in job.steps:
            if step.uses is not None:
                refs.append(str(step.uses))
    return refs
