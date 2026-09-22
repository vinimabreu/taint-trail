from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from taint_trail import Analyzer, Chain, LocalDirResolver
from taint_trail.workflow import parse_workflow

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
ACTIONS = FIXTURES / "actions"
WORKFLOWS = FIXTURES / "workflows"
REPO = FIXTURES / "repo"
MALFORMED = FIXTURES / "malformed"
TRAVERSAL = FIXTURES / "traversal"


def analyse(path: Path, actions: Path | None = ACTIONS, max_depth: int = 5) -> list[Chain]:
    analyzer = Analyzer(LocalDirResolver(actions), max_depth=max_depth, cwd=ROOT)
    return analyzer.analyse_file(path)


def kinds(chains: list[Chain]) -> list[str]:
    return [chain.verdict.kind.value for chain in chains]


def counted(chains: list[Chain]) -> list[Chain]:
    return [chain for chain in chains if chain.counts]


def carriers(chain: Chain) -> list[str]:
    return [hop.carrier for hop in chain.hops]


AnalyseText = Callable[..., list[Chain]]


@pytest.fixture
def analyse_text(tmp_path: Path) -> AnalyseText:
    def _run(
        text: str,
        actions: Path | None = ACTIONS,
        max_depth: int = 5,
        name: str = "workflow.yml",
    ) -> list[Chain]:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        analyzer = Analyzer(LocalDirResolver(actions), max_depth=max_depth, cwd=ROOT)
        return analyzer.analyse_workflow(parse_workflow(text, path))

    return _run


def workflow_with(steps: str, env: str = "", trigger: str = "issue_comment") -> str:
    """A minimal workflow around a block of steps (already indented by 6 spaces)."""
    env_block = f"env:\n{env}\n" if env else ""
    return (
        f"name: t\non:\n  {trigger}:\n{env_block}jobs:\n  j:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n{steps}\n"
    )
