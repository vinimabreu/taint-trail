"""The tool on its own CI, and the CI step that proves the tool detects.

Two halves. The first scans ``ci.yml`` and expects nothing: that is the
regression half. The second runs the exact ``run:`` script of the CI step that
scans two known-bad fixtures and expects exit 1 with ``SHELL`` and ``SPOOF``
in the output: that is the evidence half. A self-scan alone would pass for a
tool that detects nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from taint_trail.cli import main
from taint_trail.workflow import load_workflow

from .conftest import ROOT, WORKFLOWS, analyse, counted

CI = ROOT / ".github" / "workflows" / "ci.yml"
KNOWN_BAD = ("direct_run_injection.yml", "spoof_oneline_brace_group.yml")
KNOWN_BAD_STEP = "taint-trail on known-bad fixtures"


def test_the_repositorys_own_ci_workflow_has_no_shell_or_spoof_verdict() -> None:
    chains = analyse(CI, actions=None)
    assert all(chain.verdict.kind.value not in ("SHELL", "SPOOF") for chain in counted(chains))


def test_the_repositorys_own_ci_workflow_is_clean_even_under_strict() -> None:
    chains = analyse(CI, actions=None)
    assert counted(chains) == []


def test_the_known_bad_fixtures_exit_one_with_shell_and_spoof(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main([str(WORKFLOWS / name) for name in KNOWN_BAD])
    out = capsys.readouterr().out
    assert code == 1
    assert "SHELL:" in out
    assert "SPOOF:" in out


def known_bad_step_script() -> str:
    workflow = load_workflow(CI)
    for job in workflow.jobs:
        for step in job.steps:
            if step.name == KNOWN_BAD_STEP:
                assert step.run is not None
                return str(step.run)
    raise AssertionError(f"ci.yml has no step named {KNOWN_BAD_STEP!r}")


def test_the_ci_has_a_step_that_scans_both_known_bad_fixtures() -> None:
    script = known_bad_step_script()
    for name in KNOWN_BAD:
        assert name in script
    assert "SHELL" in script
    assert "SPOOF" in script


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_ci_known_bad_step_script_passes_when_run_as_the_runner_would(
    tmp_path: Path,
) -> None:
    script = tmp_path / "step.sh"
    script.write_text(known_bad_step_script(), encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SHELL:" in result.stdout
    assert "SPOOF:" in result.stdout
