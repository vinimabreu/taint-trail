"""Workflow model: shell inheritance and unreadable files."""

from __future__ import annotations

from pathlib import Path

import pytest

from taint_trail.workflow import WorkflowError, load_workflow, parse_workflow

from .conftest import MALFORMED


def steps_of(text: str) -> list[str | None]:
    workflow = parse_workflow(text, Path("wf.yml"))
    return [step.shell for job in workflow.jobs for step in job.steps]


def test_a_step_without_shell_inherits_the_job_default() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    defaults:\n      run:\n        shell: python\n    steps:\n      - run: print(1)\n"
    )
    assert steps_of(text) == ["python"]


def test_a_step_without_shell_inherits_the_workflow_default() -> None:
    text = (
        "on: push\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: Write-Host 1\n"
    )
    assert steps_of(text) == ["pwsh"]


def test_the_job_default_wins_over_the_workflow_default() -> None:
    text = (
        "on: push\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    defaults:\n      run:\n        shell: bash\n    steps:\n      - run: echo 1\n"
    )
    assert steps_of(text) == ["bash"]


def test_a_windows_runner_defaults_to_pwsh() -> None:
    text = "on: push\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: dir\n"
    assert steps_of(text) == ["pwsh"]


def test_a_windows_label_inside_a_runs_on_list_defaults_to_pwsh() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on: [self-hosted, Windows, x64]\n"
        "    steps:\n      - run: dir\n"
    )
    assert steps_of(text) == ["pwsh"]


def test_a_linux_runner_without_defaults_leaves_the_shell_unset() -> None:
    text = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ls\n"
    assert steps_of(text) == [None]


def test_a_step_shell_wins_over_every_default() -> None:
    text = (
        "on: push\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n    runs-on: windows-latest\n"
        "    defaults:\n      run:\n        shell: cmd\n    steps:\n"
        "      - shell: bash\n        run: echo 1\n      - run: dir\n"
    )
    assert steps_of(text) == ["bash", "cmd"]


def test_a_non_utf8_file_raises_workflow_error_not_unicode_error() -> None:
    with pytest.raises(WorkflowError) as info:
        load_workflow(MALFORMED / "binary.yml")
    assert "binary.yml" in str(info.value)


def test_a_utf16_file_raises_workflow_error(tmp_path: Path) -> None:
    with pytest.raises(WorkflowError):
        load_workflow(MALFORMED / "utf16.yml")


# --- runs-on as a matrix expression or a mapping ---------------------------------------


def matrix_job(matrix: str, runs_on: str = "${{ matrix.os }}") -> str:
    return (
        "on: push\njobs:\n  j:\n    strategy:\n      matrix:\n"
        f"{matrix}    runs-on: {runs_on}\n    steps:\n      - run: dir\n"
    )


def test_a_runs_on_matrix_expression_with_a_windows_value_leaves_the_shell_undetermined() -> None:
    assert steps_of(matrix_job("        os: [ubuntu-latest, windows-latest]\n")) == ["undetermined"]


def test_a_runs_on_matrix_expression_with_only_windows_values_is_undetermined_too() -> None:
    assert steps_of(matrix_job("        os: [windows-latest, windows-2022]\n")) == ["undetermined"]


def test_a_runs_on_matrix_expression_with_only_linux_values_leaves_the_shell_unset() -> None:
    assert steps_of(matrix_job("        os: [ubuntu-latest, ubuntu-22.04]\n")) == [None]


def test_a_runs_on_matrix_include_that_adds_a_windows_value_is_undetermined() -> None:
    matrix = "        os: [ubuntu-latest]\n        include:\n          - os: windows-latest\n"
    assert steps_of(matrix_job(matrix)) == ["undetermined"]


def test_a_runs_on_matrix_that_is_itself_an_expression_is_undetermined() -> None:
    text = (
        "on: push\njobs:\n  j:\n    strategy:\n"
        "      matrix: ${{ fromJSON(github.event.client_payload.matrix) }}\n"
        "    runs-on: ${{ matrix.os }}\n    steps:\n      - run: dir\n"
    )
    assert steps_of(text) == ["undetermined"]


def test_a_runs_on_expression_that_names_no_matrix_key_is_undetermined() -> None:
    assert steps_of(matrix_job("        os: [ubuntu-latest]\n", "${{ inputs.runner }}")) == [
        "undetermined"
    ]


def test_a_runs_on_matrix_key_that_does_not_exist_is_undetermined() -> None:
    assert steps_of(matrix_job("        os: [ubuntu-latest]\n", "${{ matrix.runner }}")) == [
        "undetermined"
    ]


def test_a_runs_on_mapping_with_a_windows_label_defaults_to_pwsh() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on:\n      group: g\n      labels: [x64, Windows]\n"
        "    steps:\n      - run: dir\n"
    )
    assert steps_of(text) == ["pwsh"]


def test_a_runs_on_mapping_with_a_single_windows_label_string_defaults_to_pwsh() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on:\n      group: g\n      labels: windows-latest\n"
        "    steps:\n      - run: dir\n"
    )
    assert steps_of(text) == ["pwsh"]


def test_a_bare_self_hosted_runner_with_no_os_label_is_undetermined() -> None:
    text = "on: push\njobs:\n  j:\n    runs-on: [self-hosted]\n    steps:\n      - run: ls\n"
    assert steps_of(text) == ["undetermined"]


def test_a_self_hosted_runner_with_a_linux_label_is_analysed_as_bash() -> None:
    text = "on: push\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: ls\n"
    assert steps_of(text) == [None]


def test_a_self_hosted_runner_with_an_ubuntu_label_is_analysed_as_bash() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on: [self-hosted, ubuntu-22.04]\n"
        "    steps:\n      - run: ls\n"
    )
    assert steps_of(text) == [None]


def test_a_runs_on_mapping_with_linux_labels_leaves_the_shell_unset() -> None:
    text = (
        "on: push\njobs:\n  j:\n    runs-on:\n      group: g\n      labels: [ubuntu-latest]\n"
        "    steps:\n      - run: ls\n"
    )
    assert steps_of(text) == [None]


def test_a_step_shell_still_wins_over_an_undetermined_runner() -> None:
    text = (
        "on: push\njobs:\n  j:\n    strategy:\n      matrix:\n"
        "        os: [ubuntu-latest, windows-latest]\n    runs-on: ${{ matrix.os }}\n"
        "    steps:\n      - shell: bash\n        run: ls\n"
    )
    assert steps_of(text) == ["bash"]
