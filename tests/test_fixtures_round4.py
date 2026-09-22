"""End-to-end verdicts for the workflows the third adversarial review supplied.

Each fixture is one of the reproducers, copied under a neutral name. The verdict
is what the tool must produce after the round-4 fixes: a shell or interpreter by
full path, a group closing with a continuation, a case pattern inside a subshell,
a redirected loop, a pipe into an interpreter with a redirect, a heredoc piped to
an interpreter given a script file, and a self-hosted runner with no OS label.
"""

from __future__ import annotations

from .conftest import WORKFLOWS, analyse, kinds


def test_full_path_shells_and_interpreters_are_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "full_path_shell.yml")) == ["SHELL", "SHELL", "SHELL"]


def test_a_case_pattern_inside_a_subshell_written_to_output_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "case_in_subshell_output.yml")) == ["SPOOF"]


def test_a_group_closing_with_a_continuation_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "group_close_continuation.yml")) == ["SPOOF"]


def test_a_group_closing_then_piped_to_a_shell_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "group_close_piped_to_shell.yml")) == ["SHELL"]


def test_a_loop_whose_done_line_redirects_to_output_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "loop_done_redirect_output.yml")) == ["SPOOF"]


def test_a_pipe_into_an_interpreter_with_a_redirect_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "pipe_interpreter_redirect.yml")) == ["SHELL"]


def test_a_heredoc_piped_to_an_interpreter_with_a_script_file_dies() -> None:
    assert kinds(analyse(WORKFLOWS / "heredoc_to_interpreter_with_script.yml")) == ["DIES"]


def test_a_bare_self_hosted_runner_is_unknown_not_shell() -> None:
    chains = analyse(WORKFLOWS / "self_hosted_bare_runs_on.yml")
    assert kinds(chains) == ["UNKNOWN"], [c.verdict.reason for c in chains]
    assert "shell" in chains[0].verdict.reason


def test_a_self_hosted_runner_with_a_linux_label_is_analysed_as_bash() -> None:
    assert kinds(analyse(WORKFLOWS / "self_hosted_linux_runs_on.yml")) == ["SHELL"]
