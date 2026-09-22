"""End-to-end verdicts for the workflows the fourth adversarial review supplied.

Each fixture is one of the reproducers, copied under a neutral name. The verdict
is what the tool must produce after the round-5 fixes: an interpreter reading
standard input followed by another pipe stage, an arithmetic ``((`` compound
whose terminator redirects to the runner file, a program string naming the
variable after the value was piped in, and a long flag before standard input.
"""

from __future__ import annotations

from .conftest import WORKFLOWS, analyse, kinds


def test_a_pipe_into_an_interpreter_followed_by_tee_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "pipe_interpreter_then_stage.yml")) == ["SHELL"]


def test_an_arithmetic_for_whose_done_line_redirects_to_output_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "arith_for_redirect_output.yml")) == ["SPOOF"]


def test_an_arithmetic_if_whose_fi_line_redirects_to_output_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "arith_if_redirect_output.yml")) == ["SPOOF"]


def test_a_program_string_naming_the_piped_variable_is_unknown() -> None:
    chains = analyse(WORKFLOWS / "pipe_then_program_string_names_the_var.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "by name" in chains[0].verdict.reason


def test_a_pipe_into_an_interpreter_with_a_long_flag_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "pipe_interpreter_long_flag.yml")) == ["SHELL"]
