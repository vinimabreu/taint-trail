"""Every fixture workflow, end to end, with the verdicts it must produce."""

from __future__ import annotations

from pathlib import Path

import pytest

from taint_trail.sources import UNTRUSTED_SOURCES

from .conftest import WORKFLOWS, analyse, carriers, counted, kinds


def test_the_direct_run_injection_before_any_fix_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "direct_run_injection.yml")) == ["SHELL"]


def test_moving_the_value_into_env_and_then_evaling_it_is_still_shell() -> None:
    chains = analyse(WORKFLOWS / "moved_not_fixed.yml")
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[-1].line == 15


def test_moving_the_value_through_a_composite_action_into_argv_dies() -> None:
    chains = analyse(WORKFLOWS / "moved_and_died.yml")
    assert kinds(chains) == ["DIES"]
    assert len(chains[0].hops) == 7


def test_a_static_heredoc_delimiter_to_github_output_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "spoof_static_delimiter.yml")) == ["SPOOF"]


def test_a_random_heredoc_delimiter_to_github_output_is_not_spoof() -> None:
    chains = analyse(WORKFLOWS / "spoof_random_delimiter.yml")
    assert kinds(chains) == ["DIES"]
    assert "random heredoc delimiter" in chains[0].verdict.reason


def test_a_docker_action_is_unknown() -> None:
    assert kinds(analyse(WORKFLOWS / "docker_action.yml")) == ["UNKNOWN"]


def test_a_js_action_with_execsync_is_suspect() -> None:
    assert kinds(analyse(WORKFLOWS / "js_execsync.yml")) == ["SUSPECT"]


def test_github_script_with_a_tainted_expression_is_shell() -> None:
    assert kinds(analyse(WORKFLOWS / "github_script.yml")) == ["SHELL"]


def test_workflow_dispatch_inputs_are_semi_trusted_and_not_counted() -> None:
    chains = analyse(WORKFLOWS / "workflow_dispatch_inputs.yml")
    assert kinds(chains) == ["SHELL", "SHELL"]
    assert counted(chains) == []


def test_a_composite_cycle_is_detected() -> None:
    chains = analyse(WORKFLOWS / "composite_cycle.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.reason.startswith("cycle:")


def test_an_unresolvable_action_is_unknown() -> None:
    chains = analyse(WORKFLOWS / "unresolvable_action.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "not available locally" in chains[0].verdict.reason


def test_every_documented_source_is_caught_when_interpolated_into_run() -> None:
    chains = analyse(WORKFLOWS / "all_sources.yml")
    matched = {chain.source.matched for chain in chains}
    assert set(UNTRUSTED_SOURCES) <= matched
    assert all(kind == "SHELL" for kind in kinds(chains))
    assert "github.event" in {chain.source.path for chain in chains}
    assert "github.event.pull_request.number" not in {chain.source.path for chain in chains}


def test_taint_travels_through_step_outputs_to_a_later_step() -> None:
    assert kinds(analyse(WORKFLOWS / "outputs_propagation.yml")) == ["DIES", "SHELL", "SHELL"]


def test_taint_travels_across_jobs_through_needs() -> None:
    chains = analyse(WORKFLOWS / "needs_propagation.yml")
    assert kinds(chains) == ["DIES", "SHELL"]
    assert chains[1].job == "consume"


def test_a_clean_workflow_produces_no_chain() -> None:
    assert analyse(WORKFLOWS / "clean.yml") == []


def test_an_env_var_defined_and_forgotten_dies() -> None:
    chains = analyse(WORKFLOWS / "env_never_read.yml")
    assert kinds(chains) == ["DIES"]


def test_an_env_var_forgotten_next_to_an_opaque_action_is_unknown() -> None:
    assert kinds(analyse(WORKFLOWS / "env_never_read_opaque.yml")) == ["UNKNOWN"]


def test_every_shell_sink_fixture_step_is_shell() -> None:
    chains = analyse(WORKFLOWS / "shell_sinks.yml")
    assert kinds(chains) == ["SHELL"] * 10


def test_every_value_use_fixture_step_dies() -> None:
    assert kinds(analyse(WORKFLOWS / "value_uses.yml")) == ["DIES"] * 5


def test_moving_the_eval_into_a_composite_action_is_still_shell() -> None:
    chains = analyse(WORKFLOWS / "composite_eval.yml")
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[-1].file.endswith("composite-eval/v1/action.yml")


def test_moving_the_value_into_a_composite_action_that_echoes_dies() -> None:
    assert kinds(analyse(WORKFLOWS / "composite_echo.yml")) == ["DIES"]


def test_a_composite_action_output_carries_taint_to_the_caller() -> None:
    assert kinds(analyse(WORKFLOWS / "composite_outputs.yml")) == ["DIES", "SHELL"]


# --- shapes from the adversarial review, each with the verdict it must produce ------


def test_a_one_line_brace_group_with_a_static_delimiter_is_spoof() -> None:
    assert kinds(analyse(WORKFLOWS / "spoof_oneline_brace_group.yml")) == ["SPOOF"]


def test_a_js_action_output_carries_taint_into_a_later_run_step() -> None:
    chains = analyse(WORKFLOWS / "js_action_output_then_run.yml")
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "outputs.result" in carriers(chains[1])


def test_a_composite_action_whose_js_writes_the_output_file_taints_its_outputs() -> None:
    assert kinds(analyse(WORKFLOWS / "composite_js_output_then_run.yml")) == ["DIES", "SHELL"]


def test_github_script_set_output_carries_taint_into_a_later_step() -> None:
    assert kinds(analyse(WORKFLOWS / "github_script_output_then_run.yml")) == ["UNKNOWN", "SHELL"]


def test_the_deprecated_set_output_command_is_spoof_and_taints_the_step_outputs() -> None:
    assert kinds(analyse(WORKFLOWS / "set_output_command_then_run.yml")) == ["SPOOF", "SHELL"]


def test_a_windows_runner_without_a_shell_is_unknown_not_dies() -> None:
    chains = analyse(WORKFLOWS / "windows_default_shell.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason


def test_a_job_default_shell_of_python_is_unknown_not_dies() -> None:
    assert kinds(analyse(WORKFLOWS / "job_default_shell_python.yml")) == ["UNKNOWN"]


def test_an_interpreter_string_that_names_the_variable_is_unknown_not_dies() -> None:
    chains = analyse(WORKFLOWS / "interpreter_string_names_the_var.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "by name" in chains[0].verdict.reason


def test_envsubst_into_a_shell_is_unknown_not_dies() -> None:
    assert kinds(analyse(WORKFLOWS / "envsubst_pipe.yml")) == ["UNKNOWN"]


def test_a_random_write_to_github_env_is_unknown_not_dies() -> None:
    chains = analyse(WORKFLOWS / "github_env_random_then_eval.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "later steps" in chains[0].verdict.reason


def test_a_delimiter_built_from_the_hostname_is_not_random() -> None:
    chains = analyse(WORKFLOWS / "delimiter_from_hostname.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "could not be proven random" in chains[0].verdict.reason


def test_a_matrix_include_from_a_tainted_job_output_propagates() -> None:
    chains = analyse(WORKFLOWS / "matrix_include_from_output.yml")
    assert kinds(chains) == ["DIES", "SHELL"]
    assert chains[1].job == "consume"


def test_an_expression_written_to_the_output_file_taints_the_step_outputs() -> None:
    assert kinds(analyse(WORKFLOWS / "expression_to_output_then_run.yml")) == ["SHELL", "SHELL"]


DOCUMENTED_GAPS = [
    "gap_cmdsub_command_position.yml",
    "gap_backticks.yml",
    "gap_set_positional.yml",
    "gap_awk_system.yml",
    "gap_indirect_eval.yml",
    "gap_dollar_shell.yml",
    "gap_github_script_context_payload.yml",
    "gap_event_path_jq.yml",
    "gap_oneline_compound_redirect.yml",
    "gap_case_esac_redirect.yml",
    "gap_done_continuation.yml",
    "gap_herestring.yml",
    "gap_sibling_flags.yml",
    "gap_wrapper_options.yml",
    "gap_env_busybox_su.yml",
    "gap_deno_bun_bare.yml",
    "gap_deno_redirect.yml",
    "gap_heredoc_program_string.yml",
    "gap_detached_flag_argument.yml",
]


@pytest.mark.parametrize("name", DOCUMENTED_GAPS)
def test_documented_pattern_gaps_produce_no_finding(name: str) -> None:
    """These shapes are listed under Limits in the README. The test pins that claim:
    the day one of them is detected, the README entry has to go."""
    chains = analyse(WORKFLOWS / name)
    assert all(kind not in ("SHELL", "SPOOF") for kind in kinds(chains)), [
        (c.verdict.kind.value, c.verdict.reason) for c in chains
    ]


def test_every_gap_fixture_on_disk_is_pinned_and_the_count_matches_the_readme() -> None:
    """One fixture per Limits sentence: a gap_*.yml that no test names, or a Limits
    line that no fixture pins, is a claim nobody checks."""
    on_disk = sorted(p.name for p in WORKFLOWS.glob("gap_*.yml"))
    assert on_disk == sorted(DOCUMENTED_GAPS)
    assert len(on_disk) == 19


# --- every layout of a group or redirect into the runner file, one file each --------

OUTPUT_GROUPS = sorted((WORKFLOWS / "output_groups").glob("*.yml"))
OUTPUT_REDIRECTS = sorted((WORKFLOWS / "output_redirects").glob("*.yml"))


@pytest.mark.parametrize("path", OUTPUT_GROUPS, ids=[p.stem for p in OUTPUT_GROUPS])
def test_every_output_group_layout_is_spoof(path: Path) -> None:
    chains = analyse(path)
    assert kinds(chains) == ["SPOOF"], [c.verdict.reason for c in chains]


def test_the_output_group_layouts_are_all_present() -> None:
    assert len(OUTPUT_GROUPS) == 42


@pytest.mark.parametrize("path", OUTPUT_REDIRECTS, ids=[p.stem for p in OUTPUT_REDIRECTS])
def test_every_redirect_form_into_the_runner_file_is_spoof(path: Path) -> None:
    chains = analyse(path)
    assert kinds(chains) == ["SPOOF"], [c.verdict.reason for c in chains]


def test_the_redirect_forms_are_all_present() -> None:
    assert len(OUTPUT_REDIRECTS) == 10


# --- shells other than bash still taint outputs; runs-on that may be Windows ---------


def test_a_windows_default_shell_that_writes_the_output_file_taints_the_step_outputs() -> None:
    chains = analyse(WORKFLOWS / "pwsh_writes_output_then_bash_run.yml")
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "steps.w.outputs.*" in carriers(chains[1])


def test_a_python_shell_that_writes_the_output_file_taints_the_step_outputs() -> None:
    chains = analyse(WORKFLOWS / "python_shell_writes_output_then_run.yml")
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "steps.w.outputs.*" in carriers(chains[1])


@pytest.mark.parametrize(
    "name",
    [
        "windows_matrix_runs_on.yml",
        "mixed_matrix_runs_on.yml",
        "windows_runs_on_group_labels.yml",
        "windows_self_hosted_labels.yml",
    ],
)
def test_a_runs_on_that_may_select_a_windows_runner_is_unknown_not_dies(name: str) -> None:
    chains = analyse(WORKFLOWS / name)
    assert kinds(chains) == ["UNKNOWN"], [c.verdict.reason for c in chains]
    assert "shell" in chains[0].verdict.reason


def test_a_linux_only_matrix_runs_on_is_analysed_as_bash() -> None:
    assert kinds(analyse(WORKFLOWS / "linux_matrix_runs_on.yml")) == ["SHELL"]


@pytest.mark.parametrize(
    "name",
    [
        "shell_full_path_bash.yml",
        "shell_precedence_step_over_job_over_workflow.yml",
        "shell_precedence_job_over_workflow.yml",
        "shell_precedence_workflow_over_runner.yml",
    ],
)
def test_shell_precedence_and_a_full_path_to_bash_are_analysed_as_bash(name: str) -> None:
    chains = analyse(WORKFLOWS / name)
    assert kinds(chains) == ["SHELL"], [c.verdict.reason for c in chains]


# --- JavaScript outputs the manifest does not declare; env read through an alias -----


def test_a_js_action_setting_an_undeclared_output_taints_it() -> None:
    chains = analyse(WORKFLOWS / "js_undeclared_output_then_run.yml")
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "outputs.*" in carriers(chains[1])


def test_a_js_action_reading_env_through_an_alias_is_followed() -> None:
    chains = analyse(WORKFLOWS / "js_env_alias_then_run.yml")
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "process.env.HELPER_PROMPT" in carriers(chains[0])


def test_a_js_action_with_no_declared_outputs_taints_every_name() -> None:
    assert kinds(analyse(WORKFLOWS / "js_no_outputs_declared_then_run.yml")) == ["UNKNOWN", "SHELL"]


# --- more interpreters, and commands that never name the variable ---------------------


@pytest.mark.parametrize(
    "name",
    [
        "interpreter_deno_eval_names_the_var.yml",
        "interpreter_bun_e_names_the_var.yml",
        "interpreter_php_r_names_the_var.yml",
    ],
)
def test_the_added_interpreters_naming_the_variable_are_unknown_not_dies(name: str) -> None:
    chains = analyse(WORKFLOWS / name)
    assert kinds(chains) == ["UNKNOWN"]
    assert "by name" in chains[0].verdict.reason


@pytest.mark.parametrize("name", ["no_finding_python_module.yml", "no_finding_npm_test.yml"])
def test_a_command_that_never_names_the_variable_dies(name: str) -> None:
    assert kinds(analyse(WORKFLOWS / name)) == ["DIES"]
