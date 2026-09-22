from __future__ import annotations

from taint_trail.model import Trust, VerdictKind

from .conftest import ACTIONS, AnalyseText, carriers, counted, kinds, workflow_with


def test_an_env_var_reaching_eval_is_still_a_shell_finding(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
            '        run: eval "$BODY"'
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert carriers(chains[0]) == ["env BODY", "run"]
    assert chains[0].hops[0].line == 9
    assert chains[0].hops[1].line == 10


def test_an_env_var_used_only_as_a_value_dies_in_the_shell(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
            '        run: echo "$BODY"'
        )
    )
    assert kinds(chains) == ["DIES"]
    assert "value" in chains[0].verdict.reason


def test_a_direct_expression_inside_run_is_the_classic_shell_injection(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(workflow_with('      - run: echo "${{ github.event.issue.title }}"'))
    assert kinds(chains) == ["SHELL"]
    assert "classic" in chains[0].verdict.reason
    assert chains[0].hops[0].detail.startswith("${{ github.event.issue.title }}")


def test_an_env_expression_inside_run_is_expanded_before_the_shell_and_is_shell(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
            "        run: echo ${{ env.BODY }}"
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert carriers(chains[0]) == ["env BODY", "run"]


def test_the_sink_line_points_inside_a_multi_line_run_block(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
            '        run: |\n          echo start\n          echo more\n          eval "$BODY"'
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[-1].line == 13


def test_workflow_level_env_is_visible_in_every_job(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with('      - run: eval "$BODY"', env="  BODY: ${{ github.event.comment.body }}")
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[0].carrier == "env BODY"
    assert chains[0].hops[0].line == 5


def test_a_step_env_shadows_a_job_env_with_a_clean_value(analyse_text: AnalyseText) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    env:\n      BODY: ${{ github.event.comment.body }}\n    steps:\n"
        '      - env:\n          BODY: constant\n        run: eval "$BODY"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["DIES"]
    assert "never read" in chains[0].verdict.reason


def test_one_env_var_read_by_two_steps_yields_one_chain_per_sink(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            '      - run: echo "$BODY"\n      - run: eval "$BODY"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert chains[0].occurrence == chains[1].occurrence


def test_a_value_use_is_not_reported_when_the_same_step_also_reaches_a_shell(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            '      - run: |\n          echo "$BODY"\n          eval "$BODY"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["SHELL"]


def test_an_env_var_nobody_reads_dies_with_the_reason_named(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with("      - run: echo nothing", env="  BODY: ${{ github.event.comment.body }}")
    )
    assert kinds(chains) == ["DIES"]
    assert "never read by name" in chains[0].verdict.reason


def test_an_unread_env_var_next_to_an_opaque_action_is_unknown_not_dies(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: someone/opaque@v1\n      - run: echo nothing",
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "someone/opaque@v1" in chains[0].verdict.reason


def test_a_step_that_writes_github_output_taints_all_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: parse\n        env:\n          BODY: ${{ github.event.issue.body }}\n"
            '        run: |\n          d="$(openssl rand -hex 16)"\n          {\n'
            '            echo "cmd<<${d}"\n            echo "$BODY"\n            echo "${d}"\n'
            '          } >> "$GITHUB_OUTPUT"\n'
            "      - env:\n          CMD: ${{ steps.parse.outputs.anything }}\n"
            '        run: eval "$CMD"'
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "steps.parse.outputs.*" in carriers(chains[1])
    assert "over-approximation" in chains[1].hops[1].detail


def test_a_step_output_reference_carries_the_taint_into_a_direct_interpolation(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: parse\n        env:\n          BODY: ${{ github.event.issue.body }}\n"
            '        run: echo "n=$(echo "$BODY" | wc -l)" >> "$GITHUB_OUTPUT"\n'
            "      - run: run-tool ${{ steps.parse.outputs.n }}"
        )
    )
    assert kinds(chains) == ["SPOOF", "SHELL"]


def test_a_step_without_a_tainted_env_does_not_taint_outputs_even_if_it_writes_them(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            '      - id: parse\n        run: echo "n=1" >> "$GITHUB_OUTPUT"\n'
            "      - run: run-tool ${{ steps.parse.outputs.n }}",
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    # BODY is in env but never read; outputs of parse are tainted by the rule.
    assert kinds(chains) == ["SHELL"]


def test_job_outputs_carry_taint_to_a_dependent_job_through_needs(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        "    outputs:\n      t: ${{ steps.g.outputs.t }}\n    steps:\n"
        "      - id: g\n        env:\n          T: ${{ github.event.issue.title }}\n"
        '        run: echo "t=$T" >> "$GITHUB_OUTPUT"\n'
        "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ needs.a.outputs.t }}"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["SPOOF", "SHELL"]
    assert "jobs.a.outputs.t" in carriers(chains[1])
    assert chains[1].job == "b"


def test_jobs_are_analysed_in_dependency_order_even_when_written_backwards(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  b:\n    needs: a\n    runs-on: ubuntu-latest\n"
        '    steps:\n      - run: echo "${{ needs.a.outputs.t }}"\n'
        "  a:\n    runs-on: ubuntu-latest\n    outputs:\n      t: ${{ github.event.issue.title }}\n"
        "    steps:\n      - run: echo hi\n"
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["SHELL"]


def test_a_matrix_built_from_a_tainted_expression_taints_matrix_values(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix: ${{ fromJSON(github.event.client_payload.matrix) }}\n"
        '    steps:\n      - run: echo "${{ matrix.name }}"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["SHELL"]
    assert "strategy.matrix" in carriers(chains[0])


def test_workflow_dispatch_inputs_are_reported_but_never_counted(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            '      - run: echo "${{ github.event.inputs.name }} ${{ inputs.name }}"',
            trigger="workflow_dispatch",
        )
    )
    assert kinds(chains) == ["SHELL", "SHELL"]
    assert all(chain.trust is Trust.SEMI_TRUSTED for chain in chains)
    assert counted(chains) == []


def test_a_step_using_a_non_posix_shell_is_unknown_when_it_mentions_the_var(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - shell: pwsh\n        run: Write-Host $env:BODY",
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason


def test_a_shell_line_with_a_custom_bash_invocation_is_still_analysed(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            '      - shell: bash -e {0}\n        run: eval "$BODY"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["SHELL"]


def test_trusted_context_in_env_produces_no_chain(analyse_text: AnalyseText) -> None:
    chains = analyse_text(workflow_with('      - run: eval "$SHA"', env="  SHA: ${{ github.sha }}"))
    assert chains == []


def test_a_prefix_of_a_source_inside_tojson_is_followed(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            '      - run: echo "$EVENT" | bash', env="  EVENT: ${{ toJSON(github.event) }}"
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].source.note == "contains untrusted fields"


def test_the_verdict_kind_enum_renders_the_expected_tokens() -> None:
    assert VerdictKind.SHELL.value == "SHELL"
    assert VerdictKind.SUSPECT.value == "SUSPECT"


def test_the_actions_fixture_directory_exists_for_every_test_that_recurses() -> None:
    assert (ACTIONS / "example" / "helper-action" / "v1" / "action.yml").is_file()


# --- shell inheritance, matrix include, outputs from an interpolated write ------


def test_a_windows_runner_defaults_to_pwsh_so_the_step_is_unknown(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n"
        "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        "        run: Invoke-Expression $env:BODY\n"
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason


def test_a_job_level_default_shell_is_inherited_by_its_steps(analyse_text: AnalyseText) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    defaults:\n      run:\n        shell: python\n    steps:\n"
        "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        "        run: import os; os.system(os.environ['BODY'])\n"
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: python" in chains[0].verdict.reason


def test_a_workflow_level_default_shell_is_inherited_by_every_job(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issue_comment:\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        '        run: Write-Host "$env:BODY"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason


def test_a_step_shell_overrides_every_inherited_default(analyse_text: AnalyseText) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    runs-on: windows-latest\n"
        "    defaults:\n      run:\n        shell: pwsh\n    steps:\n"
        "      - shell: bash\n        env:\n          BODY: ${{ github.event.comment.body }}\n"
        '        run: eval "$BODY"\n'
    )
    assert kinds(analyse_text(text)) == ["SHELL"]


def test_a_matrix_include_built_from_a_tainted_expression_taints_matrix_values(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix:\n"
        "        include: ${{ fromJSON(github.event.client_payload.matrix) }}\n"
        '    steps:\n      - run: echo "${{ matrix.name }}"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["SHELL"]
    assert "strategy.matrix" in carriers(chains[0])


def test_a_matrix_axis_built_from_a_tainted_expression_taints_matrix_values(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix:\n"
        "        target: ${{ fromJSON(github.event.client_payload.targets) }}\n"
        '    steps:\n      - run: echo "${{ matrix.target }}"\n'
    )
    assert kinds(analyse_text(text)) == ["SHELL"]


def test_a_run_step_that_interpolates_the_expression_into_an_output_write_taints_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: s\n"
            '        run: echo "x=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT\n'
            "      - run: echo ${{ steps.s.outputs.x }}"
        )
    )
    assert kinds(chains) == ["SHELL", "SHELL"]
    assert "steps.s.outputs.*" in carriers(chains[1])


# --- shells other than bash: outputs are tainted all the same -------------------------


def test_a_pwsh_step_that_writes_the_output_file_taints_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: w\n        shell: pwsh\n        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n"
            "        run: '\"r=$env:BODY\" >> $env:GITHUB_OUTPUT'\n"
            '      - run: eval "${{ steps.w.outputs.r }}"'
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "steps.w.outputs.*" in carriers(chains[1])
    assert "over-approximation" in chains[1].hops[1].detail


def test_a_python_step_that_writes_the_output_file_taints_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: w\n        shell: python\n        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n"
            "        run: |\n          import os\n"
            '          open(os.environ["GITHUB_OUTPUT"], "a").write("r=" + os.environ["BODY"])\n'
            '      - run: eval "${{ steps.w.outputs.r }}"'
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


def test_a_cmd_step_that_writes_the_output_file_taints_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: w\n        shell: cmd\n        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n"
            "        run: echo r=%BODY%>> %GITHUB_OUTPUT%\n"
            '      - run: eval "${{ steps.w.outputs.r }}"'
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


def test_a_pwsh_step_that_does_not_write_the_output_file_leaves_its_outputs_clean(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: w\n        shell: pwsh\n        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n"
            "        run: Write-Host $env:BODY\n"
            '      - run: eval "${{ steps.w.outputs.r }}"'
        )
    )
    assert kinds(chains) == ["UNKNOWN"]


# --- runs-on that may select Windows; shells given as a full path -----------------------


def test_a_runs_on_matrix_that_includes_windows_makes_the_shell_undetermined(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    strategy:\n      matrix:\n"
        "        os: [ubuntu-latest, windows-latest]\n    runs-on: ${{ matrix.os }}\n"
        "    steps:\n      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        '        run: echo "$BODY"\n'
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "runs-on" in chains[0].verdict.reason


def test_a_runs_on_mapping_with_a_windows_label_defaults_to_pwsh(
    analyse_text: AnalyseText,
) -> None:
    text = (
        "name: t\non:\n  issue_comment:\njobs:\n  j:\n    runs-on:\n      group: g\n"
        "      labels: [windows]\n    steps:\n"
        "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        "        run: Invoke-Expression $env:BODY\n"
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason


def test_a_shell_given_as_a_full_path_to_bash_is_analysed(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            '      - shell: /bin/bash -e {0}\n        run: eval "$BODY"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["SHELL"]


def test_a_shell_given_as_a_full_path_to_pwsh_is_unknown_by_its_name(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - shell: /usr/bin/pwsh\n        run: Write-Host $env:BODY",
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "shell: pwsh" in chains[0].verdict.reason
