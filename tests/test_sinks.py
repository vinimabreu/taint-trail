from __future__ import annotations

import pytest

from taint_trail.sinks import (
    HitKind,
    ShellHit,
    delimiter_kind,
    mask,
    refs_var,
    scan_shell,
)


def hits(script: str, *tainted: str) -> list[ShellHit]:
    return scan_shell(script, tainted).hits


def only(script: str, *tainted: str) -> ShellHit:
    found = hits(script, *tainted)
    assert len(found) == 1, found
    return found[0]


# --- references --------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["$BODY", "${BODY}", '"$BODY"', '"${BODY}"', "${BODY:-x}", "${BODY//a/b}"]
)
def test_every_expansion_form_counts_as_a_reference(text: str) -> None:
    assert refs_var(text, "BODY")


@pytest.mark.parametrize("text", ["$BODY_TEXT", "$BODYX", "${#BODY}", "BODY", "$body"])
def test_similar_names_and_length_expansions_are_not_references(text: str) -> None:
    assert not refs_var(text, "BODY")


def test_single_quoted_content_is_masked_but_double_quoted_content_is_kept() -> None:
    assert mask("echo '$BODY' \"$BODY\"") == "echo '     ' \"$BODY\""


def test_comments_are_dropped_from_the_masked_view() -> None:
    assert mask('echo "$X" # eval "$BODY"') == 'echo "$X" '


def test_a_hash_inside_a_word_is_not_a_comment() -> None:
    assert mask("echo a#b") == "echo a#b"


# --- shell sinks (moved, not fixed) -------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'eval "$BODY"',
        'bash -c "$BODY"',
        'sh -c "echo $BODY"',
        'bash -lc "$BODY"',
        'zsh -c "$BODY"',
        'source "$BODY"',
        '. "$BODY"',
        'echo "$BODY" | xargs rm -f',
        'printf "%s" "$BODY" | sh',
        'echo "$BODY" | bash',
        'echo "$BODY" | sudo bash',
        "python -c \"print('$BODY')\"",
        "node -e \"console.log('$BODY')\"",
    ],
)
def test_an_env_var_reaching_a_shell_reparse_is_a_shell_hit(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.SHELL


def test_a_tainted_value_in_command_position_is_a_shell_hit() -> None:
    hit = only("$BODY --help", "BODY")
    assert hit.kind is HitKind.SHELL
    assert "command position" in hit.reason


def test_a_pipeline_continued_on_the_next_line_is_joined_before_matching() -> None:
    hit = only('printf "%s" "$BODY" |\n  sh', "BODY")
    assert hit.kind is HitKind.SHELL
    assert hit.line == 0


def test_a_backslash_continuation_is_joined_before_matching() -> None:
    hit = only('bash \\\n  -c "$BODY"', "BODY")
    assert hit.kind is HitKind.SHELL


def test_source_on_one_command_does_not_taint_an_unrelated_echo_in_the_same_line() -> None:
    found = hits('source lib.sh; echo "$BODY"', "BODY")
    kinds = {h.kind for h in found if h.var == "BODY"}
    assert kinds == {HitKind.VALUE}


# --- value uses (moved, and died) ---------------------------------------------


@pytest.mark.parametrize(
    "line",
    ['echo "$BODY"', "echo $BODY", 'run-tool --prompt "$BODY"', 'x="${BODY:-none}"'],
)
def test_an_env_var_used_only_as_a_value_is_a_value_hit(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.VALUE


def test_a_single_quoted_reference_is_not_expanded_and_not_a_hit() -> None:
    assert hits("echo '$BODY'", "BODY") == []


def test_a_commented_out_eval_is_not_a_hit() -> None:
    assert hits('# eval "$BODY"', "BODY") == []


def test_a_variable_assigned_from_a_tainted_one_is_tainted_from_then_on() -> None:
    scan = scan_shell('TMP="$1"\neval "$TMP"', ["1"])
    kinds = [(h.kind, h.var) for h in scan.hits]
    assert (HitKind.SHELL, "TMP") in kinds
    assert scan.origins("TMP") == {"1"}


def test_origins_of_an_underived_name_is_itself() -> None:
    scan = scan_shell('echo "$BODY"', ["BODY"])
    assert scan.origins("BODY") == {"BODY"}


# --- $GITHUB_OUTPUT / $GITHUB_ENV ----------------------------------------------


def test_a_single_line_write_of_a_tainted_value_to_github_output_is_a_spoof() -> None:
    hit = only('echo "body=$BODY" >> "$GITHUB_OUTPUT"', "BODY")
    assert hit.kind is HitKind.SPOOF
    assert "newline" in hit.reason


def test_a_single_line_write_to_github_env_is_a_spoof_too() -> None:
    assert only('echo "BODY=$BODY" >> $GITHUB_ENV', "BODY").kind is HitKind.SPOOF


def test_a_tee_into_github_output_is_a_spoof() -> None:
    assert only('echo "k=$BODY" | tee -a "$GITHUB_OUTPUT"', "BODY").kind is HitKind.SPOOF


def test_a_brace_group_heredoc_with_a_static_delimiter_is_a_spoof() -> None:
    script = '{\n  echo "body<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"'
    hit = only(script, "BODY")
    assert hit.kind is HitKind.SPOOF
    assert hit.line == 2
    assert "'EOF' is static" in hit.reason


def test_three_separate_echoes_form_the_same_static_heredoc_block() -> None:
    script = (
        'echo "body<<EOF" >> $GITHUB_OUTPUT\n'
        'echo "$BODY" >> $GITHUB_OUTPUT\n'
        'echo "EOF" >> $GITHUB_OUTPUT'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.SPOOF
    assert hit.line == 1


def test_a_shell_heredoc_into_github_output_with_a_file_format_marker_is_a_spoof() -> None:
    script = 'cat <<EOF >> "$GITHUB_OUTPUT"\nbody<<END\n$BODY\nEND\nEOF\n'
    hit = only(script, "BODY")
    assert hit.kind is HitKind.SPOOF
    assert hit.line == 2


def test_a_shell_heredoc_into_github_output_without_a_marker_is_a_newline_spoof() -> None:
    hit = only('cat <<EOF >> "$GITHUB_OUTPUT"\nbody=$BODY\nEOF\n', "BODY")
    assert hit.kind is HitKind.SPOOF
    assert "newline" in hit.reason


def test_a_quoted_heredoc_delimiter_prevents_expansion_so_nothing_is_written() -> None:
    assert hits("cat <<'EOF' >> \"$GITHUB_OUTPUT\"\nbody=$BODY\nEOF\n", "BODY") == []


@pytest.mark.parametrize(
    "assignment",
    [
        'delimiter="$(openssl rand -hex 16)"',
        'delimiter="EOF_${RANDOM}"',
        'delimiter="$(uuidgen)"',
        'delimiter="$(head -c 16 /dev/urandom | base64)"',
    ],
)
def test_a_random_delimiter_turns_the_write_into_a_plain_value_use(assignment: str) -> None:
    script = (
        f"{assignment}\n"
        '{\n  echo "body<<${delimiter}"\n  echo "$BODY"\n  echo "${delimiter}"\n'
        '} >> "$GITHUB_OUTPUT"'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.VALUE
    assert "random heredoc delimiter" in hit.reason


def test_a_dynamic_delimiter_that_is_not_provably_random_is_unknown_not_spoof() -> None:
    script = (
        '{\n  echo "body<<EOF_${GITHUB_RUN_ID}"\n  echo "$BODY"\n'
        '  echo "EOF_${GITHUB_RUN_ID}"\n} >> "$GITHUB_OUTPUT"'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "could not be proven random" in hit.reason


def test_delimiter_kinds_are_named() -> None:
    assert delimiter_kind("EOF", {}) == "static"
    assert delimiter_kind("$RANDOM", {}) == "random"
    assert delimiter_kind("${d}", {"d": "$(openssl rand -hex 8)"}) == "random"
    assert delimiter_kind("${d}", {"d": "fixed"}) == "unknown"
    assert delimiter_kind("${d}", {}) == "unknown"


def test_the_scan_records_whether_the_script_writes_the_runner_files() -> None:
    assert scan_shell('echo "x=1" >> $GITHUB_OUTPUT', ["BODY"]).writes_output
    assert scan_shell("echo hi", ["BODY"]).writes_output is False


def test_the_block_closes_after_the_delimiter_so_later_writes_are_plain_again() -> None:
    script = (
        '{\n  echo "body<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"\necho "$BODY"'
    )
    found = hits(script, "BODY")
    assert [h.kind for h in found] == [HitKind.SPOOF, HitKind.VALUE]


# --- heredocs fed to interpreters ---------------------------------------------


def test_a_heredoc_body_with_a_tainted_value_fed_to_bash_is_a_shell_hit() -> None:
    hit = only("bash <<EOF\necho $BODY\nEOF\n", "BODY")
    assert hit.kind is HitKind.SHELL


def test_a_heredoc_body_with_a_tainted_value_fed_to_python_is_a_shell_hit() -> None:
    assert only("python - <<EOF\nprint('$BODY')\nEOF\n", "BODY").kind is HitKind.SHELL


def test_a_heredoc_to_a_plain_file_is_a_value_use() -> None:
    assert only("cat <<EOF > note.txt\n$BODY\nEOF\n", "BODY").kind is HitKind.VALUE


# --- invocations ----------------------------------------------------------------


def test_running_a_script_by_path_is_recorded_as_an_invocation() -> None:
    hit = only('bash "$GITHUB_ACTION_PATH/scripts/run.sh"', "PROMPT")
    assert hit.kind is HitKind.INVOKE
    assert hit.invocation is not None
    assert hit.invocation.interpreter == "bash"
    assert hit.invocation.target == "$GITHUB_ACTION_PATH/scripts/run.sh"
    assert hit.invocation.tainted_args == ()


def test_arguments_carrying_tainted_variables_are_mapped_to_positions() -> None:
    hit = only('./scripts/run.sh "$BODY" plain "$OTHER"', "BODY", "OTHER")
    assert hit.kind is HitKind.INVOKE
    assert hit.invocation is not None
    assert dict(hit.invocation.tainted_args) == {
        "1": frozenset({"BODY"}),
        "3": frozenset({"OTHER"}),
        "@": frozenset({"BODY", "OTHER"}),
        "*": frozenset({"BODY", "OTHER"}),
    }


def test_a_tainted_value_passed_as_an_argument_is_not_also_a_value_hit() -> None:
    found = hits('./run.sh "$BODY"', "BODY")
    assert [h.kind for h in found] == [HitKind.INVOKE]


def test_exec_node_with_a_self_dir_variable_is_an_invocation_and_the_variable_is_known() -> None:
    scan = scan_shell(
        'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\nexec node "$DIR/../dist/index.js"',
        ["PROMPT"],
    )
    assert scan.self_dir_vars == {"DIR"}
    assert scan.hits[0].invocation is not None
    assert scan.hits[0].invocation.interpreter == "node"


def test_a_plain_command_without_a_script_extension_is_not_an_invocation() -> None:
    assert hits("npm install --global helper-cli@1", "PROMPT") == []


def test_sourcing_a_static_file_is_an_invocation_not_a_shell_hit() -> None:
    hit = only('. "$GITHUB_ACTION_PATH/lib.sh"', "BODY")
    assert hit.kind is HitKind.INVOKE
    assert hit.invocation is not None
    assert hit.invocation.interpreter == "."


# --- one-line groups, workflow commands, interpreter strings, delimiters --------


def test_a_one_line_brace_group_with_a_static_delimiter_is_a_spoof() -> None:
    hit = only('{ echo "body<<EOF"; echo "$BODY"; echo "EOF"; } >> "$GITHUB_OUTPUT"', "BODY")
    assert hit.kind is HitKind.SPOOF
    assert "'EOF' is static" in hit.reason


def test_a_one_line_subshell_group_into_github_env_is_a_spoof_too() -> None:
    hit = only('( echo "t<<EOF"; echo "$BODY"; echo "EOF" ) >> $GITHUB_ENV', "BODY")
    assert hit.kind is HitKind.SPOOF
    assert "GITHUB_ENV" in hit.reason


def test_a_one_line_brace_group_with_a_random_delimiter_is_a_value_use() -> None:
    script = (
        'd="$(openssl rand -hex 8)"\n'
        '{ echo "body<<$d"; echo "$BODY"; echo "$d"; } >> "$GITHUB_OUTPUT"'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.VALUE
    assert "random heredoc delimiter" in hit.reason


def test_a_one_line_brace_group_that_evals_inside_is_still_a_shell_hit() -> None:
    assert only('{ eval "$BODY"; } >> "$GITHUB_OUTPUT"', "BODY").kind is HitKind.SHELL


def test_a_one_line_group_redirected_to_a_plain_file_is_a_value_use() -> None:
    assert only('{ echo "$BODY"; } >> notes.txt', "BODY").kind is HitKind.VALUE


def test_the_deprecated_set_output_command_with_a_tainted_value_is_a_spoof() -> None:
    hit = only('echo "::set-output name=x::$BODY"', "BODY")
    assert hit.kind is HitKind.SPOOF
    assert "set-output" in hit.reason


def test_the_deprecated_set_output_command_marks_the_script_as_writing_outputs() -> None:
    assert scan_shell('echo "::set-output name=x::$BODY"', ["BODY"]).writes_output


def test_an_interpreter_string_naming_the_variable_without_a_dollar_is_unknown() -> None:
    hit = only("python3 -c \"import os; os.system('echo ' + os.environ['BODY'])\"", "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "mentions the variable by name" in hit.reason


def test_a_single_quoted_reference_handed_to_envsubst_is_unknown() -> None:
    hit = only("echo 'echo $BODY' | envsubst | bash", "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "mentions the variable by name" in hit.reason


def test_an_interpreter_string_with_a_real_expansion_is_still_a_shell_hit() -> None:
    assert only("python -c \"import os; os.system('echo $BODY')\"", "BODY").kind is HitKind.SHELL


def test_a_bare_name_on_an_ordinary_line_is_not_a_reference() -> None:
    assert hits("echo BODY", "BODY") == []


@pytest.mark.parametrize("token", ["EOF_$$", "EOF_$(head -c 4 /etc/hostname)", "EOF_$(date +%s%N)"])
def test_pids_hostnames_and_clocks_are_not_randomness(token: str) -> None:
    assert delimiter_kind(token, {}) == "unknown"


def test_a_random_write_to_github_env_is_unknown_because_later_steps_are_not_tracked() -> None:
    script = (
        'd="$(openssl rand -hex 8)"\n'
        '{\n  echo "T<<$d"\n  echo "$BODY"\n  echo "$d"\n} >> "$GITHUB_ENV"'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "later steps" in hit.reason


# --- more interpreters: php -r, deno eval, bun -e, and stdin fed through a pipe ------


@pytest.mark.parametrize(
    "line",
    [
        "php -r \"echo '$BODY';\"",
        "deno eval \"console.log('$BODY')\"",
        "bun -e \"console.log('$BODY')\"",
        'echo "$BODY" | python3',
        'echo "$BODY" | python',
        'echo "$BODY" | python3 -',
        'echo "$BODY" | node',
        'echo "$BODY" | node -',
        'echo "$BODY" | php',
        'echo "$BODY" | ruby',
        'echo "$BODY" | perl',
        'echo "$BODY" | deno run -',
        'echo "$BODY" | deno run --allow-all -',
        'echo "$BODY" | sudo python3',
    ],
)
def test_the_added_interpreters_and_stdin_pipes_are_shell_hits(line: str) -> None:
    hit = only(line, "BODY")
    assert hit.kind is HitKind.SHELL, hit


@pytest.mark.parametrize(
    "line",
    [
        'php -r "system(getenv(\\"BODY\\"));"',
        'deno eval "console.log(Deno.env.get(\\"BODY\\"))"',
        'bun -e "console.log(process.env.BODY)"',
    ],
)
def test_the_added_interpreters_naming_the_variable_are_unknown(line: str) -> None:
    hit = only(line, "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "by name" in hit.reason


@pytest.mark.parametrize(
    "line",
    [
        'echo "$BODY" | python3 script.py',
        'echo "$BODY" | python3 -m json.tool',
        'echo "$BODY" | node script.js',
        'echo "$BODY" | deno run script.ts',
        'deno run script.ts "$BODY"',
        'php script.php "$BODY"',
        'bun run script.ts "$BODY"',
    ],
)
def test_an_interpreter_given_a_file_does_not_run_the_piped_value(line: str) -> None:
    kinds = {h.kind for h in hits(line, "BODY")}
    assert HitKind.SHELL not in kinds, kinds


def test_a_heredoc_fed_to_deno_run_stdin_is_a_shell_hit() -> None:
    assert only('deno run - <<EOF\nconsole.log("$BODY")\nEOF\n', "BODY").kind is HitKind.SHELL


def test_a_heredoc_fed_to_php_is_a_shell_hit() -> None:
    assert only("php <<EOF\n<?php echo '$BODY';\nEOF\n", "BODY").kind is HitKind.SHELL
