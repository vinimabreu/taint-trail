"""Every layout of a group redirected to the runner's output file.

A ``{ ...; }`` or ``( ...; )`` that ends in ``>> "$GITHUB_OUTPUT"`` applies that
target to every command inside, whatever the shape the group takes on the
page. Each entry below is one layout; each must be ``SPOOF`` on the tainted
line with the static delimiter named. The negative cases pin what a group is
not.
"""

from __future__ import annotations

import pytest

from taint_trail.sinks import HitKind, ShellHit, scan_shell

BLOCK = 'echo "x<<EOF"; echo "$BODY"; echo "EOF";'

LAYOUTS: dict[str, tuple[str, int]] = {
    "one line": (f'{{ {BLOCK} }} >> "$GITHUB_OUTPUT"', 0),
    "two lines, close at the end of the second": (f'{{ {BLOCK}\n}} >> "$GITHUB_OUTPUT"', 0),
    "open with content": (
        '{ echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"',
        1,
    ),
    "close on the last body line": (
        '{\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"; } >> "$GITHUB_OUTPUT"',
        2,
    ),
    "test then group": (f'[ -n "$BODY" ] && {{ {BLOCK} }} >> "$GITHUB_OUTPUT"', 0),
    "for do group done": (f'for k in a b; do {{ {BLOCK} }} >> "$GITHUB_OUTPUT"; done', 0),
    "if then group fi": (f'if true; then {{ {BLOCK} }} >> "$GITHUB_OUTPUT"; fi', 0),
    "else branch": (f'if false; then :; else {{ {BLOCK} }} >> "$GITHUB_OUTPUT"; fi', 0),
    "group after or": (f'false || {{ {BLOCK} }} >> "$GITHUB_OUTPUT"', 0),
    "group after semicolon": (f'true; {{ {BLOCK} }} >> "$GITHUB_OUTPUT"', 0),
    "nested one line": (f'{{ {{ {BLOCK} }} ; }} >> "$GITHUB_OUTPUT"', 0),
    "nested multi line": (
        '{\n  {\n    echo "x<<EOF"\n    echo "$BODY"\n    echo "EOF"\n  }\n} >> "$GITHUB_OUTPUT"',
        3,
    ),
    "stderr merged before the append": (
        '{\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} 2>&1 >> "$GITHUB_OUTPUT"',
        2,
    ),
    "while do group done": (
        f'while read -r k; do\n  {{ {BLOCK} }} >> "$GITHUB_OUTPUT"\ndone < list.txt',
        1,
    ),
    "subshell multi line": (
        '(\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n) >> "$GITHUB_OUTPUT"',
        2,
    ),
    "subshell open with content": (
        '( echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n) >> "$GITHUB_OUTPUT"',
        1,
    ),
    "group then more commands": (f'{{ {BLOCK} }} >> "$GITHUB_OUTPUT"; echo done', 0),
    "continuation before the redirect": (f'{{ {BLOCK} }} \\\n  >> "$GITHUB_OUTPUT"', 0),
    "comment line inside": (
        '{\n  # header\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"',
        3,
    ),
    "tab indented body": (
        '{\n\techo "x<<EOF"\n\techo "$BODY"\n\techo "EOF"\n} >> "$GITHUB_OUTPUT"',
        2,
    ),
    "close then pipe to tee": (
        '{\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} | tee -a "$GITHUB_OUTPUT"',
        2,
    ),
    "tee with stdout discarded": (f'{{ {BLOCK} }} | tee -a "$GITHUB_OUTPUT" >/dev/null', 0),
    "brace expansion inside": (
        '{ echo "x<<EOF"; echo {a,b} "$BODY"; echo "EOF"; } >> "$GITHUB_OUTPUT"',
        0,
    ),
    "command substitution inside": (
        '{ echo "x<<EOF"; echo "$(echo "$BODY")"; echo "EOF"; } >> "$GITHUB_OUTPUT"',
        0,
    ),
    "braced expansion unquoted": (
        '{ echo "x<<EOF"; echo ${BODY}; echo "EOF"; } >> "$GITHUB_OUTPUT"',
        0,
    ),
    "case inside the group": (
        '{\n  echo "x<<EOF"\n  case "$k" in\n    a) echo "$BODY";;\n  esac\n  echo "EOF"\n}'
        ' >> "$GITHUB_OUTPUT"',
        3,
    ),
    "arithmetic inside the group": (
        '{\n  echo "x<<EOF"\n  (( n++ ))\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"',
        3,
    ),
    "closing brace attached to a word does not close": (
        '{\n  echo "x<<EOF"\n  echo a}\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"',
        3,
    ),
    "open group deeper in a pipeline chain": (
        f'test -f x && test -f y && {{ {BLOCK} }} >> "$GITHUB_OUTPUT"',
        0,
    ),
}


def spoofs(script: str) -> list[ShellHit]:
    return [h for h in scan_shell(script, ["BODY"]).hits if h.kind is HitKind.SPOOF]


@pytest.mark.parametrize("layout", list(LAYOUTS), ids=list(LAYOUTS))
def test_every_group_layout_applies_the_closing_redirect_to_the_tainted_line(layout: str) -> None:
    script, line = LAYOUTS[layout]
    found = spoofs(script)
    assert [(h.line, h.var) for h in found] == [(line, "BODY")], scan_shell(script, ["BODY"]).hits
    assert "'EOF' is static" in found[0].reason
    assert not [h for h in scan_shell(script, ["BODY"]).hits if h.kind is HitKind.SHELL]


def test_a_shell_heredoc_inside_an_appended_group_is_written_to_the_file() -> None:
    script = '{\n  cat <<EOF\nx<<INNER\n$BODY\nINNER\nEOF\n} >> "$GITHUB_OUTPUT"'
    found = spoofs(script)
    assert [(h.line, h.var) for h in found] == [(3, "BODY")]
    assert "'INNER' is static" in found[0].reason


def test_a_group_piped_into_a_shell_is_a_shell_hit_on_every_line_inside() -> None:
    hits = scan_shell('{\n  echo "$BODY"\n  echo more\n} | bash', ["BODY"]).hits
    assert [(h.kind, h.line) for h in hits] == [(HitKind.SHELL, 1)]
    assert "piped into a shell" in hits[0].reason


def test_a_group_that_evals_inside_is_shell_not_spoof_in_every_layout() -> None:
    script = '{\n  eval "$BODY"\n} >> "$GITHUB_OUTPUT"'
    hits = scan_shell(script, ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.SHELL]


# --- what a group is not ---------------------------------------------------------


@pytest.mark.parametrize(
    "script",
    [
        'foo() {\n  echo "$BODY"\n}',
        '{ echo "$BODY"; } >> notes.txt',
        '{\n  echo "$BODY"\n}\necho "k=1" >> "$GITHUB_OUTPUT"',
        '{ echo "$BODY"',
        '}\necho "$BODY"',
        'echo {a,b} "$BODY"',
        'x=$(echo "$BODY")\necho "$x"',
        '{ echo "x<<EOF"; echo "$BODY"; echo "EOF"; } >> "$OTHER_FILE"',
        'echo "$BODY" >> "$GITHUB_OUTPUT_DIR/notes"',
    ],
    ids=[
        "function body",
        "plain file",
        "no redirect then a clean write",
        "never closed",
        "stray close",
        "brace expansion",
        "command substitution",
        "other variable",
        "similar name",
    ],
)
def test_shapes_that_are_not_an_output_group_stay_value_uses(script: str) -> None:
    hits = scan_shell(script, ["BODY"]).hits
    assert hits, script
    assert {h.kind for h in hits} == {HitKind.VALUE}, hits


def test_a_group_keeps_the_line_numbers_of_its_body() -> None:
    script = 'echo start\n{\n  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"'
    found = spoofs(script)
    assert [h.line for h in found] == [3]


def test_the_prefix_before_a_group_is_scanned_on_its_own() -> None:
    hits = scan_shell('eval "$BODY" && { echo "k=1"; } >> "$GITHUB_OUTPUT"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.SHELL]


def test_the_rest_after_a_group_is_scanned_without_the_group_target() -> None:
    hits = scan_shell('{ echo "k=1"; } >> "$GITHUB_OUTPUT"; echo "$BODY"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.VALUE]


# --- every redirect and tee form, on a simple line and as the group trailer --------

REDIRECTS = [
    ">>",
    ">",
    "1>>",
    "1>",
    "2>>",
    "&>>",
    "&>",
    ">|",
    "2>&1 >>",
    "| tee -a",
    "| tee --append",
    "| sudo tee -a",
    "| tee -ai",
    "| tee --append --ignore-interrupts",
]


@pytest.mark.parametrize("op", REDIRECTS)
def test_every_redirect_form_is_a_target_on_a_simple_line(op: str) -> None:
    hits = scan_shell(f'echo "k=$BODY" {op} "$GITHUB_OUTPUT"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.SPOOF], hits
    assert "newline" in hits[0].reason


@pytest.mark.parametrize("op", REDIRECTS)
def test_every_redirect_form_is_a_target_as_a_group_trailer(op: str) -> None:
    found = spoofs(f'{{ {BLOCK} }} {op} "$GITHUB_OUTPUT"')
    assert [(h.line, h.var) for h in found] == [(0, "BODY")]
    assert "'EOF' is static" in found[0].reason


@pytest.mark.parametrize("op", [">>", "&>>", ">|", "| tee -a"])
def test_every_redirect_form_reaches_the_env_file_too(op: str) -> None:
    hits = scan_shell(f'echo "K=$BODY" {op} "$GITHUB_ENV"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.SPOOF]
    assert "GITHUB_ENV" in hits[0].reason


def test_a_redirect_with_no_space_before_the_target_is_still_a_target() -> None:
    assert [h.kind for h in scan_shell('echo "k=$BODY" >>"$GITHUB_OUTPUT"', ["BODY"]).hits] == [
        HitKind.SPOOF
    ]


def test_stderr_merged_before_the_redirect_does_not_split_the_line() -> None:
    hits = scan_shell('echo "k=$BODY" 2>&1 >> "$GITHUB_OUTPUT"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.SPOOF]


# --- the target held in a variable, or an fd opened with exec ---------------------


@pytest.mark.parametrize(
    "script",
    [
        f'OUT="$GITHUB_OUTPUT"\n{{ {BLOCK} }} >> "$OUT"',
        'OUT=$GITHUB_OUTPUT\necho "k=$BODY" >> $OUT',
        'OUT="${GITHUB_OUTPUT}"\necho "k=$BODY" >> "${OUT}"',
        'export OUT="$GITHUB_OUTPUT"\necho "k=$BODY" | tee -a "$OUT"',
        'A="$GITHUB_OUTPUT"\nB="$A"\necho "k=$BODY" >> "$B"',
    ],
    ids=["group", "unquoted", "braced", "export and tee", "alias of an alias"],
)
def test_a_variable_holding_the_output_file_is_a_target(script: str) -> None:
    found = spoofs(script)
    assert [h.var for h in found] == ["BODY"], scan_shell(script, ["BODY"]).hits


def test_a_variable_holding_the_env_file_names_that_file_in_the_reason() -> None:
    found = spoofs('OUT="$GITHUB_ENV"\necho "K=$BODY" >> "$OUT"')
    assert len(found) == 1
    assert "GITHUB_ENV" in found[0].reason


def test_a_variable_holding_some_other_file_is_not_a_target() -> None:
    hits = scan_shell('OUT=notes.txt\necho "$BODY" >> "$OUT"', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.VALUE]


@pytest.mark.parametrize(
    "script",
    [
        'exec 3>>"$GITHUB_OUTPUT"\necho "x<<EOF" >&3\necho "$BODY" >&3\necho "EOF" >&3',
        'exec 3>> "$GITHUB_OUTPUT"\necho "k=$BODY" 1>&3',
        'exec 3>"$GITHUB_OUTPUT"\necho "k=$BODY" >&3',
        f'exec 5>> "$GITHUB_OUTPUT"\n{{ {BLOCK} }} >&5',
        'OUT="$GITHUB_OUTPUT"\nexec 3>>"$OUT"\necho "k=$BODY" >&3',
    ],
    ids=["three writes", "explicit stdout", "truncate", "group", "through an alias"],
)
def test_a_descriptor_opened_on_the_output_file_with_exec_is_a_target(script: str) -> None:
    found = spoofs(script)
    assert [h.var for h in found] == ["BODY"], scan_shell(script, ["BODY"]).hits


def test_a_descriptor_that_was_not_opened_on_the_output_file_is_not_a_target() -> None:
    hits = scan_shell('exec 3>>"$GITHUB_OUTPUT"\necho "$BODY" >&4', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.VALUE]


def test_a_descriptor_opened_on_another_file_is_not_a_target() -> None:
    hits = scan_shell('exec 3>>notes.txt\necho "$BODY" >&3', ["BODY"]).hits
    assert [h.kind for h in hits] == [HitKind.VALUE]
