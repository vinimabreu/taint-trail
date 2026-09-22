from __future__ import annotations

from taint_trail.model import Chain, Hop, Source, Summary, Trust, Verdict, VerdictKind
from taint_trail.report import render_chain, render_json, render_text, summarise


def chain(kind: VerdictKind, trust: Trust = Trust.UNTRUSTED, heuristic: bool = False) -> Chain:
    return Chain(
        source=Source("github.event.issue.title", trust, "github.event.issue.title"),
        hops=[Hop("wf.yml", 3, "env TITLE"), Hop("wf.yml", 5, "run", 'eval "$TITLE"')],
        verdict=Verdict(kind, "why", heuristic),
        workflow="wf.yml",
        job="build",
    )


def test_summary_counts_each_verdict_and_leaves_semi_trusted_aside() -> None:
    summary = summarise(
        [
            chain(VerdictKind.SHELL),
            chain(VerdictKind.SPOOF),
            chain(VerdictKind.SUSPECT),
            chain(VerdictKind.DIES),
            chain(VerdictKind.UNKNOWN),
            chain(VerdictKind.SHELL, Trust.SEMI_TRUSTED),
        ],
        ["wf.yml"],
    )
    assert (summary.shell, summary.spoof, summary.suspect, summary.dies, summary.unknown) == (
        1,
        1,
        1,
        1,
        1,
    )
    assert summary.semi_trusted == 1
    assert summary.chains == 6


def test_exit_code_rules() -> None:
    assert Summary(shell=1).exit_code(strict=False) == 1
    assert Summary(spoof=1).exit_code(strict=False) == 1
    assert Summary(suspect=1).exit_code(strict=False) == 0
    assert Summary(unknown=1).exit_code(strict=False) == 0
    assert Summary(suspect=1).exit_code(strict=True) == 1
    assert Summary(unknown=1).exit_code(strict=True) == 1
    assert Summary(dies=5).exit_code(strict=True) == 0


def test_a_chain_renders_header_hops_and_verdict() -> None:
    text = render_chain(chain(VerdictKind.SHELL))
    assert text.splitlines() == [
        "github.event.issue.title  [untrusted]  wf.yml / job build",
        "  wf.yml:3  env TITLE",
        '  wf.yml:5  run  (eval "$TITLE")',
        "  SHELL: why",
    ]


def test_a_heuristic_verdict_carries_the_word_heuristic() -> None:
    assert Verdict(VerdictKind.DIES, "argv", heuristic=True).render() == "DIES (heuristic): argv"
    assert Verdict(VerdictKind.UNKNOWN, "no").render() == "UNKNOWN: no"


def test_a_verdict_without_a_reason_renders_only_the_kind() -> None:
    assert Verdict(VerdictKind.DIES, "").render() == "DIES"


def test_text_output_ends_with_a_summary_line() -> None:
    chains = [chain(VerdictKind.SHELL), chain(VerdictKind.SHELL, Trust.SEMI_TRUSTED)]
    text = render_text(chains, summarise(chains, ["wf.yml"]))
    assert text.rstrip().splitlines()[-1] == (
        "2 chain(s): SHELL 1  SPOOF 0  SUSPECT 0  DIES 0  UNKNOWN 0  (+1 semi-trusted, not counted)"
    )


def test_semi_trusted_chains_say_so_in_the_header() -> None:
    assert "[semi-trusted, not counted]" in render_chain(
        chain(VerdictKind.SHELL, Trust.SEMI_TRUSTED)
    )


def test_json_includes_files_and_exit_code() -> None:
    chains = [chain(VerdictKind.SUSPECT, heuristic=True)]
    data = render_json(chains, summarise(chains, ["wf.yml"]), strict=True)
    assert data["files"] == ["wf.yml"]
    assert data["exit_code"] == 1
    assert data["chains"][0]["verdict"]["heuristic"] is True
