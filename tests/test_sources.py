from __future__ import annotations

import pytest

from taint_trail.model import Trust
from taint_trail.sources import (
    UNTRUSTED_SOURCES,
    classify,
    direct_sources,
    find_expressions,
    references,
)

CONCRETE = {
    "github.event.pages.*.page_name": "github.event.pages[0].page_name",
    "github.event.commits.*.message": "github.event.commits[0].message",
    "github.event.commits.*.author.name": "github.event.commits[1].author.name",
    "github.event.commits.*.author.email": "github.event.commits[0].author.email",
    "github.event.head_commit.author.*": "github.event.head_commit.author.name",
    "github.event.workflow_run.head_commit.author.*": (
        "github.event.workflow_run.head_commit.author.email"
    ),
    "github.event.client_payload.*": "github.event.client_payload.command",
}


@pytest.mark.parametrize("pattern", UNTRUSTED_SOURCES)
def test_every_documented_untrusted_source_is_classified_untrusted(pattern: str) -> None:
    ref = CONCRETE.get(pattern, pattern)
    source = classify(ref)
    assert source is not None
    assert source.trust is Trust.UNTRUSTED
    assert source.matched == pattern


@pytest.mark.parametrize(
    "ref",
    [
        "github.event.pull_request.number",
        "github.repository",
        "github.sha",
        "github.actor",
        "github.token",
        "github.event_name",
        "github.event.issue.number",
        "github.event.comment.id",
        "secrets.TOKEN",
        "matrix.python-version",
        "runner.os",
    ],
)
def test_trusted_context_paths_are_not_sources(ref: str) -> None:
    assert classify(ref) is None


def test_a_prefix_of_a_source_is_tainted_because_it_contains_the_untrusted_fields() -> None:
    source = classify("github.event")
    assert source is not None
    assert source.trust is Trust.UNTRUSTED
    assert source.note == "contains untrusted fields"
    assert classify("github.event.pull_request") is not None
    assert classify("github.event.issue") is not None


def test_workflow_dispatch_inputs_are_semi_trusted_not_untrusted() -> None:
    source = classify("github.event.inputs.name")
    assert source is not None
    assert source.trust is Trust.SEMI_TRUSTED
    top = classify("inputs.name")
    assert top is not None
    assert top.trust is Trust.SEMI_TRUSTED


def test_matching_is_case_insensitive_like_github_expressions() -> None:
    source = classify("GitHub.Event.Comment.Body")
    assert source is not None
    assert source.matched == "github.event.comment.body"


def test_bracket_indexes_are_folded_into_dotted_paths() -> None:
    assert references("github.event['comment'].body") == ["github.event.comment.body"]
    assert references('github.event["issue"]["title"]') == ["github.event.issue.title"]
    assert references("github.event.commits[0].message") == ["github.event.commits.*.message"]


def test_function_names_and_string_literals_are_not_references() -> None:
    refs = references("contains(github.event.comment.body, '/rerun') && format('{0}', 'x')")
    assert refs == ["github.event.comment.body"]


def test_boolean_and_null_keywords_are_not_references() -> None:
    assert references("true || false || null") == []


def test_direct_sources_deduplicates_and_keeps_order() -> None:
    sources = direct_sources("github.event.issue.title || github.event.issue.title")
    assert [s.path for s in sources] == ["github.event.issue.title"]


def test_find_expressions_reports_span_and_original_text() -> None:
    found = find_expressions('echo "${{ github.event.issue.title }}" and ${{github.sha}}')
    assert [e.body for e in found] == ["github.event.issue.title", "github.sha"]
    assert found[0].text == "${{ github.event.issue.title }}"
    assert found[0].start == 6


def test_a_multiline_expression_counts_its_lines() -> None:
    found = find_expressions("${{\n  github.event.issue.title\n}}")
    assert found[0].lines == 2
