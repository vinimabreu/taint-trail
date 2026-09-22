"""Text and JSON renderers. One chain per source occurrence, every hop shown."""

from __future__ import annotations

from typing import Any

from .model import Chain, Summary, Trust, VerdictKind

JSON_VERSION = 1


def summarise(chains: list[Chain], files: list[str]) -> Summary:
    summary = Summary(files=list(files), chains=len(chains))
    for chain in chains:
        if not chain.counts:
            summary.semi_trusted += 1
            continue
        kind = chain.verdict.kind
        if kind is VerdictKind.SHELL:
            summary.shell += 1
        elif kind is VerdictKind.SPOOF:
            summary.spoof += 1
        elif kind is VerdictKind.SUSPECT:
            summary.suspect += 1
        elif kind is VerdictKind.DIES:
            summary.dies += 1
        else:
            summary.unknown += 1
    return summary


def render_chain(chain: Chain) -> str:
    trust = "untrusted" if chain.trust is Trust.UNTRUSTED else "semi-trusted, not counted"
    where = chain.workflow + (f" / job {chain.job}" if chain.job else "")
    lines = [f"{chain.source.label}  [{trust}]  {where}"]
    lines.extend(f"  {hop.render()}" for hop in chain.hops)
    lines.append(f"  {chain.verdict.render()}")
    return "\n".join(lines)


def render_text(chains: list[Chain], summary: Summary) -> str:
    blocks = [render_chain(chain) for chain in chains]
    if not blocks:
        blocks.append("no untrusted value leaves an expression in the scanned files")
    footer = (
        f"{summary.chains} chain(s): SHELL {summary.shell}  SPOOF {summary.spoof}  "
        f"SUSPECT {summary.suspect}  DIES {summary.dies}  UNKNOWN {summary.unknown}"
    )
    if summary.semi_trusted:
        footer += f"  (+{summary.semi_trusted} semi-trusted, not counted)"
    return "\n\n".join(blocks) + "\n\n" + footer + "\n"


def chain_to_dict(chain: Chain) -> dict[str, Any]:
    return {
        "source": chain.source.path,
        "trust": chain.source.trust.value,
        "matched": chain.source.matched,
        "note": chain.source.note,
        "workflow": chain.workflow,
        "job": chain.job,
        "hops": [
            {"file": hop.file, "line": hop.line, "carrier": hop.carrier, "detail": hop.detail}
            for hop in chain.hops
        ],
        "verdict": {
            "kind": chain.verdict.kind.value,
            "heuristic": chain.verdict.heuristic,
            "reason": chain.verdict.reason,
            "text": chain.verdict.render(),
        },
        "counts": chain.counts,
    }


def render_json(chains: list[Chain], summary: Summary, strict: bool) -> dict[str, Any]:
    return {
        "version": JSON_VERSION,
        "files": summary.files,
        "chains": [chain_to_dict(chain) for chain in chains],
        "summary": {
            "chains": summary.chains,
            "SHELL": summary.shell,
            "SPOOF": summary.spoof,
            "SUSPECT": summary.suspect,
            "DIES": summary.dies,
            "UNKNOWN": summary.unknown,
            "semi_trusted": summary.semi_trusted,
        },
        "strict": strict,
        "exit_code": summary.exit_code(strict),
    }
