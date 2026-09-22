"""Data model shared by the analyser and the reporters.

A chain is one path from one occurrence of an untrusted source to one terminal
verdict. Every hop names the file and line where the value changed hands and
what carried it there (an env var, an action input, a step output, a script).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Trust(StrEnum):
    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi-trusted"


class VerdictKind(StrEnum):
    SHELL = "SHELL"
    SPOOF = "SPOOF"
    SUSPECT = "SUSPECT"
    DIES = "DIES"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Source:
    """One untrusted (or semi-trusted) expression reference, as written."""

    path: str
    trust: Trust
    matched: str
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.path} ({self.note})" if self.note else self.path


@dataclass(frozen=True)
class Hop:
    file: str
    line: int
    carrier: str
    detail: str = ""

    def render(self) -> str:
        text = f"{self.file}:{self.line}  {self.carrier}"
        if self.detail:
            text += f"  ({self.detail})"
        return text


@dataclass(frozen=True)
class Verdict:
    kind: VerdictKind
    reason: str
    heuristic: bool = False

    def render(self) -> str:
        head = self.kind.value
        if self.heuristic:
            head += " (heuristic)"
        return f"{head}: {self.reason}" if self.reason else head


@dataclass(frozen=True)
class Taint:
    """An untrusted value in flight: where it came from and every hop so far."""

    source: Source
    occurrence: int
    hops: tuple[Hop, ...] = ()

    def extend(self, hop: Hop) -> Taint:
        return Taint(self.source, self.occurrence, (*self.hops, hop))


@dataclass
class Chain:
    source: Source
    hops: list[Hop]
    verdict: Verdict
    workflow: str = ""
    job: str = ""
    occurrence: int = 0

    @property
    def trust(self) -> Trust:
        return self.source.trust

    @property
    def counts(self) -> bool:
        """Only untrusted sources count toward the exit code."""
        return self.source.trust is Trust.UNTRUSTED


@dataclass
class Summary:
    shell: int = 0
    spoof: int = 0
    suspect: int = 0
    dies: int = 0
    unknown: int = 0
    semi_trusted: int = 0
    chains: int = 0
    files: list[str] = field(default_factory=list)

    def exit_code(self, strict: bool) -> int:
        if self.shell or self.spoof:
            return 1
        if strict and (self.suspect or self.unknown):
            return 1
        return 0
