"""The adapter contract.

An adapter is anything that yields :class:`~codegraph_trace.models.Step` objects from some
agent's log. Keeping this surface tiny is what lets new agents plug in with a single small
module instead of touching the recorder.
"""

from __future__ import annotations

from typing import Iterable, Iterator, Protocol, runtime_checkable

from ..models import Step


@runtime_checkable
class StepSource(Protocol):
    """A source of agent steps in the internal shape."""

    def steps(self) -> Iterable[Step]:
        """Yield steps in chronological order."""
        ...


def iter_steps(source: StepSource) -> Iterator[Step]:
    """Iterate a :class:`StepSource` defensively (any iterable of Step)."""
    for step in source.steps():
        yield step
