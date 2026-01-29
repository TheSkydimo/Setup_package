from __future__ import annotations

import queue
from dataclasses import dataclass
from typing import Protocol


class LogSink(Protocol):
    def write(self, text: str) -> None: ...


@dataclass(frozen=True)
class QueueLogSink:
    q: "queue.Queue[str]"

    def write(self, text: str) -> None:
        if not text:
            return
        self.q.put(text)


class QueueWriter:
    """
    A minimal file-like object to redirect stdout/stderr into a queue.
    """

    def __init__(self, sink: LogSink):
        self._sink = sink

    def write(self, s: str) -> int:
        self._sink.write(s)
        return len(s)

    def flush(self) -> None:
        return

