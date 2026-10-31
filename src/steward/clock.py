# The component responsible for supplying capture timestamps.
#
# Production code reads the clock it is given. Tests move a ManualClock
# instead of waiting for real time to pass.

"""Supply timezone-aware timestamps for capture and expiry."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    """Return the current timezone-aware instant."""

    def now(self) -> datetime:
        """Return the current timestamp."""


class ManualClock:
    """Move only when a test calls advance."""

    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        """Return the current timestamp."""
        return self._now

    def advance(self, *, days: float = 0, seconds: float = 0) -> None:
        """Move the clock forward by a timedelta. Negative values move backward."""
        self._now += timedelta(days=days, seconds=seconds)
