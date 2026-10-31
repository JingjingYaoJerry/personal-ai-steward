"""Values that cross the Chrome capture boundary."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChromePage:
    page_id: str
    active: bool
    url: str
    title: str
    body: str | None = None
    extraction: str = "ok"


@dataclass(frozen=True)
class ChromeObservation:
    focused: bool
    incognito: bool
    pages: tuple[ChromePage, ...] = ()


@dataclass(frozen=True)
class BodyRead:
    status: str
    text: str | None
