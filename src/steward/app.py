# The component responsible for keeping authorized Chrome page bodies on the PC.
#
# Observation starts only after an explicit request. Raw page text lives in a
# separate file for seven days (168 hours) from the first capture of that
# focused page. The activity record remains after the text expires.

"""Capture the focused Chrome page and expire its body after seven days."""

from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

from steward.clock import Clock
from steward.models import BodyRead, ChromeObservation, ChromePage
from steward.policy import VisibleCapture, decide_ordinary_page, normalize_site

_SEVEN_DAYS = timedelta(days=7)
_LOGGER = logging.getLogger("steward.capture")

# Page text is data about a website. These two fields stay empty so a page
# cannot become the user's statement or the steward's interpretation.
_NOT_A_USER_STATEMENT = None
_NOT_AN_INTERPRETATION = None


@dataclass
class StoredActivity:
    """One focused-window segment persisted without the raw page body."""

    id: str
    schema_version: int
    source_device: str
    source_type: str
    application: str
    attribution: str
    captured_at: str
    last_observed_at: str
    duration_seconds: int
    timezone: str
    domain: str | None
    title: str | None
    page_content: str
    unavailable_reason: str | None
    source_text_role: str | None
    interpretation: None
    user_statement: None
    body_payload_id: str | None

    def to_public(self) -> dict[str, object]:
        """Return the long-term view, without a pointer to the raw body file."""
        return {
            "id": self.id,
            "schema_version": self.schema_version,
            "source_device": self.source_device,
            "source_type": self.source_type,
            "application": self.application,
            "attribution": self.attribution,
            "captured_at": self.captured_at,
            "last_observed_at": self.last_observed_at,
            "duration_seconds": self.duration_seconds,
            "timezone": self.timezone,
            "domain": self.domain,
            "title": self.title,
            "page_content": self.page_content,
            "unavailable_reason": self.unavailable_reason,
            "source_text_role": self.source_text_role,
            "interpretation": self.interpretation,
            "user_statement": self.user_statement,
        }

    def to_json(self) -> dict[str, object]:
        """Return the on-disk record. The payload id is not the page text."""
        stored = self.to_public()
        stored["body_payload_id"] = self.body_payload_id
        return stored


@dataclass
class _OpenSegment:
    """In-memory identity of the page currently being timed.

    The URL is kept here so a path change starts a new capture. It is never
    written to a record, log, export, or backup.
    """

    activity_id: str
    page_id: str
    incognito: bool
    url: str
    visible: VisibleCapture


class Steward:
    """PC-side capture session for the focused Chrome window."""

    def __init__(
        self,
        *,
        clock: Clock,
        data_dir: Path,
        logger: logging.Logger | None = None,
    ) -> None:
        """Open a stopped session and delete bodies that are already expired.

        Args:
            clock: Time source used for capture and the seven-day deadline.
            data_dir: Directory for activity records and raw bodies. This is
                the PC store; phone sync never copies the body files.
            logger: Receiver for status lines. Page text and URLs are not logged.
        """
        current = clock.now()
        if current.tzinfo is None or current.tzinfo.utcoffset(current) is None:
            raise ValueError("clock must be timezone-aware")
        self._clock = clock
        self.data_dir = data_dir
        self._logger = logger or _LOGGER
        self._state = "stopped"
        self._open: _OpenSegment | None = None
        self._approved: set[str] = set()
        self._records: list[StoredActivity] = []
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._load_permissions()
        rewrite = self._load_records()
        if rewrite:
            self._write_records()
        self._enforce_expiry()

    @property
    def observation_state(self) -> str:
        """Return stopped, running, or paused."""
        return self._state

    def start_observation(self) -> None:
        """Start capture. Opening the app does not call this."""
        if self._state != "running":
            # A pause or a new process ends the previous segment so the gap
            # is not counted as continuous time on the page.
            self._open = None
        self._state = "running"

    def pause_observation(self) -> None:
        """Stop later capture until the user starts observation again."""
        if self._state == "running":
            self._state = "paused"
        self._open = None

    def approve_site(self, site: str) -> None:
        """Allow body capture for one hostname."""
        self._approved.add(_require_site(site))
        self._write_permissions()

    def revoke_site(self, site: str) -> None:
        """Stop later body capture for one hostname."""
        self._approved.discard(_require_site(site))
        self._write_permissions()

    def approved_sites(self) -> tuple[str, ...]:
        """Return approved hostnames in sorted order."""
        return tuple(sorted(self._approved))

    def observe(self, observation: ChromeObservation) -> None:
        """Retain the current focused page, or nothing if capture is inactive.

        Background tabs are not read into a record. Incognito input contributes
        usage time only; its page fields are discarded here.
        """
        self._enforce_expiry()
        if self._state != "running":
            self._open = None
            self._logger.info("ignored chrome observation because capture is not running")
            return
        if not observation.focused:
            self._open = None
            self._logger.info("ignored chrome observation because the window is not focused")
            return
        if observation.incognito:
            self._retain_unlabelled_usage()
            return
        active = [item for item in observation.pages if item.active]
        if len(active) != 1:
            self._open = None
            self._logger.info("ignored chrome observation without one focused page")
            return
        self._retain_ordinary(active[0])

    def activity_records(self) -> list[dict[str, object]]:
        """Return long-term activity records after applying expiry."""
        self._enforce_expiry()
        return [record.to_public() for record in self._records]

    def read_body(self, activity_id: str) -> BodyRead:
        """Return the raw page text only when it is still inside seven days."""
        self._enforce_expiry()
        record = self._find(activity_id)
        if record is None:
            return BodyRead(status="missing", text=None)
        if record.page_content != "available":
            return BodyRead(status=record.page_content, text=None)
        payload_id = record.body_payload_id
        path = None if payload_id is None else self._payload_path(payload_id)
        if path is None or not path.is_file():
            return BodyRead(status="missing", text=None)
        return BodyRead(status="available", text=path.read_text(encoding="utf-8"))

    def export_records(self) -> dict[str, object]:
        """Export activity records. Raw webpage bodies are not included."""
        return {
            "format": "personal-ai-steward.activity-export",
            "format_version": 1,
            "includes_webpage_bodies": False,
            "records": self.activity_records(),
        }

    def phone_sync_payload(self) -> dict[str, object]:
        """Build the record payload that may leave the PC. Bodies stay behind."""
        return {
            "format": "personal-ai-steward.phone-sync",
            "format_version": 1,
            "includes_webpage_bodies": False,
            "records": self.activity_records(),
        }

    def write_default_backup(self, path: Path) -> None:
        """Write a default backup of activity records, excluding raw bodies.

        Password encryption is a separate recovery feature. This entry point
        still refuses to archive webpage bodies.
        """
        payload = json.dumps(self.export_records(), ensure_ascii=False, indent=2)
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("activity-export.json", payload)

    def user_statements(self) -> list[object]:
        """Return statements the user confirmed. Page capture never adds any."""
        return []

    def _retain_unlabelled_usage(self) -> None:
        now = self._clock.now()
        visible = VisibleCapture(
            domain=None,
            title=None,
            page_content="not_captured",
            unavailable_reason=None,
            source_text_role=None,
        )
        if self._open is not None and self._open.incognito:
            self._touch(self._require(self._open.activity_id), now)
            self._write_records()
            self._logger.info("extended chrome usage status=not_captured")
            return
        record = self._new_record(now, visible, None)
        self._records.append(record)
        self._open = _OpenSegment(
            activity_id=record.id,
            page_id="",
            incognito=True,
            url="",
            visible=visible,
        )
        self._write_records()
        self._logger.info("retained chrome usage status=not_captured bytes=0")

    def _retain_ordinary(self, page: ChromePage) -> None:
        visible, body = decide_ordinary_page(page, self._approved)
        now = self._clock.now()
        if (
            self._open is not None
            and not self._open.incognito
            and self._open.page_id == page.page_id
            and self._open.url == page.url
            and self._open.visible == visible
        ):
            # Same focused page as the open segment. Keep the original body so
            # polling cannot move the seven-day deadline forward.
            self._touch(self._require(self._open.activity_id), now)
            self._write_records()
            self._logger.info("extended focused chrome page status=%s", visible.page_content)
            return
        payload_id = None if body is None else self._write_body(body)
        record = self._new_record(now, visible, payload_id)
        previous = self._open
        self._records.append(record)
        self._open = _OpenSegment(
            activity_id=record.id,
            page_id=page.page_id,
            incognito=False,
            url=page.url,
            visible=visible,
        )
        try:
            self._write_records()
        except Exception:
            self._records.pop()
            self._open = previous
            if payload_id is not None:
                self._delete_payload(payload_id)
            raise
        byte_count = 0 if body is None else len(body.encode("utf-8"))
        self._logger.info(
            "retained focused chrome page status=%s bytes=%s",
            visible.page_content,
            byte_count,
        )

    def _new_record(
        self,
        moment: datetime,
        visible: VisibleCapture,
        payload_id: str | None,
    ) -> StoredActivity:
        captured_at = moment.isoformat()
        timezone_label = moment.tzname() or moment.strftime("%z") or "UTC"
        return StoredActivity(
            id=uuid4().hex,
            schema_version=1,
            source_device="pc",
            source_type="focused_window",
            application="chrome",
            attribution="observed_activity",
            captured_at=captured_at,
            last_observed_at=captured_at,
            duration_seconds=0,
            timezone=timezone_label,
            domain=visible.domain,
            title=visible.title,
            page_content=visible.page_content,
            unavailable_reason=visible.unavailable_reason,
            source_text_role=visible.source_text_role,
            interpretation=_NOT_AN_INTERPRETATION,
            user_statement=_NOT_A_USER_STATEMENT,
            body_payload_id=payload_id,
        )

    def _touch(self, record: StoredActivity, moment: datetime) -> None:
        captured = datetime.fromisoformat(record.captured_at)
        record.last_observed_at = moment.isoformat()
        record.duration_seconds = int((moment - captured).total_seconds())

    def _enforce_expiry(self) -> None:
        now = self._clock.now()
        changed = False
        for record in self._records:
            if record.page_content == "expired" and record.body_payload_id is not None:
                self._delete_payload(record.body_payload_id)
                record.body_payload_id = None
                changed = True
                continue
            if record.page_content != "available":
                continue
            captured = datetime.fromisoformat(record.captured_at)
            if now >= captured + _SEVEN_DAYS:
                if record.body_payload_id is not None:
                    self._delete_payload(record.body_payload_id)
                record.body_payload_id = None
                record.page_content = "expired"
                changed = True
        if changed:
            self._write_records()
        # A crash can leave a body file that no record points at. Drop those
        # copies whenever expiry runs, including when the app opens.
        self._remove_untracked_bodies()

    def _write_body(self, body: str) -> str:
        payload_id = uuid4().hex
        path = self._payload_path(payload_id)
        if path is None:
            raise ValueError("body payload id was rejected")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body.encode("utf-8"))
        return payload_id

    def _remove_untracked_bodies(self) -> None:
        directory = self.data_dir / "bodies"
        if not directory.is_dir() or directory.is_symlink():
            return
        allowed: set[Path] = set()
        for record in self._records:
            if record.body_payload_id is None:
                continue
            path = self._payload_path(record.body_payload_id)
            if path is not None:
                allowed.add(path)
        for path in sorted(directory.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                if path not in allowed:
                    path.unlink()
            elif path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    continue

    def _delete_payload(self, payload_id: str) -> None:
        path = self._payload_path(payload_id)
        if path is not None:
            path.unlink(missing_ok=True)

    def _payload_path(self, payload_id: str) -> Path | None:
        if not payload_id.isascii() or not payload_id.isalnum() or len(payload_id) > 64:
            return None
        return self.data_dir / "bodies" / payload_id

    def _find(self, activity_id: str) -> StoredActivity | None:
        for record in self._records:
            if record.id == activity_id:
                return record
        return None

    def _require(self, activity_id: str) -> StoredActivity:
        record = self._find(activity_id)
        if record is None:
            raise ValueError("open activity record is missing")
        return record

    def _load_permissions(self) -> None:
        path = self.data_dir / "site_permissions.json"
        if not path.exists():
            return
        parsed = _json_object(path.read_text(encoding="utf-8"))
        hosts = parsed.get("hosts", [])
        if not isinstance(hosts, list):
            raise ValueError("site permissions could not be read")
        approved: set[str] = set()
        for host in hosts:
            if not isinstance(host, str):
                raise ValueError("site permissions could not be read")
            approved.add(_require_site(host))
        self._approved = approved

    def _write_permissions(self) -> None:
        _write_json(
            self.data_dir / "site_permissions.json",
            {"format_version": 1, "hosts": list(self.approved_sites())},
        )

    def _load_records(self) -> bool:
        path = self.data_dir / "activity_records.json"
        if not path.exists():
            self._records = []
            return False
        parsed = _json_object(path.read_text(encoding="utf-8"))
        raw_records = parsed.get("records", [])
        if not isinstance(raw_records, list):
            raise ValueError("activity records could not be read")
        loaded: list[StoredActivity] = []
        for item in raw_records:
            loaded.append(_record_from_json(_object_dict(item)))
        self._records = loaded
        canonical = {"format_version": 1, "records": [record.to_json() for record in loaded]}
        return parsed != canonical

    def _write_records(self) -> None:
        _write_json(
            self.data_dir / "activity_records.json",
            {"format_version": 1, "records": [record.to_json() for record in self._records]},
        )


def _require_site(site: str) -> str:
    return normalize_site(site)


def _record_from_json(item: dict[str, object]) -> StoredActivity:
    return StoredActivity(
        id=_text(item, "id"),
        schema_version=_whole(item, "schema_version"),
        source_device=_text(item, "source_device"),
        source_type=_text(item, "source_type"),
        application=_text(item, "application"),
        attribution=_text(item, "attribution"),
        captured_at=_text(item, "captured_at"),
        last_observed_at=_text(item, "last_observed_at"),
        duration_seconds=_whole(item, "duration_seconds"),
        timezone=_text(item, "timezone"),
        domain=_optional_text(item, "domain"),
        title=_optional_text(item, "title"),
        page_content=_text(item, "page_content"),
        unavailable_reason=_optional_text(item, "unavailable_reason"),
        source_text_role=_optional_text(item, "source_text_role"),
        interpretation=None,
        user_statement=None,
        body_payload_id=_optional_text(item, "body_payload_id"),
    )


def _text(item: dict[str, object], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str):
        raise ValueError("activity records could not be read")
    return value


def _optional_text(item: dict[str, object], field: str) -> str | None:
    value = item.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("activity records could not be read")
    return value


def _whole(item: dict[str, object], field: str) -> int:
    value = item.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("activity records could not be read")
    return value


def _json_object(text: str) -> dict[str, object]:
    value = cast(object, json.loads(text))
    return _object_dict(value)


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("activity records could not be read")
    typed: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("activity records could not be read")
        typed[key] = cast(object, item)
    return typed


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
