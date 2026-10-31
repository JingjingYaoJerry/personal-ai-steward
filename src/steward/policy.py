# The component responsible for applying Chrome permission rules.
#
# A domain approval is only permission to keep that hostname. The full URL,
# query, fragment, and credentials stay out of stored records.

"""Decide what part of a Chrome page may be retained."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from steward.models import ChromePage

_SITE_ERROR = "site must be a hostname or an absolute http(s) URL"


@dataclass(frozen=True)
class ParsedPage:
    """A page address reduced to whether it is an ordinary website."""

    supported: bool
    domain: str | None


@dataclass(frozen=True)
class VisibleCapture:
    """Fields that may appear on a long-term activity record."""

    domain: str | None
    title: str | None
    page_content: str
    unavailable_reason: str | None
    source_text_role: str | None


def normalize_site(site: str) -> str:
    """Reduce a site approval to its lowercase hostname.

    Args:
        site: A hostname or an absolute http(s) URL.

    Returns:
        The hostname, without userinfo, port, path, query, or fragment.

    Raises:
        ValueError: The input does not contain one http(s) hostname.
    """
    text = site.strip()
    if not text or any(char.isspace() for char in text):
        raise ValueError(_SITE_ERROR)
    try:
        parts = urlsplit(text if "://" in text else f"https://{text}")
    except ValueError:
        raise ValueError(_SITE_ERROR) from None
    if "://" in text and parts.scheme not in {"http", "https"}:
        raise ValueError(_SITE_ERROR)
    return _hostname(parts.hostname)


def parse_page_url(url: str) -> ParsedPage:
    """Classify a page address without retaining the raw URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ParsedPage(supported=False, domain=None)
    if parts.scheme not in {"http", "https"}:
        return ParsedPage(supported=False, domain=None)
    try:
        domain = _hostname(parts.hostname)
    except ValueError:
        return ParsedPage(supported=False, domain=None)
    return ParsedPage(supported=True, domain=domain)


def decide_ordinary_page(page: ChromePage, approved: set[str]) -> tuple[VisibleCapture, str | None]:
    """Decide the stored fields and whether the body may be kept.

    Returns:
        The visible fields, and the body text when it is allowed to be stored.
        The body is omitted for unapproved, failed, denied, and non-http pages.
    """
    parsed = parse_page_url(page.url)
    if not parsed.supported or parsed.domain is None:
        # A file or data URL can itself be the sensitive content, so the title
        # is dropped with the address.
        return (
            VisibleCapture(
                domain=None,
                title=None,
                page_content="unavailable",
                unavailable_reason="unsupported_page",
                source_text_role=None,
            ),
            None,
        )
    if parsed.domain not in approved:
        return (
            VisibleCapture(
                domain=parsed.domain,
                title=page.title,
                page_content="not_permitted",
                unavailable_reason=None,
                source_text_role=None,
            ),
            None,
        )
    if page.extraction == "denied":
        return _unavailable(parsed.domain, page.title, "permission_denied"), None
    if page.extraction != "ok" or page.body is None:
        return _unavailable(parsed.domain, page.title, "extraction_failed"), None
    return (
        VisibleCapture(
            domain=parsed.domain,
            title=page.title,
            page_content="available",
            unavailable_reason=None,
            source_text_role="untrusted_data",
        ),
        page.body,
    )


def _unavailable(domain: str, title: str, reason: str) -> VisibleCapture:
    return VisibleCapture(
        domain=domain,
        title=title,
        page_content="unavailable",
        unavailable_reason=reason,
        source_text_role=None,
    )


def _hostname(host: str | None) -> str:
    if host is None:
        raise ValueError(_SITE_ERROR)
    domain = host.rstrip(".").lower()
    if not domain or "*" in domain or ".." in domain or domain.startswith("."):
        raise ValueError(_SITE_ERROR)
    return domain
