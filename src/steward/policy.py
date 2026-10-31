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
        site: A hostname, host:port, or an absolute http(s) URL.

    Returns:
        The hostname, without userinfo, port, path, query, or fragment.
        Unicode and punycode spellings of the same host return one form.

    Raises:
        ValueError: The input does not contain one http(s) hostname.
    """
    text = site.strip()
    if not text or any(char.isspace() for char in text):
        raise ValueError(_SITE_ERROR)
    if "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError:
            raise ValueError(_SITE_ERROR) from None
        if parts.scheme not in {"http", "https"}:
            raise ValueError(_SITE_ERROR)
        return _hostname(parts.hostname)
    # A bare approval has no userinfo. `user@host` must not approve `host`,
    # and `javascript:alert(1)` must not approve a host named javascript.
    if any(char in text for char in "@/?#"):
        raise ValueError(_SITE_ERROR)
    if ":" in text and not text.rsplit(":", 1)[-1].isdigit():
        raise ValueError(_SITE_ERROR)
    try:
        parts = urlsplit(f"https://{text}")
    except ValueError:
        raise ValueError(_SITE_ERROR) from None
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
    title = safe_title(page.title, page.url)
    if parsed.domain not in approved:
        return (
            VisibleCapture(
                domain=parsed.domain,
                title=title,
                page_content="not_permitted",
                unavailable_reason=None,
                source_text_role=None,
            ),
            None,
        )
    if page.extraction == "denied":
        return _unavailable(parsed.domain, title, "permission_denied"), None
    if page.extraction != "ok" or page.body is None:
        return _unavailable(parsed.domain, title, "extraction_failed"), None
    return (
        VisibleCapture(
            domain=parsed.domain,
            title=title,
            page_content="available",
            unavailable_reason=None,
            source_text_role="untrusted_data",
        ),
        page.body,
    )


def safe_title(title: str, url: str) -> str | None:
    """Drop a blank title or one that repeats the page address.

    Chrome uses the address as the tab label when document.title is empty.
    That label is not a title the page author wrote, and it can contain the
    path, query, and fragment.
    """
    cleaned = title.strip()
    if not cleaned:
        return None
    forms = {item.casefold() for item in _address_forms(url)}
    if cleaned.casefold() in forms:
        return None
    return cleaned


def page_identity(url: str) -> str:
    """Return the in-memory page key, without userinfo or fragment.

    The key is not stored. A fragment change is the same page, so it must
    not start a new body capture. A path or query change is a different page.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"}:
        return ""
    try:
        host = _hostname(parts.hostname)
    except ValueError:
        return ""
    port = f":{parts.port}" if parts.port else ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{host}{port}{parts.path}{query}"


def _address_forms(url: str) -> set[str]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return {url.strip()}
    raw_host = (parts.hostname or "").rstrip(".").lower()
    try:
        host = _hostname(parts.hostname) if parts.hostname else ""
    except ValueError:
        host = raw_host
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    fragment = f"#{parts.fragment}" if parts.fragment else ""
    candidates = {url.strip()}
    for netloc in {f"{host}{port}", f"{raw_host}{port}"}:
        if not netloc:
            continue
        tail = (
            f"{netloc}{path}{query}{fragment}",
            f"{netloc}{path}{query}",
            f"{netloc}{path}",
            netloc,
        )
        candidates.update(tail)
        if parts.scheme:
            candidates.add(f"{parts.scheme}://{netloc}{path}{query}{fragment}")
    expanded = set(candidates)
    for item in candidates:
        if item.endswith("/"):
            expanded.add(item[:-1])
        elif item:
            expanded.add(f"{item}/")
    return {item for item in expanded if item}


def _unavailable(domain: str, title: str | None, reason: str) -> VisibleCapture:
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
    domain = host.strip().rstrip(".").lower()
    if not domain or "*" in domain or ".." in domain or domain.startswith(".") or "/" in domain:
        raise ValueError(_SITE_ERROR)
    try:
        # Punycode and Unicode must approve the same site. Store the display
        # form so a later visit is not saved under a different spelling.
        try:
            domain.encode("ascii")
            ascii_form = domain
        except UnicodeError:
            ascii_form = domain.encode("idna").decode("ascii")
        display = ascii_form.encode("ascii").decode("idna")
    except UnicodeError:
        raise ValueError(_SITE_ERROR) from None
    if not display or "*" in display:
        raise ValueError(_SITE_ERROR)
    return display
