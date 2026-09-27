"""Network safety helpers: SSRF guardrails for scan targets.

Scanning is authorization-gated at the data layer (an asset must be marked
AUTHORIZED). This module adds a second, independent control: it refuses to
scan hosts that resolve to private / loopback / link-local / reserved ranges
unless the operator has explicitly enabled the local lab via
``ALLOW_PRIVATE_SCAN_TARGETS``.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse

from app.core.config import settings


class TargetNotAllowed(ValueError):
    """Raised when a target is unsafe or disallowed to scan."""


def _is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"could not resolve host {host!r}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def validate_scan_url(url: str) -> str:
    """Validate a scan target URL, enforcing scheme and SSRF policy.

    Returns the normalized URL or raises :class:`TargetNotAllowed`.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetNotAllowed("target URL must use http:// or https://")
    if not parsed.hostname:
        raise TargetNotAllowed("target URL has no host")

    if settings.allow_private_scan_targets:
        # Local lab / testbed mode — private ranges permitted.
        return url

    ips = resolve_host(parsed.hostname)
    for ip in ips:
        if not _is_public_ip(ip):
            raise TargetNotAllowed(
                f"target {parsed.hostname!r} resolves to non-public address {ip}; "
                "enable ALLOW_PRIVATE_SCAN_TARGETS only for an authorized local lab."
            )
    return url
