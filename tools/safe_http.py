"""Redirect-safe wrapper around urllib.request.urlopen. Plain urlopen
follows 3xx redirects with no check on the destination — a hostile target
can 302 a scanner into cloud metadata (169.254.169.254), localhost, or an
RFC1918 address, turning the tool into an SSRF proxy against the
operator's own network. See SECURITY-REVIEW-2026-08-22.md finding #8."""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal"}


def _is_blocked_redirect_target(hostname: str) -> bool:
    if not hostname:
        return True
    if hostname.lower() in ("localhost",) or hostname.lower() in _METADATA_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, ValueError):
            return False  # can't resolve — let the real request fail naturally
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast
    )


def _one_hop(req: urllib.request.Request, timeout: float, **kwargs):
    # OpenerDirector.open() (used below) does NOT accept a context=
    # kwarg — only the module-level urllib.request.urlopen() does. Callers
    # that pass context=<ssl.SSLContext>, expecting the same behavior as
    # passing it straight to urlopen(), would otherwise hit a TypeError on
    # every single call. Bind the SSL context to the opener itself via an
    # HTTPSHandler instead of forwarding it as a kwarg to .open().
    context = kwargs.pop("context", None)
    handlers = [_NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        return opener.open(req, timeout=timeout, **kwargs)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            # _NoRedirectHandler.redirect_request returning None makes every
            # installed redirect handler decline, so urllib's chain falls
            # through to HTTPDefaultErrorHandler, which raises HTTPError
            # instead of returning the response. HTTPError doubles as a
            # response object (.status/.code, .headers) — hand it back to
            # the caller's redirect-driving loop instead of letting it
            # propagate as an error.
            return e
        raise


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never auto-follow; safe_urlopen drives redirects itself


def safe_urlopen(req: urllib.request.Request, timeout: float = 10, max_redirects: int = 5, **kwargs):
    """Like urllib.request.urlopen(req), but validates every redirect hop's
    hostname before following it, rejecting private/loopback/link-local/
    metadata addresses.

    Extra keyword arguments are forwarded to the underlying opener on
    every hop, so callers that pass a custom SSL context to urlopen()
    keep that behavior unchanged. context=<ssl.SSLContext> is handled
    specially by _one_hop: OpenerDirector.open() doesn't accept a
    context= kwarg the way module-level urlopen() does, so it's bound to
    an HTTPSHandler on the opener instead of being forwarded as-is."""
    current = req
    for _ in range(max_redirects + 1):
        resp = _one_hop(current, timeout, **kwargs)
        if resp.status not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        next_url = urljoin(current.full_url, location)
        hostname = urlparse(next_url).hostname
        if _is_blocked_redirect_target(hostname):
            raise urllib.error.URLError(
                f"blocked redirect to disallowed host (SSRF guard): {hostname!r}"
            )
        preserve_body = resp.status in (307, 308)
        current = urllib.request.Request(
            next_url,
            data=current.data if preserve_body else None,
            headers=dict(current.header_items()),
            method=current.get_method() if preserve_body else None,
        )
    raise urllib.error.URLError(f"too many redirects (>{max_redirects})")
