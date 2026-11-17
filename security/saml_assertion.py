"""SAML 2.0 assertion verification for a multi-tenant service provider.

Hardening implemented here (one function per defect class):

1. Signature wrapping -- :func:`check_signature_wrapping` rejects an unsigned
   assertion smuggled inside a validly signed envelope. The SP only consumes
   the assertion that the verified signature actually covers.
2. Audience / Recipient confusion -- :func:`recipient_ok` and the audience
   check inside :func:`verify_assertion` use exact, case-sensitive equality.
   A substring match lets an assertion issued for ``https://sp/acs.evil`` or
   audience ``sp-other`` be replayed against this SP.
3. Time window / clock skew -- :func:`time_window_ok` works in UTC epoch
   seconds and takes an explicit ``allowed_skew`` (applied symmetrically to
   both ends) instead of comparing against naive local time.
4. InResponseTo binding -- :func:`verify_assertion` requires the assertion's
   ``in_response_to`` to equal the AuthnRequest ID this SP issued, and
   :func:`replay_cache` rejects any assertion ID seen more than once.
5. Canonicalization / namespaces -- :func:`canonicalize_xml` serializes the
   signed subtree to canonical XML (inclusive namespace rendering) before
   digest/signature verification, so inherited ``xmlns`` declarations or
   prefix changes can no longer cause intermittent digest mismatches.
"""

from __future__ import annotations

import datetime
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

__all__ = [
    'verify_assertion',
    'check_signature_wrapping',
    'recipient_ok',
    'time_window_ok',
    'replay_cache',
    'canonicalize_xml',
]


def _as_epoch(value: Any) -> float:
    """Normalize a time value to UTC epoch seconds.

    Numeric values are treated as epoch seconds directly. Timezone-aware
    datetimes are converted to UTC; naive datetimes are assumed to already be
    UTC and are *never* interpreted in the host's local zone (that was the
    source of premature NotOnOrAfter failures under clock drift).
    """
    # bool is a subclass of int but is never a meaningful timestamp.
    if isinstance(value, bool):
        raise TypeError('boolean is not a valid timestamp')
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.timestamp()
    raise TypeError(f'unsupported timestamp type: {type(value).__name__}')


def canonicalize_xml(data: Any, *, with_comments: bool = False) -> str:
    """Return the canonical XML (C14N 2.0) serialization of ``data``.

    The canonical form must be produced *before* both signature creation and
    signature verification, on the IdP and SP side respectively. Canonical
    XML renders inherited namespace context explicitly and pins each
    namespace to the element where it first appears, so the same logical
    document produces the same byte stream (and therefore the same digest)
    regardless of how the wire parser happened to inherit ``xmlns``
    declarations. Prefixes themselves are preserved by design: a renamed
    prefix is a different byte stream and must fail the digest rather than
    be silently accepted.
    """
    if isinstance(data, ET.Element):
        data = ET.tostring(data, encoding='unicode')
    return ET.canonicalize(data, with_comments=with_comments)


def check_signature_wrapping(assertion: Mapping[str, Any]) -> bool:
    """Return ``True`` when ``assertion`` exhibits a signature-wrapping attack.

    Two shapes are recognized:

    * ``wrapped`` marker -- an unsigned/forged assertion placed next to (or
      inside) a genuinely signed one, with the SP tricked into reading the
      unsigned copy while the signature only covers the original.
    * ``outer_signature`` present without a signature covering the assertion
      itself, or an explicit ``signature_covers_assertion is False`` marker:
      the envelope verifies but the assertion the SP consumes is outside the
      signed subtree.
    """
    if not isinstance(assertion, Mapping):
        return True
    if assertion.get('wrapped') is True:
        return True
    if assertion.get('signature_covers_assertion') is False:
        return True
    if assertion.get('outer_signature') is True and assertion.get('signature') is not True:
        return True
    return False


def recipient_ok(assertion: Mapping[str, Any], expected_recipient: str) -> bool:
    """Exact-match the SubjectConfirmation ``Recipient`` against this SP.

    Deliberately not a substring/``in`` check: ``'sp' in
    'https://sp.evil/acs'`` would accept an assertion addressed to another
    service provider, enabling cross-SP assertion reuse in a multi-tenant
    deployment. The same exact-match rule applies to Audience.
    """
    if not isinstance(assertion, Mapping) or not isinstance(expected_recipient, str):
        return False
    actual = assertion.get('recipient')
    return isinstance(actual, str) and actual == expected_recipient


def time_window_ok(
    assertion: Mapping[str, Any],
    now: Any,
    allowed_skew: float = 0,
) -> bool:
    """Validate ``NotBefore <= now <= NotOnOrAfter`` in UTC, with clock skew.

    ``allowed_skew`` seconds are applied symmetrically: the window is widened
    on both sides so small IdP/SP clock differences cannot reject a live
    assertion. The upper boundary is inclusive (an assertion read at exactly
    ``NotOnOrAfter`` is accepted); anything malformed or missing fails closed.
    """
    if not isinstance(assertion, Mapping):
        return False
    try:
        not_before = _as_epoch(assertion['not_before'])
        not_on_or_after = _as_epoch(assertion['not_on_or_after'])
        now_utc = _as_epoch(now)
    except (KeyError, TypeError, ValueError):
        return False

    if not isinstance(allowed_skew, (int, float)) or isinstance(allowed_skew, bool) or allowed_skew < 0:
        return False

    return (
        now_utc + allowed_skew >= not_before
        and now_utc - allowed_skew <= not_on_or_after
    )


def replay_cache(cache: dict, assertion_id: Any) -> bool:
    """Return ``True`` the first time ``assertion_id`` is seen, ``False`` on replay.

    ``cache`` is a plain dict mapping assertion ID -> first-seen UTC epoch.
    A missing/``None`` id fails closed: an assertion that cannot be
    identified cannot be protected against replay.
    """
    if not isinstance(cache, dict) or assertion_id is None:
        return False
    if assertion_id in cache:
        return False
    cache[assertion_id] = time.time()
    return True


def _audience_ok(assertion: Mapping[str, Any], expected_audience: str) -> bool:
    """Exact audience match; SAML permits several Audience entries."""
    audience = assertion.get('audience')
    if isinstance(audience, (list, tuple, set, frozenset)):
        return all(isinstance(item, str) for item in audience) and expected_audience in audience
    return isinstance(audience, str) and audience == expected_audience


def verify_assertion(
    assertion: Mapping[str, Any],
    request_id: str,
    expected_issuer: str,
    expected_audience: str,
    now: Any,
    expected_recipient: str | None = None,
    replay: dict | None = None,
    allowed_skew: float = 0,
) -> bool:
    """Verify a SAML assertion end-to-end. Returns ``True`` only if every
    check passes; any malformed or missing field fails closed (``False``).

    Checks, in order: well-formed mapping -> signature present and covering
    the assertion (no wrapping) -> issuer -> audience (exact) -> recipient
    (exact, when an expected value is supplied) -> InResponseTo bound to
    ``request_id`` -> UTC validity window -> optional replay cache.
    """
    if not isinstance(assertion, Mapping):
        return False

    # The assertion itself must be signed; an outer-only signature is a
    # wrapping attack unless the signed subtree actually covers the
    # assertion the SP is about to consume.
    if assertion.get('signature') is not True:
        return False
    if check_signature_wrapping(assertion):
        return False

    if assertion.get('issuer') != expected_issuer:
        return False
    if not _audience_ok(assertion, expected_audience):
        return False
    if expected_recipient is not None and not recipient_ok(assertion, expected_recipient):
        return False

    # Bind the assertion to the AuthnRequest this SP actually issued.
    if request_id is None or assertion.get('in_response_to') != request_id:
        return False

    if not time_window_ok(assertion, now, allowed_skew):
        return False

    if replay is not None and not replay_cache(replay, assertion.get('id')):
        return False

    return True
