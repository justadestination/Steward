"""Steward identity and the signed request format.

Steward keys are ECDSA P-256 pairs generated in the PWA with WebCrypto.
The private key is non-extractable and never leaves the phone.

Steward ID
    stw_ + base64url(SHA-256(SPKI DER of the public key)), unpadded.
    The private half never leaves the phone.

Signed request
    Headers:
      X-Steward-Id        the Steward ID
      X-Steward-Key       base64url SPKI, sent only on register
      X-Steward-Date      UTC "YYYY-MM-DDTHH:MM:SSZ"
      X-Steward-Sig       base64url raw r||s, 64 bytes

    Signed string (UTF-8, no trailing newline):
      "{METHOD}\n{PATH}\n{DATE}\n{base64url(SHA-256(body bytes))}"

    The format is data: the string above is what the Steward signs, and the
    four headers above are what it sends. This module builds the string from
    the request fields. Verification of the ECDSA P-256 signature is not
    stdlib, so it lives in S2 (the server), which uses `cryptography`.

Max clock skew
    5 minutes. Defined here in one place (do not redefine).
"""

from __future__ import annotations

import base64
import hashlib

# Max clock skew for Steward requests is 5 minutes. One place only:
# see steward/stamp.py for the R8 mail-stamp skew (2 minutes).
CLOCK_SKEW_MINUTES = 5

STEWARD_ID_PREFIX = "stw_"


def _b64url(data: bytes, padding: bool = False) -> str:
    """Base64url, optionally with padding."""
    out = base64.urlsafe_b64encode(data).decode("ascii")
    return out if padding else out.rstrip("=")


def steward_id(spki_der: bytes) -> str:
    """Derive the Steward ID from the SPKI DER bytes of a P-256 public key."""
    digest = hashlib.sha256(spki_der).digest()
    return STEWARD_ID_PREFIX + _b64url(digest)


def signed_string(method: str, path: str, date: str, body: bytes) -> str:
    """Build the string the Steward signs for a request.

    Formats as "METHOD \n PATH \n DATE \n base64url(SHA-256(body bytes))",
    UTF-8, with no trailing newline.
    """
    body_digest = _b64url(hashlib.sha256(body).digest())
    return f"{method}\n{path}\n{date}\n{body_digest}"
