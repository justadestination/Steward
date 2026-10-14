# Steward request signing

This document describes the signed request format the Steward sends to the
House, and how a client derives the Steward identifier. It is the contract
both the PWA (`pwa/identity.js`) and the server (`steward/identity.py`) agree
on; the server verifies the signature with `cryptography` (not stdlib).

## Steward key and Steward ID

On first launch the PWA generates an ECDSA P-256 key pair with WebCrypto,
`generateKey({name:'ECDSA',namedCurve:'P-256'}, false, ['sign','verify'])`,
extraction disabled, so the private key is non-extractable and never leaves
the phone. The key pair is persisted in IndexedDB (CryptoKey objects are
structured-cloneable). The Steward ID is derived from the public key:

    Steward ID = "stw_" + base64url(SHA-256(SPKI DER of the public key))

The private half never leaves the phone, and the Steward ID is never used to
identify a person: it is the ward's anonymous token on ShadeNet.

## Signed request

Every request the Steward sends is signed with its private key. The request
carries these headers:

  X-Steward-Id     the Steward ID (computed above)
  X-Steward-Key    base64url SPKI DER of the public key, sent only on
                   register; the server uses it to derive the same Steward ID
  X-Steward-Date   UTC "YYYY-MM-DDTHH:MM:SSZ"
  X-Steward-Sig    base64url raw r||s, 64 bytes

All binary header values are base64url without padding. The signature is raw
r||s (IEEE P1363, 32 bytes each), not DER: that is what WebCrypto ECDSA
produces. A server using `cryptography` must convert it with
`encode_dss_signature(r, s)` before calling `verify`.

In the PWA, `signRequest(keyPair, req)` sends X-Steward-Id, X-Steward-Date and
X-Steward-Sig; `signRequest(keyPair, req, { includeKey: true })` also sends
X-Steward-Key, and is used only for register.

The signed string is a canonical representation of the request, UTF-8 with no
trailing newline:

    METHOD \n PATH \n DATE \n base64url(SHA-256(body bytes))

`DATE` is the same `X-Steward-Date` header (seconds precision). The signature
is over that exact string. Requests with a clock skew of more than 5 minutes
are refused.

## Register flow

The Steward first registers its public key:

  1. Derive the Steward ID from the SPKI DER (the same formula as above).
  2. Sign a `{steward_id}` body with the signed-string construction.
  3. Send `POST /register` with the four headers above (`includeKey: true`).

The server derives the Steward ID from the SPKI it received, verifies the
ECDSA P-256 signature, and stores the public key. No private key ever crosses
the network.

## Verification

Verification is not stdlib: the server performs it with `cryptography`
(KeyObject.verify), and the PWA performs the analogous check with
`crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'}, publicKey, signature,
signedString)`.

## Test vector

`vectors/identity/signing.json` is written by
`node tools/make_identity_vector.mjs` (JS, because stdlib Python cannot sign
ECDSA). The script imports a fixed P-256 key labelled TEST ONLY, builds the
signed string for a register request, signs it with WebCrypto and writes
`spki_der` (hex), `spki_der_b64url`, `steward_id`, `body_digest`,
`signed_string` and the four headers (base64url, unpadded). The signature is
raw r||s (IEEE P1363), not DER. ECDSA signatures are randomized, so the
signature changes on each run; both test suites check it by shape and the JS
suite verifies it with WebCrypto, never byte for byte.
