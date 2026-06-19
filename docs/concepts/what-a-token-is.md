# What a token *is* — the keystone

> **Concept doc (explanation). The keystone of the course.** Stage 2. Anchored on **mini-token**.
> New terms link to [`GLOSSARY.md`](../GLOSSARY.md); the rationale for hand-rolling the JWS lives in
> [`DIRECTION.md`](../DIRECTION.md). Pairs with the lab
> [`tutorials/02-build-and-verify-a-token-by-hand.md`](../tutorials/02-build-and-verify-a-token-by-hand.md),
> where you build and verify one *by hand* — do that lab. This doc + that lab are the single most
> important thing in the set: they convert "a JWT is some opaque string" into a real model.

If you take one idea from the whole course, take this:

> **A token is a JSON object plus a signature over its exact bytes. "Verifying" it means
> recomputing those bytes and checking the signature against a public key you already trust — with
> no call back to whoever issued it.**

Everything else (OAuth, OIDC, sessions, scopes) is plumbing *around* that fact.

---

## A token is just claims

A [JWT](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect) is a set of **claims** — a JSON object:

```json
{ "iss": "https://idp.example", "sub": "svc-abc123", "aud": "https://kms.example",
  "iat": 1750000000, "nbf": 1750000000, "exp": 1750000300, "jti": "a1b2c3…",
  "grants": { … } }
```

`iss` (who issued it), `sub` (who it's about — your `Principal.id` from stage 1), `aud` (who it's
*for*), the time window (`iat`/`nbf`/`exp`), `jti` (a unique id, for revocation), and the
family-specific `grants` claim. **The claims are not secret** — anyone can read them. What stops you
from *forging* one is the signature.

---

## A JWS is three base64url segments

The signed, compact form is a [JWS](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect). It's
literally three base64url strings joined by dots:

```
base64url(header) . base64url(payload) . base64url(signature)
└── {"alg":"EdDSA","kid":"…"}      └── {"iss":…,"sub":…}        └── 64 raw signature bytes
```

- **header** — `{"alg":"EdDSA","kid":"…"}`. The `alg` names the algorithm; the
  [`kid`](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect) names *which* signing key was used.
- **payload** — the claims object above.
- **signature** — an [Ed25519](../GLOSSARY.md#cryptographic-foundations) signature.

### The detail everyone gets wrong: *what* is signed

The signature is **not** over the raw JSON. It's over the ASCII of the first two segments —
the base64url *text*:

```
signingInput = base64url(header) + "." + base64url(payload)        ← this exact ASCII string
signature    = Ed25519-sign(privateKey, signingInput)
token        = signingInput + "." + base64url(signature)
```

This matters because JSON is not canonical — re-serializing `{"a":1,"b":2}` could reorder keys or
change whitespace and produce *different bytes*, which would break the signature. By signing the
already-encoded text and **never parse-then-reserializing before verifying**, the verifier checks
the *exact bytes that were signed*. (Read `token/Jws.java` — the whole class is ~80 lines and worth
reading end to end. This is why the family hand-rolls the JWS instead of pulling a JOSE library: a
compact JWS is simple enough to *read*.)

---

## Offline verification: the whole point

Because the signature covers reproducible bytes and the *public* key is published, anyone can verify
a token **without contacting the issuer.** That's what makes tokens scale: the issuer signs once;
every verifier checks locally, forever, even offline.

The public keys are published as a [JWKS](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect) — a
JSON Web Key Set — at a URL like `/jwks.json`. For Ed25519 each key is an "OKP" JWK:
`{"kty":"OKP","crv":"Ed25519","x":"<raw 32-byte public key, base64url>","use":"sig","alg":"EdDSA","kid":"…"}`.
Only **public** material — safe to serve unauthenticated.

### Verification order is a security property, not a style choice

`TokenVerifier` (the reference offline verifier) runs the checks in a deliberate order. The order
*is* the lesson:

1. **Split** the token into three segments. Parse only the *header* (you need the `kid`). Don't trust
   the payload yet.
2. **Pin the algorithm.** Reject any header whose `alg` isn't `EdDSA`. The verifier only ever
   verifies with an Ed25519 key. **Never let the token's own `alg` field choose the verification
   algorithm** — that's the classic JOSE *alg-confusion* footgun (`alg: none`, or RS256↔HS256
   key confusion). The token doesn't get to pick how it's checked.
3. **Select the key by `kid`**, from the trusted JWKS. Unknown `kid` → reject.
4. **Verify the signature** over the signing input. Fail → reject. *Only now is the payload
   trustworthy.*
5. **Parse the claims and check them:** `iss`, `aud`, the time window (`nbf`/`exp`, with a small
   clock-skew leeway), then the **revocation** denylist (`jti`).

Step 4 before step 5 is the rule: **never trust claim data until the signature is proven.** A
verifier that read `exp` or `sub` before checking the signature would be trusting attacker-controlled
bytes.

Every failure collapses to "not valid" — a verifier never returns an *oracle* explaining *why*. (See
[`secure-design-invariants.md`](secure-design-invariants.md).)

---

## Rotation and revocation — how keys and tokens end

- **Key rotation.** The issuer signs with one *active* key, but the JWKS keeps **retired public keys
  published** until they outlive the token TTL (mini-token's `SigningKeyService`, with a
  `retiredKeyRetention` ≈ 2× TTL). So a token signed just before a rotation still verifies against
  its (still-published) old key. The `kid` is what lets a verifier pick the right one. Rotation is
  safe precisely because the verifier needs no live coordination — it just reads the current JWKS.
- **Revocation.** Tokens are short-lived by design — **expiry is the primary control.** Revocation is
  the early kill switch: a `jti` on a denylist lets a verifier reject a specific token before its
  natural `exp` (mini-token's `RevocationService`).

The signing keys themselves are sensitive (the private half mints tokens). Stage 6 shows how the
family wraps them at rest under mini-kms so no plaintext key touches disk.

---

## Now read it

- **The signed token (read this whole file — it's the keystone artifact):**
  `libs/mini-token` → `token/Jws` (`sign` / `split` / `verifySignature` — note the signing input is
  the base64url *text*).
- **Keys & publication:** `crypto/Ed25519Keys` (JDK-only Ed25519; the raw-32-byte `x`), `jwks/Jwk` +
  `JwkSet` (the published public set).
- **Offline verification:** `service/TokenVerifier#verify` (the ordered checks above; note the
  `alg` pin) and `token/JwsClaimsVerifier` (the OIDC-friendly variant that accepts array `aud`).
- **Lifecycle:** `service/SigningKeyService` (rotation, retired-key retention),
  `service/RevocationService` (the denylist).

Now do the lab — [`02-build-and-verify-a-token-by-hand.md`](../tutorials/02-build-and-verify-a-token-by-hand.md):
issue a real token, decode it, verify the signature against the live JWKS yourself, then **flip one
byte and watch it fail.** Then continue to stage 3,
[`oauth-and-oidc-flows.md`](oauth-and-oidc-flows.md).
