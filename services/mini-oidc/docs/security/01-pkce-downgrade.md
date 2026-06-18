# 01 — PKCE downgrade to `plain`

**Severity:** Medium (authorization-code interception for public clients)
**Status:** ✅ Fixed (S256 is mandatory; `plain` is rejected)

**Affected code:**
- `util/Pkce.java` — `isSupportedMethod`, `verify`
- `server/OidcHandlers.java` — `authorize` (the `code_challenge_method` default), `discovery`

## What the issue is

PKCE (RFC 7636) binds an authorization code to the client instance that started
the flow: at `/authorize` the client sends a `code_challenge`, at `/token` it
sends the `code_verifier`, and the OP checks they correspond. With the **`S256`**
method the challenge is `base64url(SHA-256(verifier))`, so observing the
authorization request reveals nothing useful. With the legacy **`plain`** method
the challenge *is* the verifier in clear — anyone who can see the authorization
request (a proxy log, the browser history, a referrer header) can replay it.

mini-oidc made PKCE mandatory, but originally **accepted `plain` and even
defaulted to it** when the method was omitted:

```java
// Pkce.isSupportedMethod (before) — both methods accepted
return METHOD_S256.equals(method) || METHOD_PLAIN.equals(method);

// OidcHandlers.authorize (before) — a missing method defaulted to plain
final String method = q.getOrDefault("code_challenge_method", Pkce.METHOD_PLAIN);

// Pkce.verify (before) — any non-S256 method fell through to comparing verbatim
final String computed = METHOD_S256.equals(method) ? s256(verifier) : verifier;
```

So a client (or an attacker crafting the authorization request) could select
`plain`, and PKCE silently provided **no** protection against code interception —
the very threat it exists for. The constant-time compare was fine; the *policy*
was the hole.

## The threat it poses

For a **public client** (no client secret — a SPA or native app, authenticated
only by PKCE), `plain` collapses the defense entirely. An attacker who intercepts
the authorization code (a malicious app registered for the same redirect scheme,
a logged redirect URL, a shared device) can redeem it at `/token` by echoing the
challenge as the verifier. The code-interception attack PKCE was designed to stop
succeeds. OAuth 2.1 and the current Security BCP require `S256` for this reason.

## The fix

`S256` is now the only accepted method. `plain` is gone from the supported set,
the discovery document, and the authorize default; `verify` fails closed on
anything that is not `S256`.

### Before

```java
public static boolean verify(final String method, final String challenge, final String verifier) {
  if (challenge == null || verifier == null) {
    return false;
  }
  final String computed = METHOD_S256.equals(method) ? s256(verifier) : verifier; // plain fallthrough
  return MessageDigest.isEqual(challenge.getBytes(US_ASCII), computed.getBytes(US_ASCII));
}
```

### After

```java
// Pkce.verify — fail closed on anything but S256
if (challenge == null || verifier == null || !METHOD_S256.equals(method)) {
  return false;
}
final String computed = s256(verifier);
return MessageDigest.isEqual(challenge.getBytes(US_ASCII), computed.getBytes(US_ASCII));

// Pkce.isSupportedMethod — only S256
return METHOD_S256.equals(method);

// OidcHandlers.authorize — a missing method defaults to S256 (an explicit `plain` is rejected here)
final String method = q.getOrDefault("code_challenge_method", Pkce.METHOD_S256);

// OidcHandlers.discovery — advertise only S256
doc.put("code_challenge_methods_supported", List.of(Pkce.METHOD_S256));
```

## Why the fix works

A challenge that is always `base64url(SHA-256(verifier))` cannot be satisfied by
replaying the challenge: an interceptor sees the challenge but never the verifier,
and SHA-256 is one-way. Rejecting `plain` at `/authorize` means the weak mode is
unreachable rather than merely discouraged, and `verify` failing closed on an
unknown/missing method removes the "treat the verifier as the challenge" path
even if a code somehow carried a non-S256 method.

## Tests

`src/test/java/.../util/PkceTest.java` asserts the RFC 7636 worked example
verifies under `S256`, a wrong verifier is rejected, and — the regression for
this finding — `plain` (and a `null` method) never satisfy a challenge even when
the verifier equals the challenge verbatim, and `isSupportedMethod("plain")` is
false. `OidcFlowTest` exercises the full S256 authorization-code flow end to end.
