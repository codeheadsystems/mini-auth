# 02 — Open redirect on logout (`post_logout_redirect_uri`)

**Severity:** Medium (open redirect on the trusted OP origin)
**Status:** ✅ Fixed (post-logout URI validated against the client's registered URIs)

**Affected code:**
- `server/OidcHandlers.java` — `logout`
- `model/OidcClient.java` — `allowsRedirect`

## What the issue is

OIDC RP-Initiated Logout lets a relying party send the user to `/logout` and,
optionally, on to a `post_logout_redirect_uri` afterward. The authorization
endpoint already validates `redirect_uri` strictly — only an **exact registered
URI** is honored (`OidcClient.allowsRedirect`, `OidcHandlers.authorize:168`),
"never redirect to an unregistered URI — that is how codes get phished."

`logout` did **not** apply the same rule: it redirected to whatever the caller
supplied.

```java
// OidcHandlers.logout (before)
final String postLogout = ctx.queryParam("post_logout_redirect_uri");
final HttpResponse cleared = (postLogout != null && !postLogout.isBlank())
    ? HttpResponse.redirect(postLogout)               // arbitrary destination
    : HttpResponse.json(200, Map.of("status", "logged_out"));
```

So `GET /logout?post_logout_redirect_uri=https://evil.example` returned a 302 to
an attacker-chosen site — no session, no client, no validation required.

## The threat it poses

A classic **open redirect**, and a good phishing primitive precisely because the
302 originates from the *trusted OP origin* (`https://oidc.example/logout → …`).
An attacker sends a victim a link on the real OP, the browser bounces to a
look-alike site that asks them to "log back in," and the credentials (or a fresh
passkey enrolment) are harvested. Anti-phishing training that says "check the
domain" is defeated because the link genuinely starts on the OP.

## The fix

`post_logout_redirect_uri` is now honored only when it is a registered redirect
URI of the client named by `client_id`; anything else falls back to the plain
JSON `logged_out` response (the cookie is cleared either way).

### After

```java
// OidcHandlers.logout (after)
final String postLogout = ctx.queryParam("post_logout_redirect_uri");
final boolean allowed = postLogout != null && !postLogout.isBlank()
    && clients.get(ctx.queryParam("client_id")).map(c -> c.allowsRedirect(postLogout)).orElse(false);
final HttpResponse cleared = allowed
    ? HttpResponse.redirect(postLogout)
    : HttpResponse.json(200, Map.of("status", "logged_out"));
return cleared.header("Set-Cookie", cookies.clearSession());
```

## Why the fix works

The destination must now appear in a client's registered URI allow-list — the
same trust anchor the authorization endpoint uses — so an attacker cannot point
the OP at an arbitrary origin. An absent/unknown `client_id`, or a URI that is not
registered for it, yields no redirect at all (`orElse(false)`), so the default is
safe. `ClientService.get(null)` is null-safe, so a missing `client_id` simply
fails the check rather than throwing.

> **Educational simplification.** A full implementation keeps a *separate*
> `post_logout_redirect_uris` list per client (RFC: RP-Initiated Logout) and can
> identify the client from an `id_token_hint`. mini-oidc reuses the existing
> registered redirect URIs as the allow-list and takes `client_id` explicitly —
> enough to close the open redirect without a schema change.

## Tests

`OidcFlowTest` (`passkeyLoginYieldsVerifiableTokensRefreshesAndLogsOut`) covers
the logout path: the session is destroyed, the subject's refresh-token family is
revoked, and the cookie is cleared. The validation rule mirrors the
exact-registered-URI check already asserted for `/authorize`.
