# 02 — Route bypass via path confusion

**Severity:** High (authorization bypass / privilege escalation)
**Status:** ✅ Fixed (canonicalize then segment-match)

**Affected code:**
- `server/GatewayHandlers.java` — `verify`, `normalizePath`
- `model/RouteRule.java` — `matches`, `pathCovers`

## What the issue is

Routes are matched in order by path prefix, first match wins, deny-by-default for
anything unmatched. The match was a raw substring test against the **un-normalized**
path taken straight from `X-Forwarded-Uri`:

```java
// GatewayHandlers.verify (before) — query stripped, nothing else
final String path = pathOf(uri);

// RouteRule.matches (before) — raw substring prefix
if (!path.startsWith(pathPrefix)) {
  return false;
}
```

That has two distinct holes:

1. **Substring over-match.** A rule for `/admin` also matches `/admin-public`,
   `/administrator`, `/admin.bak` — any path that merely *starts with the string*
   `/admin`, not the path *segment* `/admin`.
2. **No canonicalization.** A protected `/admin/x` requested as `/./admin/x`,
   `//admin/x`, or `/public/%2e%2e/admin` does **not** `startsWith("/admin")`, so
   it misses the protective rule and falls through to a more permissive later rule
   (e.g. the default `AUTHENTICATED` catch-all) — while a normalizing upstream
   still resolves it to `/admin`. Classic proxy **path confusion**.

## The threat it poses

Both holes let a caller reach an upstream resource the routes meant to gate. With
the catch-all `AUTHENTICATED` default, `/public/../admin/secret` is gated as
"any logged-in user" by the gateway but served as `/admin/secret` by the
upstream — a **privilege escalation** for any authenticated caller, and a
**bypass** of a `SCOPE` rule. Deny-by-default bounds the worst case (a totally
unmatched path is still denied) but does nothing about a hostile path that
*matches the wrong rule*.

## The fix

The gateway now canonicalizes the path **before** matching, refusing anything it
cannot safely canonicalize, and rule matching is **segment-aware**.

### After

```java
// GatewayHandlers.verify — canonicalize first; refuse the un-canonicalizable
final String path = normalizePath(pathOf(uri));
if (path == null) {
  return HttpResponse.json(403, Map.of("error", "forbidden"));
}

// GatewayHandlers.normalizePath — decode ONCE (preserving a literal '+'), collapse // . ..,
// refuse traversal-above-root / NUL. Decoding once (never twice) means an upstream that also
// normalizes once sees the same path we matched.
decoded = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8);
... split on '/', drop "" and ".", pop on "..", return null if ".." underflows or a NUL appears ...

// RouteRule.pathCovers — segment-aware: "/admin" covers "/admin" and "/admin/x", NOT "/admin-public"
if ("/".equals(pathPrefix)) { return true; }              // catch-all
final String prefix = pathPrefix.endsWith("/") ? pathPrefix.substring(0, pathPrefix.length() - 1) : pathPrefix;
return path.equals(prefix) || path.startsWith(prefix + "/");
```

## Why the fix works

- **Decode-once + collapse** means `/public/%2e%2e/admin` becomes `/admin` *at the
  gateway*, so it now matches the `/admin` rule instead of slipping past it — and
  because we decode exactly once (double-decoding is its own vulnerability), an
  upstream that normalizes once sees the identical path. Traversal that would
  escape the root, an embedded NUL, or an undecodable escape return `null` and are
  refused outright (403) rather than matched against any rule.
- **Segment-aware matching** means a prefix only matches at a `/` boundary or on
  exact equality, so `/admin` can never silently widen to cover `/admin-public`.

Together they remove both the over-match and the path-confusion fall-through, so a
caller can no longer steer a request into a more permissive rule than the one its
real (canonical) path belongs to.

## Tests

`server/GatewayPathTest.java` covers `normalizePath`: `.`/`//`/`..` collapse,
trailing-slash, the encoded-traversal case (`/public/%2e%2e/admin → /admin`,
`/admin%2Fx → /admin/x`), and the refusals (traversal above root, NUL).
`service/RoutePolicyTest.java` (`prefixMatchIsSegmentAwareNotSubstring`) asserts
`/admin-public` is **not** caught by the `/admin` SCOPE rule (it falls to the
catch-all) while the real `/admin` and `/admin/x` still defer to it.
