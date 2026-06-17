package com.codeheadsystems.minigateway.model;

/**
 * How a {@link RouteRule} gates its paths.
 *
 * <ul>
 *   <li>{@link #PUBLIC} — no authentication required; the request is always allowed through.</li>
 *   <li>{@link #AUTHENTICATED} — any valid caller (an SSO session or a verified bearer token)
 *       is allowed; an unauthenticated caller is denied.</li>
 *   <li>{@link #SCOPE} — a valid caller is allowed only if mini-policy permits the rule's required
 *       scope for that principal (the principal's scopes come from its token, or it is denied).</li>
 * </ul>
 */
public enum RouteAccess {
  PUBLIC,
  AUTHENTICATED,
  SCOPE
}
