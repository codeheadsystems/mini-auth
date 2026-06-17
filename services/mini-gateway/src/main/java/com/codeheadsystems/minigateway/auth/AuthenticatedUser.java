package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minipolicy.Principal;
import java.util.List;

/**
 * The caller behind a proxied request, once validated — the input to a per-route policy decision and
 * the source of the identity headers handed to the upstream on allow.
 *
 * @param subject the authenticated principal id (a token {@code sub} / SSO session subject).
 * @param admin   whether the caller holds the control/admin capability.
 * @param scopes  the granted scopes (from a bearer token; empty for an SSO session).
 * @param source  how the caller was authenticated — {@code "session"} or {@code "token"}.
 */
public record AuthenticatedUser(String subject, boolean admin, List<String> scopes, String source) {

  public AuthenticatedUser {
    scopes = scopes == null ? List.of() : List.copyOf(scopes);
  }

  /** @return the mini-policy principal this caller resolves to. */
  public Principal principal() {
    return new Principal(subject, admin);
  }
}
