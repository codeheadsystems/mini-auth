package com.codeheadsystems.minioidc.model;

import java.util.List;

/**
 * A validated {@code /authorize} request parked server-side while the human logs in and consents.
 *
 * <p>The browser is redirected to the login/consent UI carrying only an opaque {@code requestId};
 * all the real request parameters (and the CSRF token guarding the login/consent POSTs) live here,
 * server-side, so they cannot be tampered with mid-flow. Once consent completes, this is exchanged
 * for a one-time {@link AuthorizationCode}.
 *
 * @param requestId            the opaque handle carried in the login/consent URLs.
 * @param clientId             the requesting client.
 * @param redirectUri          the (pre-validated) redirect URI.
 * @param responseType         the OAuth {@code response_type} (only {@code code} is supported).
 * @param scopes               the requested scopes (already split; includes {@code openid}).
 * @param state                the client's opaque {@code state} (echoed back on redirect).
 * @param nonce                the client's {@code nonce} (bound into the ID token), or null.
 * @param codeChallenge        the PKCE {@code code_challenge}.
 * @param codeChallengeMethod  the PKCE method ({@code S256}/{@code plain}).
 * @param csrfToken            the CSRF token the login/consent forms must echo back.
 * @param createdAt            creation time (epoch seconds), for expiry.
 */
public record PendingAuthorization(
    String requestId,
    String clientId,
    String redirectUri,
    String responseType,
    List<String> scopes,
    String state,
    String nonce,
    String codeChallenge,
    String codeChallengeMethod,
    String csrfToken,
    long createdAt) {

  public PendingAuthorization {
    scopes = scopes == null ? List.of() : List.copyOf(scopes);
  }
}
