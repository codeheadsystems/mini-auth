package com.codeheadsystems.minioidc.model;

import java.util.List;

/**
 * A one-time authorization code minted after a human authenticates and consents, exchanged at
 * {@code /token} for the ID + access (+ refresh) tokens.
 *
 * <p>It binds together everything the token endpoint must re-check: the client and redirect URI it
 * was issued to, the authenticated subject, the granted scopes, the OIDC {@code nonce}, and the
 * PKCE {@code code_challenge}. A code is single-use and short-lived; the service deletes it on
 * redemption and treats any later presentation as a replay.
 *
 * @param code                the opaque code value (also the store key).
 * @param clientId            the client the code was issued to.
 * @param redirectUri         the redirect URI the code was issued for (must match at {@code /token}).
 * @param subject             the authenticated principal id (the token {@code sub}).
 * @param scopes              the consented/granted scopes.
 * @param nonce               the OIDC {@code nonce} to embed in the ID token, or null.
 * @param codeChallenge       the PKCE {@code code_challenge} to verify at {@code /token}.
 * @param codeChallengeMethod the PKCE method.
 * @param authTime            when the human authenticated (epoch seconds; the ID token {@code auth_time}).
 * @param expiresAt           code expiry (epoch seconds).
 */
public record AuthorizationCode(
    String code,
    String clientId,
    String redirectUri,
    String subject,
    List<String> scopes,
    String nonce,
    String codeChallenge,
    String codeChallengeMethod,
    long authTime,
    long expiresAt) {

  public AuthorizationCode {
    scopes = scopes == null ? List.of() : List.copyOf(scopes);
  }
}
