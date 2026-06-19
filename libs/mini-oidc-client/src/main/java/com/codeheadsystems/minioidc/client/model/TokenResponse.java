package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The {@code /token} response — the result of an authorization-code exchange or a refresh.
 *
 * <p><b>Secret hygiene:</b> the access/id/refresh tokens are bearer credentials. {@link #toString()}
 * is overridden to redact them, so the record can never leak a token into a log or exception. Only
 * explicit accessors (the harness, which reports a token's kid/claims, never the token itself) read
 * them.
 *
 * @param accessToken  the access token (a compact JWS).
 * @param tokenType    the token type (always {@code Bearer}).
 * @param expiresIn    the access-token lifetime in seconds.
 * @param idToken      the OIDC id_token (a compact JWS) — present on the code grant.
 * @param refreshToken the rotating refresh token.
 * @param scope        the granted scopes (space-delimited).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") long expiresIn,
    @JsonProperty("id_token") String idToken,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("scope") String scope) {

  /** Redacts every token — the record must never print bearer material. */
  @Override
  public String toString() {
    return "TokenResponse[tokenType=" + tokenType + ", expiresIn=" + expiresIn + ", scope=" + scope
        + ", accessToken=<redacted>, idToken=<redacted>, refreshToken=<redacted>]";
  }
}
