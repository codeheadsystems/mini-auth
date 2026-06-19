package com.codeheadsystems.minioidc.client.model;

/**
 * The inputs to building an {@code /authorize} URL for the authorization-code + PKCE flow.
 *
 * <p>The {@code codeChallenge} is the S256 challenge derived from a {@code code_verifier} the caller
 * keeps secret until the token exchange (see the client's PKCE helper). {@code responseType} is
 * always {@code code} and {@code codeChallengeMethod} is always {@code S256} — set by the URL builder.
 *
 * @param clientId      the registered client id.
 * @param redirectUri   a pre-registered redirect URI.
 * @param scope         the requested scopes (space-delimited; must include {@code openid}).
 * @param state         opaque CSRF/round-trip value echoed back on the redirect.
 * @param nonce         the OIDC nonce bound into the id_token.
 * @param codeChallenge the S256 PKCE challenge.
 */
public record AuthorizeRequest(String clientId, String redirectUri, String scope, String state,
                               String nonce, String codeChallenge) {
}
