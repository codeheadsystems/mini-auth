package com.codeheadsystems.miniidp.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The OAuth 2.0 token response from mini-idp's {@code POST /oauth/token} (client_credentials grant) —
 * the client-side copy of the JSON body mini-idp returns.
 *
 * <p>The {@code accessToken} is a compact JWS (a bearer token). It is sensitive in the sense that it
 * grants access, so a caller holds it only as long as needed and never logs it — but it is NOT a
 * long-lived secret like a client secret, and the exercise harness verifies it offline and then
 * discards it.
 *
 * @param accessToken the signed JWT (compact JWS).
 * @param tokenType   the token type, always {@code Bearer}.
 * @param expiresIn   the token lifetime in seconds.
 * @param scope       the space-delimited granted scope string.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") long expiresIn,
    @JsonProperty("scope") String scope) {
}
