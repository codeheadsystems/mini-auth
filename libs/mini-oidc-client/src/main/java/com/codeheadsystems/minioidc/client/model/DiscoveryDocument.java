package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The subset of mini-oidc's OpenID discovery document the console + harness use. Unknown fields are
 * ignored, so the OP can publish more without breaking this client.
 *
 * @param issuer                the OP's issuer identifier (what an id_token's {@code iss} must match).
 * @param authorizationEndpoint the {@code /authorize} URL.
 * @param tokenEndpoint         the {@code /token} URL.
 * @param userinfoEndpoint      the {@code /userinfo} URL.
 * @param jwksUri               the JWKS URL (for offline id_token verification).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DiscoveryDocument(
    @JsonProperty("issuer") String issuer,
    @JsonProperty("authorization_endpoint") String authorizationEndpoint,
    @JsonProperty("token_endpoint") String tokenEndpoint,
    @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
    @JsonProperty("jwks_uri") String jwksUri) {
}
