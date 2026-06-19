package com.codeheadsystems.miniidp.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * mini-idp's discovery document ({@code GET /.well-known/idp-configuration}) — the client-side copy
 * of the subset a console needs.
 *
 * <p>The exercise harness reads {@link #issuer()} from here so it can verify an issued token's
 * {@code iss} claim against the IDP's own declared issuer (rather than hard-coding it). The other
 * fields are kept for completeness/display; unknown fields are ignored so the contract can grow.
 *
 * @param issuer        the {@code iss} every token from this IDP carries.
 * @param tokenEndpoint the OAuth token endpoint URL.
 * @param jwksUri       the JWKS URL.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DiscoveryDocument(
    @JsonProperty("issuer") String issuer,
    @JsonProperty("token_endpoint") String tokenEndpoint,
    @JsonProperty("jwks_uri") String jwksUri) {
}
