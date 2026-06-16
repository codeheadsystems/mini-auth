package com.codeheadsystems.miniidp.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * The JWT claim set mini-idp issues and that mini-kms verifies — the published token contract.
 *
 * <p>Standard registered claims (RFC 7519) plus two mini-idp-specific claims:
 * <ul>
 *   <li>{@code grants} — the authorization payload ({@link GrantsClaim}): control-plane flag and
 *       per-key-group operations. A verifier maps {@code sub} → {@code Principal.id},
 *       {@code grants.control} → {@code Principal.admin}, and {@code grants.groups} → its
 *       {@code KeyAuthorizationPolicy}.</li>
 *   <li>{@code cnf} — an OPTIONAL confirmation claim (RFC 7800) reserved for future channel
 *       binding (e.g. an mTLS certificate thumbprint {@code x5t#S256}, or a peer uid for a Unix
 *       socket). mini-idp does not populate or enforce it yet; the placeholder is here so the
 *       claim name is reserved in the published contract.</li>
 * </ul>
 *
 * <p>{@code aud} is modelled as a single string (the mini-kms audience). {@code iat}/{@code nbf}/
 * {@code exp} are NumericDate values: seconds since the Unix epoch. The record is serialized to
 * the JWS payload and parsed back during verification, so it is the single source of truth for
 * the JSON shape — {@code @JsonProperty} names below are the contract.
 *
 * @param issuer       {@code iss} — the issuer URL.
 * @param subject      {@code sub} — the clientId.
 * @param audience     {@code aud} — the intended audience (mini-kms).
 * @param issuedAt     {@code iat} — issuance time (epoch seconds).
 * @param notBefore    {@code nbf} — not-valid-before time (epoch seconds).
 * @param expiresAt    {@code exp} — expiry time (epoch seconds).
 * @param tokenId      {@code jti} — unique token id (used for revocation).
 * @param grants       {@code grants} — the authorization payload.
 * @param confirmation {@code cnf} — optional channel-binding placeholder; null when absent.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record JwtClaims(
    @JsonProperty("iss") String issuer,
    @JsonProperty("sub") String subject,
    @JsonProperty("aud") String audience,
    @JsonProperty("iat") long issuedAt,
    @JsonProperty("nbf") long notBefore,
    @JsonProperty("exp") long expiresAt,
    @JsonProperty("jti") String tokenId,
    @JsonProperty("grants") GrantsClaim grants,
    @JsonProperty("cnf") Map<String, Object> confirmation) {
}
