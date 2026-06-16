package com.codeheadsystems.miniidp.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The protected header of a compact JWS (RFC 7515) for a mini-idp token.
 *
 * <p>Three fields:
 * <ul>
 *   <li>{@code alg} — always {@code "EdDSA"} (RFC 8037), the JOSE name for Ed25519 signatures.</li>
 *   <li>{@code typ} — always {@code "JWT"}.</li>
 *   <li>{@code kid} — the id of the signing key, so a verifier can pick the matching JWK during
 *       rotation. This is the only field that varies per key.</li>
 * </ul>
 *
 * @param algorithm {@code alg}.
 * @param type      {@code typ}.
 * @param keyId     {@code kid}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record JwsHeader(
    @JsonProperty("alg") String algorithm,
    @JsonProperty("typ") String type,
    @JsonProperty("kid") String keyId) {

  /** The only signature algorithm mini-idp uses. */
  public static final String ALG_EDDSA = "EdDSA";

  /** Build the standard JWT header for the given signing-key id. */
  public static JwsHeader forKid(final String kid) {
    return new JwsHeader(ALG_EDDSA, "JWT", kid);
  }
}
