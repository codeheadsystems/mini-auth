package com.codeheadsystems.minitoken.token;

import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The protected header of a compact JWS (RFC 7515) for a mini-idp token.
 *
 * <p>Three fields:
 * <ul>
 *   <li>{@code alg} — {@code "EdDSA"} (RFC 8037, Ed25519) by default; {@code "ES256"} (RFC 7518,
 *       ECDSA P-256) when an issuer signs with an ES256 key (see {@link SigningAlgorithm}).</li>
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

  /** The family's default signature algorithm (and the only one mini-token's verifiers accept). */
  public static final String ALG_EDDSA = "EdDSA";

  /** Build the standard EdDSA JWT header for the given signing-key id. */
  public static JwsHeader forKid(final String kid) {
    return new JwsHeader(ALG_EDDSA, "JWT", kid);
  }

  /** Build the standard JWT header for a key of the given algorithm. */
  public static JwsHeader forKid(final SigningAlgorithm algorithm, final String kid) {
    return new JwsHeader(algorithm.jwsName(), "JWT", kid);
  }
}
