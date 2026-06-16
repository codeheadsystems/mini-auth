package com.codeheadsystems.minitoken;

/**
 * Identifies one version of a token-signing key.
 *
 * <p>This is a pure value type — the {@code kid} that travels in a JWS header and labels a JWK
 * in the published JWKS, plus the JWS {@code alg} the key signs with. It carries no key material
 * and performs no crypto; it is the stable handle the rest of the token plane (rotation,
 * revocation, JWKS publication) is keyed on.
 *
 * <p>In mini-idp the equivalent identifier is the {@code kid} on {@code SigningKeyRecord} /
 * {@code Jwk}. When that machinery is extracted into this module, this type becomes the shared
 * key handle for both mini-idp and mini-oidc.
 *
 * @param kid a stable, opaque key identifier (matches the JWS header {@code kid} and JWK {@code kid}).
 * @param algorithm the JWS algorithm name this key signs with (e.g. {@code "EdDSA"}).
 */
public record SigningKeyId(String kid, String algorithm) {

  /** The family's default signature algorithm, matching mini-idp's Ed25519 issuance. */
  public static final String DEFAULT_ALGORITHM = "EdDSA";

  /** Validate: a key id must be present and an algorithm must be named. */
  public SigningKeyId {
    if (kid == null || kid.isBlank()) {
      throw new IllegalArgumentException("kid must not be blank");
    }
    if (algorithm == null || algorithm.isBlank()) {
      throw new IllegalArgumentException("algorithm must not be blank");
    }
  }

  /** @return a {@link SigningKeyId} for {@code kid} using the family default ({@code EdDSA}). */
  public static SigningKeyId ofEdDsa(final String kid) {
    return new SigningKeyId(kid, DEFAULT_ALGORITHM);
  }
}
