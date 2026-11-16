package com.codeheadsystems.minitoken.jwks;

import com.codeheadsystems.minitoken.crypto.EcP256Keys;
import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.token.Base64Url;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.PublicKey;

/**
 * A single public signing key in JWK form (RFC 7517), describing an Ed25519 key (RFC 8037) or an
 * EC P-256 key (RFC 7518 §6.2) for ES256.
 *
 * <p>For Ed25519 the JWK is an "OKP" (Octet Key Pair) key: {@code kty=OKP}, {@code crv=Ed25519},
 * and {@code x} = the base64url of the raw 32-byte public key. We also publish {@code use=sig},
 * {@code alg=EdDSA}, and a {@code kid} so a verifier can select the right key during rotation.
 *
 * <p>For ES256 the JWK is an "EC" key: {@code kty=EC}, {@code crv=P-256}, and the public point as
 * {@code x} and {@code y} (each the fixed-width 32-byte big-endian coordinate, base64url), with
 * {@code alg=ES256}. {@code y} is absent for Ed25519.
 *
 * <p>This carries only public material — it is safe to serve unauthenticated at the JWKS endpoint.
 *
 * @param keyType   {@code kty}: {@code "OKP"} for Ed25519, {@code "EC"} for P-256.
 * @param curve     {@code crv}: {@code "Ed25519"} or {@code "P-256"}.
 * @param publicKey {@code x}: the raw Ed25519 public key, or the EC x coordinate (base64url, unpadded).
 * @param y         {@code y}: the EC y coordinate (base64url, unpadded); null for Ed25519.
 * @param use       {@code use}, always {@code "sig"} (signature verification).
 * @param algorithm {@code alg}: {@code "EdDSA"} or {@code "ES256"}.
 * @param keyId     {@code kid}, the key identifier echoed in each token's JWS header.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record Jwk(
    @JsonProperty("kty") String keyType,
    @JsonProperty("crv") String curve,
    @JsonProperty("x") String publicKey,
    @JsonProperty("y") String y,
    @JsonProperty("use") String use,
    @JsonProperty("alg") String algorithm,
    @JsonProperty("kid") String keyId) {

  /** Build the JWK for an Ed25519 public key under the given kid. */
  public static Jwk forEd25519(final String kid, final PublicKey publicKey) {
    final String x = Base64Url.encode(Ed25519Keys.rawPublicKey(publicKey));
    return new Jwk("OKP", "Ed25519", x, null, "sig", "EdDSA", kid);
  }

  /** Build the JWK for an EC P-256 public key (an ES256 signing key) under the given kid. */
  public static Jwk forEcP256(final String kid, final PublicKey publicKey) {
    return new Jwk("EC", "P-256", Base64Url.encode(EcP256Keys.x(publicKey)),
        Base64Url.encode(EcP256Keys.y(publicKey)), "sig", "ES256", kid);
  }

  /**
   * Reconstruct the JDK public key from this JWK (used by verifiers/tests): an EC P-256 key from
   * {@code x}/{@code y} when {@code kty=EC}, otherwise an Ed25519 key from the raw {@code x} bytes.
   */
  public PublicKey toPublicKey() {
    if ("EC".equals(keyType)) {
      return EcP256Keys.fromCoordinates(Base64Url.decode(publicKey), Base64Url.decode(y));
    }
    // Rebuild the SPKI DER from the fixed Ed25519 prefix + the raw 32-byte key, then decode it.
    final byte[] raw = Base64Url.decode(publicKey);
    return Ed25519Keys.decodePublic(java.util.Base64.getEncoder().encodeToString(spki(raw)));
  }

  // The 12-byte SubjectPublicKeyInfo prefix for an Ed25519 key (algorithm id + bit-string header).
  private static byte[] spki(final byte[] raw) {
    final byte[] prefix = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    final byte[] out = new byte[prefix.length + raw.length];
    System.arraycopy(prefix, 0, out, 0, prefix.length);
    System.arraycopy(raw, 0, out, prefix.length, raw.length);
    return out;
  }
}
