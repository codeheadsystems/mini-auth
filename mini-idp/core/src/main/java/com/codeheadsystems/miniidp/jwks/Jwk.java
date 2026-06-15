package com.codeheadsystems.miniidp.jwks;

import com.codeheadsystems.miniidp.crypto.Ed25519Keys;
import com.codeheadsystems.miniidp.token.Base64Url;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.PublicKey;

/**
 * A single public signing key in JWK form (RFC 7517 / RFC 8037), describing an Ed25519 key.
 *
 * <p>For Ed25519 the JWK is an "OKP" (Octet Key Pair) key: {@code kty=OKP}, {@code crv=Ed25519},
 * and {@code x} = the base64url of the raw 32-byte public key. We also publish {@code use=sig},
 * {@code alg=EdDSA}, and a {@code kid} so a verifier can select the right key during rotation.
 *
 * <p>This carries only public material — it is safe to serve unauthenticated at the JWKS endpoint.
 *
 * @param keyType   {@code kty}, always {@code "OKP"} for Ed25519.
 * @param curve     {@code crv}, always {@code "Ed25519"}.
 * @param publicKey {@code x}, the raw public key (base64url, unpadded).
 * @param use       {@code use}, always {@code "sig"} (signature verification).
 * @param algorithm {@code alg}, always {@code "EdDSA"}.
 * @param keyId     {@code kid}, the key identifier echoed in each token's JWS header.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record Jwk(
    @JsonProperty("kty") String keyType,
    @JsonProperty("crv") String curve,
    @JsonProperty("x") String publicKey,
    @JsonProperty("use") String use,
    @JsonProperty("alg") String algorithm,
    @JsonProperty("kid") String keyId) {

  /** Build the JWK for an Ed25519 public key under the given kid. */
  public static Jwk forEd25519(final String kid, final PublicKey publicKey) {
    final String x = Base64Url.encode(Ed25519Keys.rawPublicKey(publicKey));
    return new Jwk("OKP", "Ed25519", x, "sig", "EdDSA", kid);
  }

  /** Reconstruct the JDK public key from this JWK's raw {@code x} bytes (used by verifiers/tests). */
  public PublicKey toPublicKey() {
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
