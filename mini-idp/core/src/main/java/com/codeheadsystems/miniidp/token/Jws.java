package com.codeheadsystems.miniidp.token;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Hand-rolled compact-serialization JWS (RFC 7515), signed with Ed25519/EdDSA.
 *
 * <p>We assemble the token by hand rather than depend on a JOSE library — the same way mini-kms
 * hand-rolls its envelope formats — because a compact JWS is genuinely simple and worth being
 * able to read end to end:
 *
 * <pre>
 *   signingInput = base64url(UTF-8(headerJson)) + "." + base64url(payloadJson)
 *   signature    = Ed25519-sign(privateKey, ASCII(signingInput))
 *   token        = signingInput + "." + base64url(signature)
 * </pre>
 *
 * <p>The bytes that are signed are the ASCII of {@code signingInput} — i.e. the base64url text,
 * NOT the raw JSON. Verification recomputes that exact byte string from the first two segments
 * and checks the Ed25519 signature over it; this is what lets a verifier validate offline with
 * only the public JWK. We never parse-then-reserialize before verifying, so a token always
 * verifies against the exact bytes it was signed over.
 */
public final class Jws {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private Jws() {
  }

  /**
   * Sign a header + claims into a compact JWS string.
   *
   * @param header     the protected header (carries {@code kid}).
   * @param claims     the claim set serialized as the payload.
   * @param privateKey the Ed25519 private key.
   * @return the compact JWS: {@code header.payload.signature}.
   */
  public static String sign(final JwsHeader header, final JwtClaims claims, final PrivateKey privateKey) {
    final String headerSegment = Base64Url.encode(toJson(header));
    final String payloadSegment = Base64Url.encode(toJson(claims));
    final String signingInput = headerSegment + "." + payloadSegment;
    final byte[] signature = ed25519Sign(privateKey, signingInput.getBytes(StandardCharsets.US_ASCII));
    return signingInput + "." + Base64Url.encode(signature);
  }

  /**
   * Split a compact JWS into its three segments without verifying anything.
   *
   * @param token the compact JWS.
   * @return the parsed segments.
   * @throws IllegalArgumentException if the token is not three dot-separated segments.
   */
  public static Parts split(final String token) {
    if (token == null) {
      throw new IllegalArgumentException("token must not be null");
    }
    final String[] segments = token.split("\\.", -1);
    if (segments.length != 3) {
      throw new IllegalArgumentException("compact JWS must have exactly three segments");
    }
    return new Parts(segments[0], segments[1], segments[2]);
  }

  /**
   * Verify a token's Ed25519 signature against a public key.
   *
   * <p>This checks ONLY the cryptographic signature over the signing input; claim validation
   * (expiry, audience, revocation) is the caller's responsibility (see {@code TokenVerifier}).
   *
   * @param parts     the split token segments.
   * @param publicKey the Ed25519 public key to verify against.
   * @return whether the signature is valid.
   */
  public static boolean verifySignature(final Parts parts, final PublicKey publicKey) {
    final String signingInput = parts.header() + "." + parts.payload();
    try {
      final Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(publicKey);
      verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return verifier.verify(Base64Url.decode(parts.signature()));
    } catch (final GeneralSecurityException e) {
      // A malformed signature/key is simply "not valid" — never an oracle for why.
      return false;
    }
  }

  /** Parse the decoded header segment into a {@link JwsHeader}. */
  public static JwsHeader parseHeader(final Parts parts) {
    return fromJson(Base64Url.decode(parts.header()), JwsHeader.class);
  }

  /** Parse the decoded payload segment into a {@link JwtClaims}. */
  public static JwtClaims parseClaims(final Parts parts) {
    return fromJson(Base64Url.decode(parts.payload()), JwtClaims.class);
  }

  private static byte[] ed25519Sign(final PrivateKey privateKey, final byte[] message) {
    try {
      final Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(privateKey);
      signer.update(message);
      return signer.sign();
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("Ed25519 signing failed", e);
    }
  }

  private static byte[] toJson(final Object value) {
    try {
      return MAPPER.writeValueAsBytes(value);
    } catch (final JacksonException e) {
      throw new IllegalStateException("failed to serialize JWS segment", e);
    }
  }

  private static <T> T fromJson(final byte[] json, final Class<T> type) {
    try {
      return MAPPER.readValue(json, type);
    } catch (final JacksonException e) {
      throw new IllegalArgumentException("malformed JWS segment", e);
    }
  }

  /**
   * The three raw (still base64url-encoded) segments of a compact JWS.
   *
   * @param header    the encoded protected header.
   * @param payload   the encoded payload.
   * @param signature the encoded signature.
   */
  public record Parts(String header, String payload, String signature) {
  }
}
