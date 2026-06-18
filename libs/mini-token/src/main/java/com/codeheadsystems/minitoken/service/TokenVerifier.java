package com.codeheadsystems.minitoken.service;

import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.token.JwtClaims;
import java.security.PublicKey;
import java.time.Clock;
import java.util.function.Predicate;

/**
 * Offline verification of a mini-idp token against a published {@link JwkSet}.
 *
 * <p>This is the reference implementation of what a verifier (the future mini-kms) does with a
 * token and the JWKS — and what mini-idp's own tests use to prove a token round-trips. It needs no
 * call back to the IDP: it selects the signing key by the JWS {@code kid}, checks the Ed25519
 * signature, then validates the standard claims (issuer, audience, time window) and the revocation
 * denylist. A small clock-skew {@code leeway} is allowed on the time checks.
 *
 * <p>Verification order matters: signature first (so we never trust unsigned claim data), then the
 * registered claims. Each failure maps to a {@link FailureReason} so callers can react, but a
 * production token endpoint should surface only a single generic error to clients — never echo the
 * specific reason back (no oracle).
 *
 * <p><b>Audience scope:</b> this verifier treats {@code aud} as a single string (mini-idp tokens
 * carry one audience). A consumer that must accept array-valued audiences (e.g. some OIDC tokens)
 * should use {@link com.codeheadsystems.minitoken.token.JwsClaimsVerifier}, which handles {@code aud}
 * as a string-or-array per RFC 7519.
 */
public final class TokenVerifier {

  private final String expectedIssuer;
  private final String expectedAudience;
  private final Clock clock;
  private final long leewaySeconds;

  /**
   * @param expectedIssuer   the {@code iss} every accepted token must carry.
   * @param expectedAudience the {@code aud} every accepted token must carry (this verifier's id).
   * @param clock            the clock used for the time-window checks.
   * @param leewaySeconds    permitted clock skew on {@code nbf}/{@code exp}, in seconds.
   */
  public TokenVerifier(final String expectedIssuer, final String expectedAudience,
                       final Clock clock, final long leewaySeconds) {
    this.expectedIssuer = expectedIssuer;
    this.expectedAudience = expectedAudience;
    this.clock = clock;
    this.leewaySeconds = leewaySeconds;
  }

  /**
   * Verify a token.
   *
   * @param token     the compact JWS.
   * @param jwkSet    the published public keys.
   * @param isRevoked predicate that returns true if a given {@code jti} is revoked.
   * @return a {@link Result} describing success (with claims) or the first failure encountered.
   */
  public Result verify(final String token, final JwkSet jwkSet, final Predicate<String> isRevoked) {
    final Jws.Parts parts;
    final JwsHeader header;
    final JwtClaims claims;
    try {
      parts = Jws.split(token);
      header = Jws.parseHeader(parts);
    } catch (final RuntimeException e) {
      return Result.failure(FailureReason.BAD_FORMAT);
    }

    // Pin the algorithm two ways: we only ever verify with an Ed25519 key (selected by kid), AND we
    // reject any header that does not declare EdDSA. Never let the token's own `alg` choose the
    // verification algorithm — that is the classic JOSE alg-confusion footgun (e.g. `alg: none`).
    if (!JwsHeader.ALG_EDDSA.equals(header.algorithm())) {
      return Result.failure(FailureReason.BAD_ALGORITHM);
    }

    final PublicKey publicKey = publicKeyFor(jwkSet, header.keyId());
    if (publicKey == null) {
      return Result.failure(FailureReason.UNKNOWN_KID);
    }
    if (!Jws.verifySignature(parts, publicKey)) {
      return Result.failure(FailureReason.BAD_SIGNATURE);
    }

    // Only now that the signature is proven do we trust the payload.
    try {
      claims = Jws.parseClaims(parts);
    } catch (final RuntimeException e) {
      return Result.failure(FailureReason.BAD_FORMAT);
    }

    if (expectedIssuer != null && !expectedIssuer.equals(claims.issuer())) {
      return Result.failure(FailureReason.WRONG_ISSUER);
    }
    if (expectedAudience != null && !expectedAudience.equals(claims.audience())) {
      return Result.failure(FailureReason.WRONG_AUDIENCE);
    }

    final long now = clock.instant().getEpochSecond();
    if (now + leewaySeconds < claims.notBefore()) {
      return Result.failure(FailureReason.NOT_YET_VALID);
    }
    if (now - leewaySeconds >= claims.expiresAt()) {
      return Result.failure(FailureReason.EXPIRED);
    }
    if (isRevoked != null && isRevoked.test(claims.tokenId())) {
      return Result.failure(FailureReason.REVOKED);
    }
    return Result.success(claims);
  }

  private static PublicKey publicKeyFor(final JwkSet jwkSet, final String kid) {
    if (kid == null) {
      return null;
    }
    for (final Jwk jwk : jwkSet.keys()) {
      if (kid.equals(jwk.keyId())) {
        return jwk.toPublicKey();
      }
    }
    return null;
  }

  /** Why a token failed verification. */
  public enum FailureReason {
    /** Not a well-formed compact JWS / claims JSON. */
    BAD_FORMAT,
    /** The header's {@code alg} is not {@code EdDSA}. */
    BAD_ALGORITHM,
    /** No published key matches the token's {@code kid}. */
    UNKNOWN_KID,
    /** The Ed25519 signature did not verify. */
    BAD_SIGNATURE,
    /** {@code exp} is in the past. */
    EXPIRED,
    /** {@code nbf} is in the future. */
    NOT_YET_VALID,
    /** {@code iss} does not match the expected issuer. */
    WRONG_ISSUER,
    /** {@code aud} does not match the expected audience. */
    WRONG_AUDIENCE,
    /** The token's {@code jti} is on the revocation denylist. */
    REVOKED
  }

  /**
   * The outcome of {@link #verify}.
   *
   * @param valid   whether the token passed all checks.
   * @param claims  the verified claims on success, else null.
   * @param reason  the failure reason on failure, else null.
   */
  public record Result(boolean valid, JwtClaims claims, FailureReason reason) {

    static Result success(final JwtClaims claims) {
      return new Result(true, claims, null);
    }

    static Result failure(final FailureReason reason) {
      return new Result(false, null, reason);
    }
  }
}
