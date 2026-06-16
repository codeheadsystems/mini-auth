package com.codeheadsystems.miniidp.service;

import com.codeheadsystems.miniidp.auth.Authorization;
import com.codeheadsystems.miniidp.auth.Grant;
import com.codeheadsystems.miniidp.auth.KeyOperation;
import com.codeheadsystems.miniidp.model.ClientRecord;
import com.codeheadsystems.miniidp.service.SigningKeyService.Signer;
import com.codeheadsystems.miniidp.token.GrantsClaim;
import com.codeheadsystems.miniidp.token.Jws;
import com.codeheadsystems.miniidp.token.JwsHeader;
import com.codeheadsystems.miniidp.token.JwtClaims;
import com.codeheadsystems.miniidp.util.RandomIds;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.StringJoiner;

/**
 * Issues short-lived signed access tokens for the client-credentials grant.
 *
 * <p>Given an authenticated {@link ClientRecord}, it builds the {@link JwtClaims} (binding the
 * client's {@link Authorization} into the {@code grants} claim), stamps the standard time claims
 * from the {@link Clock}, mints a unique {@code jti}, and signs with the current
 * {@link SigningKeyService} key — the JWS header carries that key's {@code kid} for rotation.
 *
 * <p>The {@code cnf} (channel-binding) claim is intentionally left null: it is a reserved
 * placeholder for future mTLS-thumbprint / peer-uid binding and is neither populated nor enforced
 * yet.
 */
public final class TokenIssuer {

  private final SigningKeyService signingKeys;
  private final RandomIds ids;
  private final Clock clock;
  private final String issuer;
  private final String audience;
  private final Duration tokenTtl;

  /**
   * @param signingKeys the signing-key service supplying the active signer.
   * @param ids         the random {@code jti} generator.
   * @param clock       the clock for time claims.
   * @param issuer      the {@code iss} value (this IDP's issuer URL).
   * @param audience    the {@code aud} value (the mini-kms audience).
   * @param tokenTtl    the token lifetime ({@code exp - iat}).
   */
  public TokenIssuer(final SigningKeyService signingKeys, final RandomIds ids, final Clock clock,
                     final String issuer, final String audience, final Duration tokenTtl) {
    this.signingKeys = signingKeys;
    this.ids = ids;
    this.clock = clock;
    this.issuer = issuer;
    this.audience = audience;
    this.tokenTtl = tokenTtl;
  }

  /**
   * Issue a token for an authenticated client.
   *
   * @param client the authenticated client.
   * @return the serialized token plus the metadata the {@code /oauth/token} response needs.
   */
  public IssuedToken issue(final ClientRecord client) {
    final Instant now = clock.instant();
    final Instant expiry = now.plus(tokenTtl);
    final String jti = ids.newJti();
    final Authorization authorization = client.authorization();

    final JwtClaims claims = new JwtClaims(
        issuer,
        client.clientId(),
        audience,
        now.getEpochSecond(),
        now.getEpochSecond(),
        expiry.getEpochSecond(),
        jti,
        GrantsClaim.from(authorization),
        null /* cnf placeholder: not populated yet */);

    final Signer signer = signingKeys.currentSigner();
    final String compact = Jws.sign(JwsHeader.forKid(signer.kid()), claims, signer.privateKey());

    return new IssuedToken(
        compact,
        "Bearer",
        tokenTtl.toSeconds(),
        scopeOf(authorization),
        jti,
        expiry.getEpochSecond());
  }

  /**
   * Render an OAuth {@code scope} string from the authorization, so a client can see what it got
   * without decoding the token. Each data grant becomes {@code group:OPERATION} entries, and
   * control-plane authority becomes the bare scope {@code control}.
   */
  private static String scopeOf(final Authorization authorization) {
    final StringJoiner joiner = new StringJoiner(" ");
    if (authorization.controlPlane()) {
      joiner.add("control");
    }
    for (final Grant grant : authorization.grants()) {
      for (final KeyOperation op : grant.operations()) {
        joiner.add(grant.keyGroup() + ":" + op.name());
      }
    }
    return joiner.toString();
  }

  /**
   * The issued token and the metadata the token endpoint returns.
   *
   * @param accessToken the compact JWS.
   * @param tokenType   always {@code "Bearer"}.
   * @param expiresIn   lifetime in seconds.
   * @param scope       a space-delimited summary of the granted access.
   * @param jti         the token id (so the issuer can audit/revoke it).
   * @param expiresAt   absolute expiry (epoch seconds), used when recording a revocation.
   */
  public record IssuedToken(String accessToken, String tokenType, long expiresIn, String scope,
                            String jti, long expiresAt) {
  }
}
