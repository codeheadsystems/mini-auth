package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.directory.DirectoryUser;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.SigningKeyService.Signer;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mints OpenID Connect ID tokens and access tokens, and republishes the JWKS — all on top of
 * mini-token's signing keys, JWS format, and rotation. mini-oidc does NOT re-implement the token
 * plane: it asks {@link SigningKeyService} for the active Ed25519 signer and uses mini-token's
 * {@link Jws#sign(JwsHeader, Map, java.security.PrivateKey)} so every token is offline-verifiable
 * against the same published JWKS as mini-idp's, with the same key rotation.
 *
 * <p>What is mini-oidc-specific is only the <em>claim sets</em>: an ID token (audience = the client,
 * carrying {@code auth_time}, optional {@code nonce}, and profile/email claims per granted scope)
 * and a scope-bearing access token (audience = the OP's userinfo/resource, carrying {@code scope}
 * and {@code azp}) — claim shapes that mini-idp's fixed token contract does not express.
 */
public final class OidcTokens {

  private final SigningKeyService signingKeys;
  private final Clock clock;
  private final String issuer;
  private final String accessAudience;
  private final Duration idTokenTtl;
  private final Duration accessTokenTtl;

  /**
   * @param signingKeys    the shared signing-key service (keys, JWKS, rotation).
   * @param clock          the clock for time claims.
   * @param issuer         the {@code iss} (this OP's issuer URL).
   * @param accessAudience the access token {@code aud} (this OP's userinfo/resource identifier).
   * @param idTokenTtl     ID token lifetime.
   * @param accessTokenTtl access token lifetime.
   */
  public OidcTokens(final SigningKeyService signingKeys, final Clock clock, final String issuer,
                    final String accessAudience, final Duration idTokenTtl, final Duration accessTokenTtl) {
    this.signingKeys = signingKeys;
    this.clock = clock;
    this.issuer = issuer;
    this.accessAudience = accessAudience;
    this.idTokenTtl = idTokenTtl;
    this.accessTokenTtl = accessTokenTtl;
  }

  /** @return the published JWK Set (active + retired-but-retained keys), straight from mini-token. */
  public JwkSet jwkSet() {
    return signingKeys.jwkSet();
  }

  /**
   * Rotate the signing key: mint a fresh Ed25519 key and make it active. The retired key stays in the
   * JWKS until every token it could have signed has expired, so in-flight ID/access tokens still
   * verify. Mirrors mini-idp's rotation — both issuers share mini-token's {@code SigningKeyService}.
   *
   * @return the new active key id.
   */
  public String rotateSigningKey() {
    return signingKeys.rotate();
  }

  /** @return the access token audience (the OP's userinfo/resource identifier). */
  public String accessAudience() {
    return accessAudience;
  }

  /**
   * Mint a scope-bearing access token for the userinfo/resource audience.
   *
   * @param subject  the authenticated principal id.
   * @param clientId the client the token is issued to ({@code azp}).
   * @param scopes   the granted scopes.
   * @return the compact JWS plus its lifetime, for the {@code /token} response.
   */
  public AccessToken mintAccessToken(final String subject, final String clientId, final List<String> scopes) {
    final long now = clock.instant().getEpochSecond();
    final long exp = now + accessTokenTtl.toSeconds();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", issuer);
    claims.put("sub", subject);
    claims.put("aud", accessAudience);
    claims.put("azp", clientId);
    claims.put("scope", String.join(" ", scopes));
    claims.put("iat", now);
    claims.put("nbf", now);
    claims.put("exp", exp);
    return new AccessToken(sign(claims), accessTokenTtl.toSeconds());
  }

  /**
   * Mint an ID token for the client, carrying authentication facts and the profile/email claims the
   * granted scopes permit.
   *
   * @param user     the resolved user (source of subject + profile claims).
   * @param clientId the audience ({@code aud}/{@code azp}).
   * @param nonce    the request {@code nonce} to echo, or null.
   * @param authTime when the human authenticated (epoch seconds).
   * @param scopes   the granted scopes (gate which profile claims appear).
   * @return the compact JWS ID token.
   */
  public String mintIdToken(final DirectoryUser user, final String clientId, final String nonce,
                            final long authTime, final List<String> scopes) {
    final long now = clock.instant().getEpochSecond();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", issuer);
    claims.put("sub", user.subject());
    claims.put("aud", clientId);
    claims.put("azp", clientId);
    claims.put("iat", now);
    claims.put("nbf", now);
    claims.put("exp", now + idTokenTtl.toSeconds());
    claims.put("auth_time", authTime);
    if (nonce != null) {
      claims.put("nonce", nonce);
    }
    // Profile/email claims are released only when their scope was granted (OIDC §5.4).
    if (scopes.contains("profile") && user.name() != null) {
      claims.put("name", user.name());
    }
    if (scopes.contains("email") && user.email() != null) {
      claims.put("email", user.email());
      claims.put("email_verified", user.emailVerified());
    }
    return sign(claims);
  }

  private String sign(final Map<String, Object> claims) {
    final Signer signer = signingKeys.currentSigner();
    return Jws.sign(JwsHeader.forKid(signer.kid()), claims, signer.privateKey());
  }

  /**
   * A minted access token and its lifetime.
   *
   * @param token     the compact JWS.
   * @param expiresIn lifetime in seconds (the {@code expires_in} field).
   */
  public record AccessToken(String token, long expiresIn) {
  }
}
