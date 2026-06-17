package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import tools.jackson.databind.JsonNode;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Validates a bearer access token <b>via mini-token</b>: it verifies the JWS offline against the
 * OP's JWKS (signature, then {@code iss}/{@code aud}/expiry) using {@link JwsClaimsVerifier}, then
 * reads the subject and granted scopes. No call back to the OP, and any failure (missing, malformed,
 * wrong issuer/audience, expired) collapses to empty — never an oracle.
 *
 * <p>This is the API-client path: a service calling a gated upstream presents
 * {@code Authorization: Bearer <access token>} instead of a browser SSO cookie.
 */
public final class BearerAuthenticator {

  private final JwksProvider jwks;
  private final String expectedIssuer;
  private final String expectedAudience;
  private final Clock clock;
  private final long leewaySeconds;

  public BearerAuthenticator(final JwksProvider jwks, final String expectedIssuer,
                             final String expectedAudience, final Clock clock, final long leewaySeconds) {
    this.jwks = jwks;
    this.expectedIssuer = expectedIssuer;
    this.expectedAudience = expectedAudience;
    this.clock = clock;
    this.leewaySeconds = leewaySeconds;
  }

  /**
   * @param authorizationHeader the proxied request's {@code Authorization} header (or null).
   * @return the authenticated caller, or empty if there is no valid bearer token.
   */
  public Optional<AuthenticatedUser> authenticate(final String authorizationHeader) {
    if (authorizationHeader == null
        || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
      return Optional.empty();
    }
    final String token = authorizationHeader.substring(7).trim();
    return JwsClaimsVerifier.verify(token, jwks.get(), expectedIssuer, expectedAudience, clock, leewaySeconds)
        .map(BearerAuthenticator::toUser);
  }

  private static AuthenticatedUser toUser(final JsonNode claims) {
    final List<String> scopes = new ArrayList<>();
    if (claims.has("scope")) {
      for (final String scope : claims.get("scope").asString().trim().split("\\s+")) {
        if (!scope.isBlank()) {
          scopes.add(scope);
        }
      }
    }
    final boolean admin = claims.has("admin") && claims.get("admin").asBoolean();
    return new AuthenticatedUser(claims.get("sub").asString(), admin, scopes, "token");
  }
}
