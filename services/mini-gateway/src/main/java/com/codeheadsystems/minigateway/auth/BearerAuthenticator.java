package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import com.codeheadsystems.minitoken.token.GrantsClaim;
import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
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
 *
 * <p><b>Two token dialects.</b> The family mints two shapes of access token, and the gateway must
 * understand both. mini-oidc (humans) carries authority in a top-level space-delimited {@code scope}
 * string and an {@code admin} flag. mini-idp (machines) carries no top-level {@code scope}; its
 * authority lives in a {@code grants} claim — a control-plane flag plus per-key-group operations.
 * {@link #toUser} reads <em>both</em>: a machine token's grants are mapped through mini-token's
 * {@link GrantsClaim#toAuthorization()} and each operation surfaced as a {@code keyGroup:OPERATION}
 * scope, so a machine token can satisfy a SCOPE route written against its key-group grants (not only
 * AUTHENTICATED routes). Without this, a valid machine token would authenticate yet silently carry
 * zero authority.
 *
 * <p><b>Revocation is not consulted on this path.</b> A bearer access token is accepted until it
 * expires; the gateway holds no revocation denylist and {@link JwsClaimsVerifier} takes no
 * {@code isRevoked} hook. This is acceptable precisely because OP access tokens are short-lived —
 * the TTL is the revocation bound — and mini-oidc's revocation acts on the longer-lived refresh
 * tokens (which the gateway never sees), not on access tokens. Operators who need tighter bearer
 * revocation must shorten the access-token TTL; wiring a polled denylist into the verifier is a
 * documented future option, not current behavior.
 */
public final class BearerAuthenticator {

  /** Reused to lift the {@code grants} subtree into a {@link GrantsClaim} (thread-safe once built). */
  private static final ObjectMapper MAPPER = new ObjectMapper();

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
    boolean admin = false;

    // mini-oidc dialect: a top-level space-delimited `scope` string + an `admin` boolean.
    if (claims.has("scope")) {
      for (final String scope : claims.get("scope").asString().trim().split("\\s+")) {
        if (!scope.isBlank()) {
          scopes.add(scope);
        }
      }
    }
    if (claims.has("admin") && claims.get("admin").asBoolean()) {
      admin = true;
    }

    // mini-idp dialect: authority lives in a `grants` claim instead (control flag + per-key-group
    // operations). Map it via mini-token's GrantsClaim.toAuthorization() — this method's first
    // production caller — and surface each operation as a `keyGroup:OPERATION` scope so a SCOPE route
    // can gate on a machine token's key-group grants. A grants claim we cannot map (a typo'd
    // operation, malformed JSON) fails closed: no added scopes, no admin — never an exception out of
    // this method, so the gateway stays oracle-free and fails safe.
    if (claims.has("grants") && !claims.get("grants").isNull()) {
      try {
        final Authorization authorization =
            MAPPER.treeToValue(claims.get("grants"), GrantsClaim.class).toAuthorization();
        admin = admin || authorization.controlPlane();
        for (final Grant grant : authorization.grants()) {
          for (final KeyOperation operation : grant.operations()) {
            scopes.add(grant.keyGroup() + ":" + operation.name());
          }
        }
      } catch (final RuntimeException ignored) {
        // Fail closed: an unmappable grants claim (typo'd operation, malformed JSON) confers no
        // grant-derived authority. The mapping throws during deserialization/toAuthorization, before
        // any grant scope is added, so the oidc-dialect scopes/admin collected above stand untouched.
        // We deliberately swallow the reason — surfacing it would be an oracle.
      }
    }

    return new AuthenticatedUser(claims.get("sub").asString(), admin, scopes, "token");
  }
}
