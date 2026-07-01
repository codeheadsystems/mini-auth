package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import com.codeheadsystems.minitoken.token.GrantsClaim;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwtClaims;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

/**
 * The machine-to-machine token exercise: prove that mini-idp issues a token for a service account
 * and that the token verifies <b>offline</b> against the published JWKS — exactly what a real
 * resource server (the future mini-kms) does, with no call back to the IDP.
 *
 * <p>Steps: request a client-credentials token → fetch the JWKS → read the IDP's declared issuer →
 * verify the token's Ed25519 signature against the JWKS (and its {@code iss}/time window) using
 * mini-token's reference {@link TokenVerifier}. The signature check is the headline assertion.
 *
 * <p><b>No secrets escape.</b> The client secret the operator supplied and the access token the flow
 * obtained are NEVER placed in a step, the summary, or a log. Steps report only non-secret facts: the
 * subject, the signing key id, the expiry, a grants summary, and — on failure — the verification
 * outcome (which is a category like {@code BAD_SIGNATURE}, not a secret).
 */
public final class M2mTokenFlow implements Exercise {

  /** The stable exercise id (used in the route and the result). */
  public static final String ID = "m2m-token";

  /** Clock-skew leeway (seconds) allowed on the token's time-window checks. */
  private static final long LEEWAY_SECONDS = 5;

  private final Clock clock;

  /** @param clock the clock used for the token time-window checks (injected for testability). */
  public M2mTokenFlow(final Clock clock) {
    this.clock = clock;
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "Machine-to-machine token";
  }

  @Override
  public String description() {
    return "Issue a client-credentials token from mini-idp and verify its signature offline against "
        + "the published JWKS.";
  }

  /**
   * Run the flow.
   *
   * @param idp          the mini-idp client.
   * @param clientId     the service-account id to authenticate as.
   * @param clientSecret the service-account secret — used for the one token call, never retained or
   *                     reported.
   * @return the result (PASS only if the token verifies offline).
   */
  public ExerciseResult run(final MiniIdpClient idp, final String clientId,
                            final String clientSecret) {
    final List<Step> steps = new ArrayList<>();

    final TokenResponse token;
    try {
      token = idp.token(clientId, clientSecret);
    } catch (final ClientException e) {
      // No oracle: a wrong secret, an unknown client, and an unreachable IDP all look the same.
      steps.add(new Step("Request token", Status.FAIL,
          "the token request was refused or the IDP was unreachable"));
      return ExerciseResult.of(this, steps, "Could not obtain a token.");
    }
    if (token.accessToken() == null || token.accessToken().isBlank()) {
      steps.add(new Step("Request token", Status.FAIL, "the response carried no access token"));
      return ExerciseResult.of(this, steps, "Could not obtain a token.");
    }
    steps.add(new Step("Request token", Status.PASS,
        "received a " + token.tokenType() + " token (expires in " + token.expiresIn() + "s)"));

    final JwkSet jwks;
    try {
      jwks = idp.jwks();
    } catch (final ClientException e) {
      steps.add(new Step("Fetch JWKS", Status.FAIL, "could not fetch the published signing keys"));
      return ExerciseResult.of(this, steps, "Could not fetch the JWKS.");
    }
    steps.add(new Step("Fetch JWKS", Status.PASS,
        jwks.keys().size() + " signing key(s) published"));

    final String issuer;
    try {
      issuer = idp.discovery().issuer();
    } catch (final ClientException e) {
      steps.add(new Step("Read discovery", Status.FAIL, "could not read the IDP's issuer"));
      return ExerciseResult.of(this, steps, "Could not read the discovery document.");
    }
    steps.add(new Step("Read discovery", Status.PASS, "issuer = " + issuer));

    // The headline check: verify the Ed25519 signature against the JWKS, plus iss and the time
    // window. Audience is left unchecked (null) — the harness does not assume a particular resource
    // server's audience; the signature + issuer + expiry are the meaningful smoke-test assertions.
    final TokenVerifier verifier = new TokenVerifier(issuer, null, clock, LEEWAY_SECONDS);
    final TokenVerifier.Result result = verifier.verify(token.accessToken(), jwks, jti -> false);
    if (!result.valid()) {
      steps.add(new Step("Verify signature offline", Status.FAIL,
          "verification failed: " + result.reason()));
      return ExerciseResult.of(this, steps, "The token did NOT verify against the JWKS.");
    }
    final JwtClaims claims = result.claims();
    // NOTE: the grants summary below is illustrative, not proof of authorization. It shows the
    // authority the token CARRIES, not authority anything checked. No resource server in the family
    // consumes these grants yet — the token -> mini-kms authorization path is designed, not wired
    // (see docs/concepts/honest-seams.md #1). This step's real assertion is the offline signature
    // check above, not that any grant was enforced.
    steps.add(new Step("Verify signature offline", Status.PASS,
        "sub=" + claims.subject() + ", kid=" + keyIdOf(token.accessToken())
            + ", exp=" + claims.expiresAt() + ", grants=" + grantsSummary(claims.grants())));

    return ExerciseResult.of(this, steps, "Token issued and verified offline against the JWKS.");
  }

  /** @return the JWS header's {@code kid} (non-secret), or {@code "?"} if it cannot be read. */
  private static String keyIdOf(final String token) {
    try {
      return Jws.parseHeader(Jws.split(token)).keyId();
    } catch (final RuntimeException e) {
      return "?";
    }
  }

  /** @return a compact, non-secret summary of the grants claim (control flag + key-group names). */
  private static String grantsSummary(final GrantsClaim grants) {
    if (grants == null) {
      return "none";
    }
    final StringJoiner groups = new StringJoiner(",", "[", "]");
    grants.groups().forEach(group -> groups.add(group.keyGroup()));
    return "control=" + grants.control() + " groups=" + groups;
  }
}
