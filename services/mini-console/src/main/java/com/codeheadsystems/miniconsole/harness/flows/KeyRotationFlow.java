package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.RotationResult;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import com.codeheadsystems.minitoken.token.Jws;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * The signing-key rotation exercise: prove that rotating mini-idp's signing key is safe for tokens
 * already in flight — the new key becomes active, but the retired key is <b>retained</b> in the JWKS
 * so a token minted before the rotation still verifies offline afterward.
 *
 * <p>Steps: mint a token (recording its signing kid) → read the published JWKS → rotate the signing
 * key → re-read the JWKS and assert (a) the new active kid is present and (b) the pre-rotation kid is
 * still present → verify the pre-rotation token offline against the post-rotation JWKS.
 *
 * <p><b>This exercise MUTATES mini-idp state</b> — it really rotates a signing key. That is harmless
 * (rotation is a routine, retention-preserving operation), but the operator should know, so the
 * Harness page labels it as state-changing.
 *
 * <p><b>No secrets escape.</b> The client secret the operator supplied and the access token the flow
 * obtained are NEVER placed in a step, the summary, or a log — only non-secret facts (key ids, an
 * expiry, a verification outcome).
 */
public final class KeyRotationFlow implements Exercise {

  /** The stable exercise id (used in the route and the result). */
  public static final String ID = "key-rotation";

  /** Clock-skew leeway (seconds) allowed on the token's time-window checks. */
  private static final long LEEWAY_SECONDS = 5;

  private final Clock clock;

  /** @param clock the clock used for the offline time-window check (injected for testability). */
  public KeyRotationFlow(final Clock clock) {
    this.clock = clock;
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "Signing-key rotation";
  }

  @Override
  public String description() {
    return "Rotate mini-idp's signing key and prove a token minted beforehand still verifies — the "
        + "retired key stays in the JWKS. NOTE: this rotates a real signing key.";
  }

  /**
   * Run the flow.
   *
   * @param idp          the mini-idp client (its admin token authorizes the rotation).
   * @param clientId     the service-account id used to mint the pre-rotation token.
   * @param clientSecret the service-account secret — used for the one token call, never retained or
   *                     reported.
   * @return the result (PASS only if the retired key is retained and the old token still verifies).
   */
  public ExerciseResult run(final MiniIdpClient idp, final String clientId,
                            final String clientSecret) {
    final List<Step> steps = new ArrayList<>();

    final TokenResponse token;
    try {
      token = idp.token(clientId, clientSecret);
    } catch (final ClientException e) {
      // No oracle: a wrong secret, an unknown client, and an unreachable IDP all look the same.
      steps.add(new Step("Mint pre-rotation token", Status.FAIL,
          "the token request was refused or the IDP was unreachable"));
      return ExerciseResult.of(this, steps, "Could not obtain a token to test rotation with.");
    }
    final String oldKid = keyIdOf(token.accessToken());
    steps.add(new Step("Mint pre-rotation token", Status.PASS, "signed by kid=" + oldKid));

    final String issuer;
    try {
      issuer = idp.discovery().issuer();
    } catch (final ClientException e) {
      steps.add(new Step("Read discovery", Status.FAIL, "could not read the IDP's issuer"));
      return ExerciseResult.of(this, steps, "Could not read the discovery document.");
    }

    final RotationResult rotation;
    try {
      rotation = idp.rotateSigningKey();
    } catch (final ClientException e) {
      // A refused admin token and an unreachable IDP look the same — no oracle.
      steps.add(new Step("Rotate signing key", Status.FAIL,
          "rotation was refused or the IDP was unreachable"));
      return ExerciseResult.of(this, steps, "Could not rotate the signing key.");
    }
    steps.add(new Step("Rotate signing key", Status.PASS, "new active kid=" + rotation.activeKid()));

    final JwkSet jwks;
    try {
      jwks = idp.jwks();
    } catch (final ClientException e) {
      steps.add(new Step("Re-read JWKS", Status.FAIL, "could not fetch the published signing keys"));
      return ExerciseResult.of(this, steps, "Could not fetch the JWKS after rotation.");
    }
    final List<String> kids = jwks.keys().stream().map(Jwk::keyId).toList();
    final boolean newPresent = kids.contains(rotation.activeKid());
    final boolean oldRetained = kids.contains(oldKid);
    steps.add(new Step("New key published", newPresent ? Status.PASS : Status.FAIL,
        "active kid " + (newPresent ? "present" : "MISSING") + " in JWKS"));
    steps.add(new Step("Retired key retained", oldRetained ? Status.PASS : Status.FAIL,
        "pre-rotation kid " + (oldRetained ? "still present" : "DROPPED") + " in JWKS"));

    // The headline: the old token must still verify offline against the post-rotation JWKS.
    final TokenVerifier verifier = new TokenVerifier(issuer, null, clock, LEEWAY_SECONDS);
    final TokenVerifier.Result result = verifier.verify(token.accessToken(), jwks, jti -> false);
    steps.add(new Step("Pre-rotation token still verifies",
        result.valid() ? Status.PASS : Status.FAIL,
        result.valid() ? "verified offline against the post-rotation JWKS"
            : "verification failed: " + result.reason()));

    final boolean ok = newPresent && oldRetained && result.valid();
    return ExerciseResult.of(this, steps, ok
        ? "Rotation kept the retired key; the pre-rotation token still verifies."
        : "Rotation did NOT preserve in-flight tokens.");
  }

  /** @return the JWS header's {@code kid} (non-secret), or {@code "?"} if it cannot be read. */
  private static String keyIdOf(final String token) {
    try {
      return Jws.parseHeader(Jws.split(token)).keyId();
    } catch (final RuntimeException e) {
      return "?";
    }
  }
}
