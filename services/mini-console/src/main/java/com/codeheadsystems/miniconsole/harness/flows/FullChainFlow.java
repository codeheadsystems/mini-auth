package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minigateway.client.MiniGatewayClient;
import com.codeheadsystems.minigateway.client.VerifyOutcome;
import com.codeheadsystems.minigateway.client.VerifyRequest;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * The full-chain exercise: the one runnable thing that demonstrates the headline learning goal —
 * <b>identity → token → gateway verifies → resource</b> — end to end, with no manual copy-paste in the
 * seam. Every other harness flow exercises a single hop; this one threads all three services so a
 * learner can watch a request earn its way to a protected upstream.
 *
 * <p>Steps, in order:
 * <ol>
 *   <li><b>Resolve the identity in mini-directory</b> — prove the service account exists in the source
 *       of truth and see its fully-expanded grants (the thing a policy decision is made over).</li>
 *   <li><b>Mint a client-credentials token from mini-idp</b> — exchange the service account's
 *       credentials for a short-lived, Ed25519-signed access token.</li>
 *   <li><b>Present that SAME token to mini-gateway's {@code /verify}</b> — exactly as a reverse proxy
 *       would before forwarding to a no-auth upstream. The gateway verifies the JWS <b>offline</b>
 *       against the OP's JWKS (no call back to mini-idp) and answers {@code AUTHORIZED}. That answer
 *       is the headline assertion: the resource is protected by the chain, not by the upstream.</li>
 * </ol>
 *
 * <p><b>Honest SKIP.</b> The first two steps need the operator to supply the service account's id and
 * secret; without them the whole flow is reported <b>SKIP</b>, never a misleading PASS (mirroring the
 * other credential-needing flows).
 *
 * <p><b>No secrets escape.</b> The client secret and the minted access token are used only for the
 * calls above and are NEVER placed in a step, the summary, or a log. Steps report only non-secret
 * facts: the resolved subject, the grant count, the token type/expiry, and the gateway's decision.
 */
public final class FullChainFlow implements Exercise {

  /** The stable exercise id (used in the route and the result). */
  public static final String ID = "full-chain";

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "Full chain: identity → token → gateway";
  }

  @Override
  public String description() {
    return "Resolve a service account in mini-directory, mint a client-credentials token from "
        + "mini-idp, then present that token to mini-gateway's /verify and assert it is authorized "
        + "to reach a protected resource.";
  }

  /**
   * Run the flow.
   *
   * @param directory the mini-directory client (the identity source of truth).
   * @param idp       the mini-idp client (the machine token issuer).
   * @param gateway   the mini-gateway client (the forward-auth endpoint).
   * @param inputs    the operator-supplied inputs (a service-account id + secret, and the gated path);
   *                  the secret is used for the single token call and never retained.
   * @return the result: SKIP when no credentials were supplied, else PASS only if the gateway
   *         authorizes the minted token.
   */
  public ExerciseResult run(final MiniDirectoryClient directory, final MiniIdpClient idp,
                            final MiniGatewayClient gateway, final Inputs inputs) {
    final List<Step> steps = new ArrayList<>();
    final String clientId = blankToNull(inputs.clientId());
    final String clientSecret = blankToNull(inputs.clientSecret());
    final String path = blankTo(inputs.path(), "/");

    if (clientId == null || clientSecret == null) {
      steps.add(new Step("Resolve identity (mini-directory)", Status.SKIP,
          "no service-account id + secret supplied — provide both to drive the whole chain"));
      steps.add(new Step("Mint client-credentials token (mini-idp)", Status.SKIP,
          "needs the service-account credentials above"));
      steps.add(new Step("Gateway verifies the token (mini-gateway)", Status.SKIP,
          "needs a token from the step above"));
      return ExerciseResult.ofWithSkips(this, steps,
          "Supply a service-account id + secret to drive identity → token → gateway end to end.");
    }

    // Step 1 — the identity exists in the source of truth and resolves to its effective grants.
    try {
      final Resolution resolution = directory.resolve(clientId);
      steps.add(new Step("Resolve identity (mini-directory)", Status.PASS,
          "resolved " + resolution.id() + " (admin=" + resolution.admin() + ", "
              + resolution.grants().size() + " effective grant(s))"));
    } catch (final ClientException e) {
      // No oracle: an unknown account and an unreachable directory look the same.
      steps.add(new Step("Resolve identity (mini-directory)", Status.FAIL,
          "the service account did not resolve or the directory was unreachable"));
      return ExerciseResult.of(this, steps, "The identity did not resolve in mini-directory.");
    }

    // Step 2 — mini-idp mints a client-credentials token for that identity.
    final TokenResponse token;
    try {
      token = idp.token(clientId, clientSecret);
    } catch (final ClientException e) {
      // No oracle: a wrong secret, an unknown client, and an unreachable IDP all look the same.
      steps.add(new Step("Mint client-credentials token (mini-idp)", Status.FAIL,
          "the token request was refused or the IDP was unreachable"));
      return ExerciseResult.of(this, steps, "mini-idp did not issue a token.");
    }
    if (token.accessToken() == null || token.accessToken().isBlank()) {
      steps.add(new Step("Mint client-credentials token (mini-idp)", Status.FAIL,
          "the response carried no access token"));
      return ExerciseResult.of(this, steps, "mini-idp did not issue a token.");
    }
    steps.add(new Step("Mint client-credentials token (mini-idp)", Status.PASS,
        "received a " + token.tokenType() + " token (expires in " + token.expiresIn() + "s)"));

    // Step 3 — present that SAME token to the gateway, the way a reverse proxy would. The gateway
    // verifies the JWS offline against the OP's JWKS and answers AUTHORIZED — the headline of the
    // whole chain: the resource is protected by the chain, not by the (no-auth) upstream.
    try {
      final VerifyOutcome outcome =
          gateway.verify(VerifyRequest.withBearer("GET", path, token.accessToken()));
      steps.add(new Step("Gateway verifies the token (mini-gateway)",
          outcome == VerifyOutcome.AUTHORIZED ? Status.PASS : Status.FAIL,
          "verify(" + path + ") with the minted token -> " + outcome
              + (outcome == VerifyOutcome.AUTHORIZED ? "" : " (expected AUTHORIZED)")));
    } catch (final ClientException e) {
      steps.add(new Step("Gateway verifies the token (mini-gateway)", Status.FAIL,
          "the gateway was unreachable or returned an unexpected status"));
      return ExerciseResult.of(this, steps, "The gateway did not verify the minted token.");
    }

    return ExerciseResult.of(this, steps,
        "Identity resolved, token minted, and the gateway authorized it — the chain protects the "
            + "resource end to end.");
  }

  private static String blankTo(final String value, final String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }

  private static String blankToNull(final String value) {
    return value == null || value.isBlank() ? null : value;
  }

  /**
   * The operator-supplied inputs for a run. The id + secret drive the directory resolution and the
   * token mint (the secret is never retained); {@code path} is the gated path probed at the gateway.
   *
   * @param clientId     the service-account id to resolve and authenticate as (blank → the flow SKIPs).
   * @param clientSecret the service-account secret — used for the one token call, never retained.
   * @param path         the gated path to verify the minted token against (blank → {@code /}).
   */
  public record Inputs(String clientId, String clientSecret, String path) {
  }
}
