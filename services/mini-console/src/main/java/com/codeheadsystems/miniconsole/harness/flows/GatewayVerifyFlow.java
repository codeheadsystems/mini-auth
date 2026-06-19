package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minigateway.client.MiniGatewayClient;
import com.codeheadsystems.minigateway.client.VerifyOutcome;
import com.codeheadsystems.minigateway.client.VerifyRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * The forward-auth exercise: drive mini-gateway's {@code /verify} the way a reverse proxy would and
 * assert it makes the right decision on each branch — deny an unauthenticated caller, allow a valid
 * bearer, and forbid an authenticated caller that lacks the route's scope.
 *
 * <p>The first branch needs no credentials and always runs: an anonymous browser request to a gated
 * path must be sent to login (302) or refused (401) — never silently allowed. The other two branches
 * need an operator-supplied access token (and, for the forbidden branch, a path that token's scope
 * does not cover); when those inputs are absent the branch is honestly <b>SKIP</b>, never a misleading
 * PASS. This mirrors the OIDC flow's honesty about steps it cannot drive headlessly.
 *
 * <p><b>Secret hygiene.</b> The bearer token the operator supplies is used only for the verify calls
 * and is never placed in a step, the summary, or a log. Steps report only the non-secret decision
 * (the {@link VerifyOutcome}) and the path that was tested.
 */
public final class GatewayVerifyFlow implements Exercise {

  /** The stable exercise id (used in the route and the result). */
  public static final String ID = "gateway-verify";

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "Gateway forward-auth";
  }

  @Override
  public String description() {
    return "Call mini-gateway's /verify like a reverse proxy and assert it denies an anonymous "
        + "caller, allows a valid bearer, and forbids a caller without the route's scope.";
  }

  /**
   * Run the flow.
   *
   * @param gateway the mini-gateway client.
   * @param inputs  the operator-supplied inputs (the gated path; and, optionally, a bearer token plus
   *                a scope-gated path for the allow/forbid branches — none retained).
   * @return the result: SKIP for branches whose inputs were not supplied, else PASS/FAIL.
   */
  public ExerciseResult run(final MiniGatewayClient gateway, final Inputs inputs) {
    final List<Step> steps = new ArrayList<>();
    final String path = blankTo(inputs.path(), "/");
    final String method = blankTo(inputs.method(), "GET");

    // Branch 1 — anonymous: a gated path with no credentials must NOT be allowed. We probe as a
    // browser so a gateway with a login URL answers 302; an API-only gateway answers 401. Either
    // (anything but AUTHORIZED) is a pass.
    try {
      final VerifyOutcome anon = gateway.verify(VerifyRequest.anonymous(method, path, true));
      final boolean denied = anon == VerifyOutcome.REDIRECT_LOGIN
          || anon == VerifyOutcome.UNAUTHENTICATED;
      steps.add(new Step("Anonymous request is denied", denied ? Status.PASS : Status.FAIL,
          "verify(" + path + ") with no credentials -> " + anon
              + (denied ? "" : " (expected a redirect-to-login or 401)")));
    } catch (final ClientException e) {
      steps.add(new Step("Anonymous request is denied", Status.FAIL,
          "the gateway was unreachable or returned an unexpected status"));
      return ExerciseResult.of(this, steps, "Could not reach the gateway.");
    }

    final String bearer = blankToNull(inputs.bearerToken());
    if (bearer == null) {
      steps.add(new Step("Valid bearer is allowed", Status.SKIP,
          "no access token supplied — provide one to exercise the allow branch"));
      steps.add(new Step("Insufficient scope is forbidden", Status.SKIP,
          "no access token supplied — provide one plus a scope-gated path to exercise the forbid branch"));
      return ExerciseResult.ofWithSkips(this, steps,
          "Anonymous denial verified; supply a bearer token to exercise the allow/forbid branches.");
    }

    // Branch 2 — a valid bearer for the (authenticated) path is allowed (200).
    try {
      final VerifyOutcome allowed = gateway.verify(VerifyRequest.withBearer(method, path, bearer));
      steps.add(new Step("Valid bearer is allowed", allowed == VerifyOutcome.AUTHORIZED
          ? Status.PASS : Status.FAIL,
          "verify(" + path + ") with a bearer -> " + allowed
              + (allowed == VerifyOutcome.AUTHORIZED ? "" : " (expected AUTHORIZED)")));
    } catch (final ClientException e) {
      steps.add(new Step("Valid bearer is allowed", Status.FAIL,
          "the bearer verify call returned an unexpected status"));
    }

    // Branch 3 — the same bearer against a path its scope does not cover is forbidden (403).
    final String scopePath = blankToNull(inputs.scopePath());
    if (scopePath == null) {
      steps.add(new Step("Insufficient scope is forbidden", Status.SKIP,
          "no scope-gated path supplied — provide one to exercise the forbid branch"));
    } else {
      try {
        final VerifyOutcome forbidden = gateway.verify(VerifyRequest.withBearer(method, scopePath, bearer));
        steps.add(new Step("Insufficient scope is forbidden", forbidden == VerifyOutcome.FORBIDDEN
            ? Status.PASS : Status.FAIL,
            "verify(" + scopePath + ") with the bearer -> " + forbidden
                + (forbidden == VerifyOutcome.FORBIDDEN ? "" : " (expected FORBIDDEN)")));
      } catch (final ClientException e) {
        steps.add(new Step("Insufficient scope is forbidden", Status.FAIL,
            "the forbid-branch verify call returned an unexpected status"));
      }
    }

    return ExerciseResult.ofWithSkips(this, steps,
        "Exercised the gateway's forward-auth decision across the supplied branches.");
  }

  private static String blankTo(final String value, final String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }

  private static String blankToNull(final String value) {
    return value == null || value.isBlank() ? null : value;
  }

  /**
   * The operator-supplied inputs for a run. Only {@code path} is needed for the always-on anonymous
   * branch; {@code bearerToken} enables the allow branch and {@code scopePath} the forbid branch.
   *
   * @param method      the request method to test (blank → {@code GET}).
   * @param path        the gated path to test (blank → {@code /}).
   * @param bearerToken an access token to present (the allow/forbid branches), or blank.
   * @param scopePath   a path the token's scope does NOT cover (the forbid branch), or blank.
   */
  public record Inputs(String method, String path, String bearerToken, String scopePath) {
  }
}
