package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.flows.CertLifecycleFlow;
import com.codeheadsystems.miniconsole.harness.flows.GatewayVerifyFlow;
import com.codeheadsystems.miniconsole.harness.flows.KeyRotationFlow;
import com.codeheadsystems.miniconsole.harness.flows.OidcCodePkceFlow;
import java.util.List;

/**
 * The Harness pages: a list of end-to-end exercises the operator can run to smoke-test the family,
 * and the result of a run.
 *
 * <p>The exercise inputs (a service-account id and secret for the m2m flow) are supplied on the form
 * <b>per run</b> and are never stored in config — keeping secrets out of configuration and matching
 * how an operator actually smoke-tests. The secret field is a password input over a POST body, so it
 * never lands in a URL or an access log; the result page (rendered by {@link #result}) reports only
 * the non-secret facts the flow returned.
 */
public final class HarnessPages {

  private HarnessPages() {
  }

  /**
   * The Harness landing page: each registered exercise with its description and a run form. The idp
   * flows (m2m token, key rotation) take a client id + secret; the certificate-lifecycle flow needs no
   * input (it generates its own CSR). Each exercise's form is shown only when its backend is wired,
   * else a note pointing at the flag that wires it. The mutating flows carry an explicit warning.
   *
   * @param registry         the registered exercises.
   * @param idpAvailable     whether a mini-idp client is wired (gates the idp flows).
   * @param caAvailable      whether a mini-ca client is wired (gates the certificate flow).
   * @param oidcAvailable    whether a mini-oidc client is wired (gates the OIDC flow).
   * @param gatewayAvailable whether a mini-gateway client is wired (gates the gateway flow).
   * @param csrf             the CSRF token for the run form(s) and the nav (escaped here).
   * @return a complete HTML document.
   */
  public static String list(final ExerciseRegistry registry, final boolean idpAvailable,
                            final boolean caAvailable, final boolean oidcAvailable,
                            final boolean gatewayAvailable, final String csrf) {
    final StringBuilder body = new StringBuilder();
    body.append("<p class=\"muted\">Run an end-to-end flow against the wired services and verify the "
        + "result. Credentials you enter are used for the single run and never stored.</p>");
    // Run-all: drives every flow that needs no operator credential and summarizes the outcomes. The
    // credential-needing flows are reported SKIP — run those individually below.
    body.append("""
        <form method="post" action="/harness/run-all" style="margin:.5rem 0">
          <input type="hidden" name="csrf" value="$CSRF">
          <button type="submit">Run all (no-credential flows)</button>
        </form>
        """.replace("$CSRF", Layout.escape(csrf)));
    for (final Exercise exercise : registry.all()) {
      body.append("<section style=\"margin-top:1.5rem\"><h2 style=\"font-size:1.1rem\">")
          .append(Layout.escape(exercise.title())).append("</h2><p class=\"muted\">")
          .append(Layout.escape(exercise.description())).append("</p>");
      final boolean isCert = CertLifecycleFlow.ID.equals(exercise.id());
      final boolean isOidc = OidcCodePkceFlow.ID.equals(exercise.id());
      final boolean isGateway = GatewayVerifyFlow.ID.equals(exercise.id());
      if (KeyRotationFlow.ID.equals(exercise.id())) {
        body.append("<p class=\"warn\">This exercise rotates a real mini-idp signing key.</p>");
      } else if (isCert) {
        body.append("<p class=\"warn\">This exercise issues and revokes real certificates.</p>");
      }
      if (isCert) {
        body.append(caAvailable ? noInputRunForm(exercise.id(), csrf) : requires("--ca-url"));
      } else if (isOidc) {
        body.append(oidcAvailable ? oidcRunForm(exercise.id(), csrf) : requires("--oidc-url"));
      } else if (isGateway) {
        body.append(gatewayAvailable ? gatewayRunForm(exercise.id(), csrf) : requires("--gateway-url"));
      } else {
        body.append(idpAvailable ? runForm(exercise.id(), csrf) : requires("--idp-url"));
      }
      body.append("</section>");
    }
    return Layout.page("Harness", Layout.authenticatedNav(csrf), body.toString());
  }

  /**
   * Render the result of a run: an overall PASS/FAIL banner, the one-line summary, and the ordered
   * steps with their per-step status and (non-secret) detail.
   *
   * @param result the exercise result (already secret-free by contract).
   * @param csrf   the CSRF token for the nav and the "run again" form (escaped here).
   * @return a complete HTML document.
   */
  public static String result(final ExerciseResult result, final String csrf) {
    final StringBuilder body = new StringBuilder();
    // A SKIP overall (e.g. the OIDC flow could not drive a headless passkey login) is reported as
    // SKIP — never a misleading PASS or FAIL. Only a clean PASS is unstyled; SKIP/FAIL are warned.
    final ExerciseResult.Status overall = result.status();
    final boolean clean = overall == ExerciseResult.Status.PASS;
    body.append("<p><strong class=\"").append(clean ? "" : "warn").append("\">")
        .append(overall).append("</strong> — ").append(Layout.escape(result.title())).append("</p>");
    body.append("<p>").append(Layout.escape(result.summary())).append("</p>");
    body.append("<table><thead><tr><th>Step</th><th>Status</th><th>Detail</th></tr></thead><tbody>");
    for (final ExerciseResult.Step step : result.steps()) {
      final boolean stepOk = step.status() == ExerciseResult.Status.PASS;
      body.append("<tr><td>").append(Layout.escape(step.label())).append("</td><td class=\"")
          .append(stepOk ? "" : "warn").append("\">").append(step.status())
          .append("</td><td>").append(Layout.escape(step.detail())).append("</td></tr>");
    }
    body.append("</tbody></table>");
    body.append("<p style=\"margin-top:1rem\"><a href=\"/harness\">Run another exercise</a></p>");
    return Layout.page("Harness result", Layout.authenticatedNav(csrf), body.toString());
  }

  /**
   * Render the summary of a "run all": a one-line tally ({@code X passed, Y skipped, Z failed}) and a
   * compact row per exercise with its overall status and (non-secret) summary. The full per-step
   * detail stays on the individual-run page; this is the at-a-glance smoke-test view.
   *
   * @param results the per-exercise results (already secret-free by contract).
   * @param csrf    the CSRF token for the nav (escaped here).
   * @return a complete HTML document.
   */
  public static String summary(final List<ExerciseResult> results, final String csrf) {
    long passed = results.stream().filter(r -> r.status() == ExerciseResult.Status.PASS).count();
    long skipped = results.stream().filter(r -> r.status() == ExerciseResult.Status.SKIP).count();
    long failed = results.stream().filter(r -> r.status() == ExerciseResult.Status.FAIL).count();

    final StringBuilder body = new StringBuilder();
    body.append("<p><strong class=\"").append(failed == 0 ? "" : "warn").append("\">")
        .append(passed).append(" passed, ").append(skipped).append(" skipped, ")
        .append(failed).append(" failed").append("</strong></p>");
    body.append("<table><thead><tr><th>Exercise</th><th>Status</th><th>Summary</th></tr></thead><tbody>");
    for (final ExerciseResult result : results) {
      final boolean clean = result.status() == ExerciseResult.Status.PASS;
      body.append("<tr><td>").append(Layout.escape(result.title())).append("</td><td class=\"")
          .append(clean ? "" : "warn").append("\">").append(result.status())
          .append("</td><td>").append(Layout.escape(result.summary())).append("</td></tr>");
    }
    body.append("</tbody></table>");
    body.append("<p style=\"margin-top:1rem\"><a href=\"/harness\">Back to the Harness</a></p>");
    return Layout.page("Harness summary", Layout.authenticatedNav(csrf), body.toString());
  }

  /** The page shown when no harness backend (mini-idp, mini-ca, mini-oidc, or mini-gateway) is set. */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">No services are configured for the harness. Set "
        + "<code>--idp-url</code> (for the token flows), <code>--ca-url</code> (for the certificate "
        + "flow), <code>--oidc-url</code> (for the OIDC flow), and/or <code>--gateway-url</code> (for "
        + "the forward-auth flow) to enable exercises.</p>";
    return Layout.page("Harness", Layout.authenticatedNav(csrf), body);
  }

  /** A run form for an idp exercise: a client id and a (password) secret, plus the CSRF token. */
  private static String runForm(final String exerciseId, final String csrf) {
    return """
        <form method="post" action="/harness/$ID/run" style="margin-top:.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><label>Client id<br><input type="text" name="clientId" autocomplete="off"></label></p>
          <p><label>Client secret<br><input type="password" name="clientSecret" autocomplete="off"></label></p>
          <button type="submit">Run</button>
        </form>
        """.replace("$ID", Layout.escape(exerciseId)).replace("$CSRF", Layout.escape(csrf));
  }

  /** A run form for an exercise that needs no operator input (the certificate flow). */
  private static String noInputRunForm(final String exerciseId, final String csrf) {
    return """
        <form method="post" action="/harness/$ID/run" style="margin-top:.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <button type="submit">Run</button>
        </form>
        """.replace("$ID", Layout.escape(exerciseId)).replace("$CSRF", Layout.escape(csrf));
  }

  /**
   * The OIDC run form. The client id / redirect URI / scope are always submitted (to build the
   * authorize URL); the code + verifier + client secret are optional — supply them, after completing a
   * manual passkey login at the authorize URL, to drive the exchange + offline id_token verification.
   * Without a code the flow honestly SKIPs the interactive steps.
   */
  private static String oidcRunForm(final String exerciseId, final String csrf) {
    return """
        <form method="post" action="/harness/$ID/run" style="margin-top:.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><label>Client id<br><input type="text" name="clientId" autocomplete="off"></label></p>
          <p><label>Redirect URI<br><input type="text" name="redirectUri" autocomplete="off"></label></p>
          <p><label>Scope<br><input type="text" name="scope" value="openid profile" autocomplete="off"></label></p>
          <p class="muted">To complete the interactive login, open the authorize URL this run prints,
          sign in, then re-run with the returned code and the printed verifier:</p>
          <p><label>Authorization code (optional)<br><input type="text" name="code" autocomplete="off"></label></p>
          <p><label>PKCE code_verifier (optional)<br><input type="text" name="codeVerifier" autocomplete="off"></label></p>
          <p><label>Client secret (confidential clients, optional)<br><input type="password" name="clientSecret" autocomplete="off"></label></p>
          <button type="submit">Run</button>
        </form>
        """.replace("$ID", Layout.escape(exerciseId)).replace("$CSRF", Layout.escape(csrf));
  }

  /**
   * The gateway run form. The path is always submitted (to drive the anonymous-denial branch); the
   * bearer token + scope-gated path are optional — supply them to exercise the allow and forbid
   * branches. The bearer is a password input over a POST body, so it never lands in a URL or a log.
   */
  private static String gatewayRunForm(final String exerciseId, final String csrf) {
    return """
        <form method="post" action="/harness/$ID/run" style="margin-top:.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><label>Gated path<br><input type="text" name="path" value="/" autocomplete="off"></label></p>
          <p><label>Method<br><input type="text" name="method" value="GET" autocomplete="off"></label></p>
          <p class="muted">Supply a bearer access token to exercise the allow branch, plus a path its
          scope does NOT cover to exercise the forbid branch:</p>
          <p><label>Bearer access token (optional)<br><input type="password" name="bearerToken" autocomplete="off"></label></p>
          <p><label>Scope-gated path (optional)<br><input type="text" name="scopePath" autocomplete="off"></label></p>
          <button type="submit">Run</button>
        </form>
        """.replace("$ID", Layout.escape(exerciseId)).replace("$CSRF", Layout.escape(csrf));
  }

  /** A note shown in place of a run form when the exercise's backend is not wired. */
  private static String requires(final String flag) {
    return "<p class=\"muted\">Requires <code>" + Layout.escape(flag) + "</code>.</p>";
  }
}
