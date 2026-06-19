package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.flows.CertLifecycleFlow;
import com.codeheadsystems.miniconsole.harness.flows.KeyRotationFlow;

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
   * @param registry     the registered exercises.
   * @param idpAvailable whether a mini-idp client is wired (gates the idp flows).
   * @param caAvailable  whether a mini-ca client is wired (gates the certificate flow).
   * @param csrf         the CSRF token for the run form(s) and the nav (escaped here).
   * @return a complete HTML document.
   */
  public static String list(final ExerciseRegistry registry, final boolean idpAvailable,
                            final boolean caAvailable, final String csrf) {
    final StringBuilder body = new StringBuilder();
    body.append("<p class=\"muted\">Run an end-to-end flow against the wired services and verify the "
        + "result. Credentials you enter are used for the single run and never stored.</p>");
    for (final Exercise exercise : registry.all()) {
      body.append("<section style=\"margin-top:1.5rem\"><h2 style=\"font-size:1.1rem\">")
          .append(Layout.escape(exercise.title())).append("</h2><p class=\"muted\">")
          .append(Layout.escape(exercise.description())).append("</p>");
      final boolean isCert = CertLifecycleFlow.ID.equals(exercise.id());
      if (KeyRotationFlow.ID.equals(exercise.id())) {
        body.append("<p class=\"warn\">This exercise rotates a real mini-idp signing key.</p>");
      } else if (isCert) {
        body.append("<p class=\"warn\">This exercise issues and revokes real certificates.</p>");
      }
      if (isCert) {
        body.append(caAvailable ? noInputRunForm(exercise.id(), csrf) : requires("--ca-url"));
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
    final boolean passed = result.status() == ExerciseResult.Status.PASS;
    final StringBuilder body = new StringBuilder();
    body.append("<p><strong class=\"").append(passed ? "" : "warn").append("\">")
        .append(passed ? "PASS" : "FAIL").append("</strong> — ")
        .append(Layout.escape(result.title())).append("</p>");
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

  /** The page shown when no harness backend (mini-idp or mini-ca) is configured. */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">No services are configured for the harness. Set "
        + "<code>--idp-url</code> (for the token flows) and/or <code>--ca-url</code> (for the "
        + "certificate flow) to enable exercises.</p>";
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

  /** A note shown in place of a run form when the exercise's backend is not wired. */
  private static String requires(final String flag) {
    return "<p class=\"muted\">Requires <code>" + Layout.escape(flag) + "</code>.</p>";
  }
}
