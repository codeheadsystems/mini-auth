package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
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
   * The Harness landing page: each registered exercise with its description and a run form taking a
   * client id + secret. The signing-key rotation flow additionally carries a warning that it mutates
   * mini-idp state.
   *
   * @param registry the registered exercises.
   * @param csrf     the CSRF token for the run form(s) and the nav (escaped here).
   * @return a complete HTML document.
   */
  public static String list(final ExerciseRegistry registry, final String csrf) {
    final StringBuilder body = new StringBuilder();
    body.append("<p class=\"muted\">Run an end-to-end flow against the wired services and verify the "
        + "result. Credentials you enter are used for the single run and never stored.</p>");
    for (final Exercise exercise : registry.all()) {
      body.append("<section style=\"margin-top:1.5rem\"><h2 style=\"font-size:1.1rem\">")
          .append(Layout.escape(exercise.title())).append("</h2><p class=\"muted\">")
          .append(Layout.escape(exercise.description())).append("</p>");
      if (KeyRotationFlow.ID.equals(exercise.id())) {
        body.append("<p class=\"warn\">This exercise rotates a real mini-idp signing key.</p>");
      }
      body.append(runForm(exercise.id(), csrf));
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

  /** The page shown when no mini-idp is configured (the m2m flow has nothing to call). */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">No mini-idp is configured, so the machine-to-machine "
        + "token exercise cannot run. Set <code>--idp-url</code> (and an IDP token) to enable it.</p>";
    return Layout.page("Harness", Layout.authenticatedNav(csrf), body);
  }

  /** A run form for one exercise: a client id and a (password) secret, plus the CSRF token. */
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
}
