package com.codeheadsystems.miniconsole.harness;

import java.util.List;

/**
 * The outcome of running an {@link Exercise}: an overall status, the ordered steps that produced it,
 * and a one-line summary.
 *
 * <p><b>Redaction is a contract of this type.</b> Nothing here ever carries a secret — not the client
 * secret an operator supplied, not the access token a flow obtained. Steps report only non-secret
 * facts (a subject, a key id, an expiry, a verification outcome). A flow that needs to mention a
 * secret-bearing value substitutes {@code «redacted»}.
 *
 * @param exerciseId the id of the exercise that produced this result.
 * @param title      the exercise's human title.
 * @param status     the overall status (PASS only when every step passed).
 * @param steps      the ordered steps, each with its own status and a non-secret detail.
 * @param summary    a one-line, non-secret summary for the result header.
 */
public record ExerciseResult(String exerciseId, String title, Status status, List<Step> steps,
                             String summary) {

  /** Defensively copy the step list so the record is immutable. */
  public ExerciseResult {
    steps = steps == null ? List.of() : List.copyOf(steps);
  }

  /** The status of an exercise or one of its steps. */
  public enum Status {
    /** The step/exercise succeeded. */
    PASS,
    /** The step/exercise failed an assertion. */
    FAIL,
    /** The step was not run (e.g. a precondition was not met). */
    SKIP
  }

  /**
   * One step in a flow.
   *
   * @param label  what the step did (e.g. "Verify signature offline").
   * @param status the step's status.
   * @param detail a short, non-secret detail line.
   */
  public record Step(String label, Status status, String detail) {
  }

  /**
   * Assemble a result from its steps, deriving the overall status: PASS only if every step passed,
   * otherwise FAIL (a single SKIP among passes is not a failure but also not a clean PASS — here a
   * flow that wants SKIP semantics sets the summary accordingly; Slice 3's one flow never SKIPs).
   *
   * @param exercise the exercise that ran.
   * @param steps    the ordered steps.
   * @param summary  the one-line summary.
   * @return the assembled result.
   */
  public static ExerciseResult of(final Exercise exercise, final List<Step> steps,
                                  final String summary) {
    final boolean anyFail = steps.stream().anyMatch(step -> step.status() == Status.FAIL);
    return new ExerciseResult(exercise.id(), exercise.title(),
        anyFail ? Status.FAIL : Status.PASS, steps, summary);
  }

  /**
   * Assemble a result whose overall status is SKIP-aware: FAIL if any step failed, else SKIP if any
   * step was skipped (a partial run — e.g. the OIDC flow that cannot drive a headless passkey login),
   * else PASS. This keeps a flow honest: a run that could not complete its interactive steps reports
   * SKIP, never a misleading PASS.
   *
   * @param exercise the exercise that ran.
   * @param steps    the ordered steps.
   * @param summary  the one-line summary.
   * @return the assembled result.
   */
  public static ExerciseResult ofWithSkips(final Exercise exercise, final List<Step> steps,
                                           final String summary) {
    final boolean anyFail = steps.stream().anyMatch(step -> step.status() == Status.FAIL);
    final boolean anySkip = steps.stream().anyMatch(step -> step.status() == Status.SKIP);
    final Status overall = anyFail ? Status.FAIL : anySkip ? Status.SKIP : Status.PASS;
    return new ExerciseResult(exercise.id(), exercise.title(), overall, steps, summary);
  }
}
