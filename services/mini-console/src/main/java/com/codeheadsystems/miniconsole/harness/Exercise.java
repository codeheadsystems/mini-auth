package com.codeheadsystems.miniconsole.harness;

/**
 * An end-to-end exercise the console can run to smoke-test the family — drive a real flow across one
 * or more services and verify the result, the way a real client would.
 *
 * <p>This interface carries only the exercise's <b>metadata</b> (id, title, description) so the
 * Harness page can list and describe the available flows. Running a flow is flow-specific — each
 * concrete exercise exposes its own {@code run(...)} taking exactly the clients and operator-supplied
 * inputs it needs — because the inputs differ per flow (the m2m flow needs a client id + secret; a
 * future cert flow needs none). The console handler dispatches by {@link #id()} to the concrete flow.
 *
 * <p>The engine is deliberately I/O-free at the package level: a flow receives already-built clients
 * and returns an {@link ExerciseResult}, so it is unit-testable against fakes with no sockets.
 */
public interface Exercise {

  /** @return the stable id used in the route ({@code /harness/{id}/run}) and the result. */
  String id();

  /** @return the human title shown on the Harness page. */
  String title();

  /** @return a one-sentence description of what the flow proves. */
  String description();
}
