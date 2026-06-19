package com.codeheadsystems.miniconsole.harness;

import java.util.List;
import java.util.Optional;

/**
 * The catalog of available exercises, for the Harness page to list. Slice 3 registers one flow
 * (the machine-to-machine token flow); later slices add the OIDC, certificate, gateway, and
 * key-rotation flows.
 */
public final class ExerciseRegistry {

  private final List<Exercise> exercises;

  /** @param exercises the registered exercises, in display order. */
  public ExerciseRegistry(final List<Exercise> exercises) {
    this.exercises = List.copyOf(exercises);
  }

  /** @return all registered exercises, in display order. */
  public List<Exercise> all() {
    return exercises;
  }

  /**
   * @param id an exercise id.
   * @return the exercise with that id, if registered.
   */
  public Optional<Exercise> byId(final String id) {
    return exercises.stream().filter(exercise -> exercise.id().equals(id)).findFirst();
  }
}
