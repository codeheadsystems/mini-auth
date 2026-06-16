package com.codeheadsystems.minipolicy;

/**
 * The verb a {@link Principal} is attempting — what is being done.
 *
 * <p>Opaque to the engine on purpose: an action is a mini-kms {@code KeyOperation} name today
 * ({@code ENCRYPT}, {@code DECRYPT}, …), and can later be an HTTP method (mini-gateway
 * forward-auth), an OIDC scope verb, or a directory operation, with no change to the decision
 * function. The wildcard {@link #ANY} lets a grant cover every action on a resource.
 *
 * @param value the action name; must be present.
 */
public record Action(String value) {

  /** Wildcard action: a grant carrying {@code ANY} permits every action. */
  public static final Action ANY = new Action("*");

  /** Validate: an action must name something. */
  public Action {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("action must not be blank");
    }
  }

  /**
   * @param value the action name.
   * @return the action.
   */
  public static Action of(final String value) {
    return new Action(value);
  }
}
