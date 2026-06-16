package com.codeheadsystems.minipolicy;

/**
 * The thing being accessed — what the action is performed on.
 *
 * <p>Opaque to the engine on purpose: a resource is a mini-kms key-group id today, and can later
 * be a forward-auth route, an OIDC scope target, or a directory record, with no change to the
 * decision function. The wildcard {@link #ANY} lets a grant cover every resource.
 *
 * @param value the resource identifier; must be present.
 */
public record Resource(String value) {

  /** Wildcard resource: a grant carrying {@code ANY} permits every resource. */
  public static final Resource ANY = new Resource("*");

  /** Validate: a resource must identify something. */
  public Resource {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("resource must not be blank");
    }
  }

  /**
   * @param value the resource identifier.
   * @return the resource.
   */
  public static Resource of(final String value) {
    return new Resource(value);
  }
}
