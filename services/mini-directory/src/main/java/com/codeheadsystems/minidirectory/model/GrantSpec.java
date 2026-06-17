package com.codeheadsystems.minidirectory.model;

import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Resource;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The stored / on-the-wire form of a single permission: an {@code (action, resource)} pair.
 *
 * <p>This is a thin, JSON-friendly mirror of mini-policy's {@link Grant} (whose {@link Action} and
 * {@link Resource} are themselves {@code record(String value)} wrappers — serializing those
 * directly would nest a {@code {"value": …}} object per coordinate). Keeping a flat
 * {@code {"action": "...", "resource": "..."}} shape makes the directory file and the admin API
 * readable, while {@link #toPolicyGrant()} converts to the exact type mini-policy evaluates.
 *
 * <p>The wildcard {@code "*"} maps to {@link Action#ANY} / {@link Resource#ANY} (mini-policy's
 * wildcards are simply the value {@code "*"}, so {@code Action.of("*").equals(Action.ANY)}); a grant
 * of {@code ("*", "billing")} therefore means "any action on key group {@code billing}".
 *
 * @param action   the permitted action name (a mini-kms {@code KeyOperation} today, or {@code "*"}).
 * @param resource the permitted resource id (a key-group id today, or {@code "*"}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrantSpec(String action, String resource) {

  /** Validate: both coordinates must be present (mirrors mini-policy's own validation). */
  public GrantSpec {
    if (action == null || action.isBlank()) {
      throw new IllegalArgumentException("grant action must not be blank");
    }
    if (resource == null || resource.isBlank()) {
      throw new IllegalArgumentException("grant resource must not be blank");
    }
  }

  /** @return the mini-policy {@link Grant} this spec denotes (honoring {@code "*"} wildcards). */
  public Grant toPolicyGrant() {
    return new Grant(Action.of(action), Resource.of(resource));
  }

  /** Project a mini-policy {@link Grant} back into its flat wire form. */
  public static GrantSpec from(final Grant grant) {
    return new GrantSpec(grant.action().value(), grant.resource().value());
  }
}
