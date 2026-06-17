package com.codeheadsystems.minidirectory.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A named bundle of grants. Assigning a role to an account (or a group) is shorthand for granting
 * every permission the role carries — "roles expand to grants" during {@link
 * com.codeheadsystems.minidirectory.service.DirectoryService#resolve resolution}.
 *
 * <p>Roles are the reusable unit of authorization: define {@code billing-operator} once as the set
 * of operations on the {@code billing} key group, then hand it to many principals instead of
 * copying grants around. A role references no other roles or groups, so role expansion is a single
 * flat step (no recursion, no cycles).
 *
 * @param id          the stable role id (e.g. {@code "billing-operator"}); must be present.
 * @param description an optional human-readable description (may be null).
 * @param grants      the permissions this role confers; never null (empty allowed).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Role(String id, String description, List<GrantSpec> grants) {

  /** Validate the id and defensively copy the grant list. */
  public Role {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("role id must not be blank");
    }
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /** @return a copy with a replaced description and grant set (used by the update endpoint). */
  public Role with(final String newDescription, final List<GrantSpec> newGrants) {
    return new Role(id, newDescription, newGrants);
  }
}
