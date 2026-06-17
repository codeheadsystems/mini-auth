package com.codeheadsystems.minidirectory.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A named collection that accounts join to inherit authorization. A group bundles a set of
 * {@link Role}s (by id) plus any direct grants, and every account that is a member of the group
 * inherits all of them during {@link
 * com.codeheadsystems.minidirectory.service.DirectoryService#resolve resolution}.
 *
 * <p>Membership is recorded on the account ({@code Account.memberOf}), not here, so a group is just
 * the reusable grant bundle. A group references roles but not other groups, so resolution stays a
 * flat, acyclic expansion: account → groups → roles → grants, and account → roles → grants.
 *
 * @param id          the stable group id (e.g. {@code "finance"}); must be present.
 * @param description an optional human-readable description (may be null).
 * @param roles       role ids this group confers on its members; never null (empty allowed).
 * @param grants      direct grants this group confers on its members; never null (empty allowed).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Group(String id, String description, List<String> roles, List<GrantSpec> grants) {

  /** Validate the id and defensively copy the lists. */
  public Group {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("group id must not be blank");
    }
    roles = roles == null ? List.of() : List.copyOf(roles);
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /** @return a copy with replaced description, roles, and grants (used by the update endpoint). */
  public Group with(final String newDescription, final List<String> newRoles,
                    final List<GrantSpec> newGrants) {
    return new Group(id, newDescription, newRoles, newGrants);
  }
}
