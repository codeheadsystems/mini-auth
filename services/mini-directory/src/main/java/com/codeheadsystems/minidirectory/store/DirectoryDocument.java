package com.codeheadsystems.minidirectory.store;

import com.codeheadsystems.minidirectory.model.Account;
import com.codeheadsystems.minidirectory.model.Group;
import com.codeheadsystems.minidirectory.model.Role;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The single JSON document the directory persists (the {@code directory.json} file): all accounts,
 * groups, and roles together.
 *
 * <p>One document rather than a file per type, because the three collections reference each other
 * (accounts cite groups and roles; groups cite roles) and a single atomic write keeps those
 * cross-references mutually consistent — there is never a window where, say, accounts.json mentions
 * a role that roles.json has not yet recorded. It is written through {@link JsonStore} (atomic +
 * {@code 0600}).
 *
 * @param accounts the resolvable identities (humans + service accounts); never null.
 * @param groups   the group definitions; never null.
 * @param roles    the role definitions; never null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DirectoryDocument(List<Account> accounts, List<Group> groups, List<Role> roles) {

  /** Defensively copy each collection so the record is immutable. */
  public DirectoryDocument {
    accounts = accounts == null ? List.of() : List.copyOf(accounts);
    groups = groups == null ? List.of() : List.copyOf(groups);
    roles = roles == null ? List.of() : List.copyOf(roles);
  }

  /** @return an empty directory (first-run state). */
  public static DirectoryDocument empty() {
    return new DirectoryDocument(List.of(), List.of(), List.of());
  }
}
