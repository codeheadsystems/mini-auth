package com.codeheadsystems.minidirectory.model;

import com.codeheadsystems.minidirectory.secret.SecretHash;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A resolvable identity in the directory — a {@code HUMAN} or a {@code SERVICE_ACCOUNT}. An account
 * is exactly what a {@link com.codeheadsystems.minipolicy.Principal} is made from: its {@code id}
 * becomes the principal id (and a token {@code sub}), and its {@code admin} flag becomes the
 * principal's control/admin capability.
 *
 * <p>Its authorization is the union of three sources, combined at resolution time: the
 * {@code roles} assigned directly, the {@code grants} assigned directly, and everything inherited
 * from the groups in {@code memberOf} (each group's direct grants plus its roles' grants). See
 * {@link com.codeheadsystems.minidirectory.service.DirectoryService#resolve}.
 *
 * <p>{@code secretHash} is the Argon2id hash of the service-account secret, or null for a human (and
 * for a service account before a secret is set). It is the only secret-bearing field, and it holds
 * no recoverable secret — see {@link SecretHash}. It is persisted but never returned by the read
 * API and never logged.
 *
 * @param id          the stable identifier; becomes the mini-policy principal id / token {@code sub}.
 * @param kind        whether this is a human or a service account.
 * @param displayName an optional human-friendly label (may be null).
 * @param admin       whether the account holds the control/admin capability.
 * @param enabled     whether the account is currently active (a disabled account still resolves but
 *                    callers may refuse it; credential verification always fails when disabled).
 * @param memberOf    the ids of groups this account belongs to; never null.
 * @param roles       the ids of roles assigned directly to this account; never null.
 * @param grants      grants assigned directly to this account; never null.
 * @param secretHash  the Argon2id secret hash for a service account, or null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Account(
    String id,
    PrincipalKind kind,
    String displayName,
    boolean admin,
    boolean enabled,
    List<String> memberOf,
    List<String> roles,
    List<GrantSpec> grants,
    SecretHash secretHash) {

  /** Validate identity fields and defensively copy the lists. */
  public Account {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("account id must not be blank");
    }
    if (kind == null) {
      throw new IllegalArgumentException("account kind must not be null");
    }
    memberOf = memberOf == null ? List.of() : List.copyOf(memberOf);
    roles = roles == null ? List.of() : List.copyOf(roles);
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /**
   * @return a copy with replaced authorization-shaping fields (the {@code PUT .../assignment} op):
   *     admin capability, group memberships, assigned roles, and direct grants. Identity and the
   *     secret hash are untouched.
   */
  public Account withAssignment(final boolean newAdmin, final List<String> newMemberOf,
                                final List<String> newRoles, final List<GrantSpec> newGrants) {
    return new Account(id, kind, displayName, newAdmin, enabled, newMemberOf, newRoles, newGrants,
        secretHash);
  }

  /** @return a copy with a replaced enabled flag. */
  public Account withEnabled(final boolean newEnabled) {
    return new Account(id, kind, displayName, admin, newEnabled, memberOf, roles, grants, secretHash);
  }

  /** @return a copy with a replaced secret hash (service-account credential set/rotate). */
  public Account withSecretHash(final SecretHash newSecretHash) {
    return new Account(id, kind, displayName, admin, enabled, memberOf, roles, grants, newSecretHash);
  }
}
