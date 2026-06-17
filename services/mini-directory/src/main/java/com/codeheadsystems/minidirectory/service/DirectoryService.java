package com.codeheadsystems.minidirectory.service;

import com.codeheadsystems.minidirectory.model.Account;
import com.codeheadsystems.minidirectory.model.GrantSpec;
import com.codeheadsystems.minidirectory.model.Group;
import com.codeheadsystems.minidirectory.model.PrincipalKind;
import com.codeheadsystems.minidirectory.model.ResolvedPrincipal;
import com.codeheadsystems.minidirectory.model.Role;
import com.codeheadsystems.minidirectory.secret.Argon2SecretHasher;
import com.codeheadsystems.minidirectory.secret.SecretHash;
import com.codeheadsystems.minidirectory.store.DirectoryDocument;
import com.codeheadsystems.minidirectory.store.JsonStore;
import com.codeheadsystems.minidirectory.util.RandomIds;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The directory: the single source of truth for identities (humans + service accounts), groups,
 * and roles, and the authority that resolves any account into a mini-policy {@link Principal} with
 * its fully-expanded grants.
 *
 * <p>State is held in memory ({@code id -> }record maps preserving insertion order) and persisted
 * to one JSON file via {@link JsonStore} on every mutation — the same in-memory-with-atomic-rewrite
 * model mini-idp's {@code ClientService} uses. All public methods are {@code synchronized}: the
 * directory is small, writes are infrequent, and a single coarse lock keeps concurrent HTTP worker
 * threads consistent.
 *
 * <p>Failure modes are expressed with plain exceptions so the service stays HTTP-free: an
 * {@link IllegalArgumentException} for bad input (blank/duplicate-free validation, a reference to a
 * role/group that does not exist) and an {@link IllegalStateException} for a create that collides
 * with an existing id. The server layer maps these to 400 / 409.
 *
 * <p>Service-account secrets are generated here, hashed immediately with Argon2id, and the
 * plaintext is returned exactly once (at creation); the directory never stores or returns the raw
 * secret again. Humans carry no secret.
 */
public final class DirectoryService {

  private final JsonStore<DirectoryDocument> store;
  private final Argon2SecretHasher hasher;
  private final RandomIds ids;
  private final Map<String, Account> accounts = new LinkedHashMap<>();
  private final Map<String, Group> groups = new LinkedHashMap<>();
  private final Map<String, Role> roles = new LinkedHashMap<>();

  /**
   * @param store  the backing JSON store (loaded on construction if it exists).
   * @param hasher the Argon2id hasher for service-account secrets.
   * @param ids    the random id/secret generator for service accounts.
   */
  public DirectoryService(final JsonStore<DirectoryDocument> store, final Argon2SecretHasher hasher,
                          final RandomIds ids) {
    this.store = store;
    this.hasher = hasher;
    this.ids = ids;
    if (store.exists()) {
      final DirectoryDocument loaded = store.load();
      loaded.roles().forEach(role -> roles.put(role.id(), role));
      loaded.groups().forEach(group -> groups.put(group.id(), group));
      loaded.accounts().forEach(account -> accounts.put(account.id(), account));
    }
  }

  // ---- Roles ---------------------------------------------------------------------------------

  /** Create a role. @throws IllegalStateException if the id already exists. */
  public synchronized Role createRole(final String id, final String description,
                                      final List<GrantSpec> grants) {
    final Role role = new Role(id, description, grants);
    if (roles.containsKey(role.id())) {
      throw new IllegalStateException("role already exists: " + role.id());
    }
    roles.put(role.id(), role);
    persist();
    return role;
  }

  /** @return all roles, in insertion order. */
  public synchronized List<Role> listRoles() {
    return new ArrayList<>(roles.values());
  }

  /** @return the role with this id, if present. */
  public synchronized Optional<Role> getRole(final String id) {
    return Optional.ofNullable(roles.get(id));
  }

  /** Replace a role's description and grants. @return the updated role, or empty if no such role. */
  public synchronized Optional<Role> updateRole(final String id, final String description,
                                                final List<GrantSpec> grants) {
    final Role existing = roles.get(id);
    if (existing == null) {
      return Optional.empty();
    }
    final Role updated = existing.with(description, grants);
    roles.put(id, updated);
    persist();
    return Optional.of(updated);
  }

  /** Delete a role. @return whether one was removed. */
  public synchronized boolean deleteRole(final String id) {
    final boolean removed = roles.remove(id) != null;
    if (removed) {
      persist();
    }
    return removed;
  }

  // ---- Groups --------------------------------------------------------------------------------

  /**
   * Create a group.
   *
   * @throws IllegalStateException    if the id already exists.
   * @throws IllegalArgumentException if it references a role that does not exist.
   */
  public synchronized Group createGroup(final String id, final String description,
                                        final List<String> roleIds, final List<GrantSpec> grants) {
    final Group group = new Group(id, description, roleIds, grants);
    if (groups.containsKey(group.id())) {
      throw new IllegalStateException("group already exists: " + group.id());
    }
    requireRolesExist(group.roles());
    groups.put(group.id(), group);
    persist();
    return group;
  }

  /** @return all groups, in insertion order. */
  public synchronized List<Group> listGroups() {
    return new ArrayList<>(groups.values());
  }

  /** @return the group with this id, if present. */
  public synchronized Optional<Group> getGroup(final String id) {
    return Optional.ofNullable(groups.get(id));
  }

  /**
   * Replace a group's description, roles, and grants.
   *
   * @return the updated group, or empty if no such group.
   * @throws IllegalArgumentException if it references a role that does not exist.
   */
  public synchronized Optional<Group> updateGroup(final String id, final String description,
                                                  final List<String> roleIds,
                                                  final List<GrantSpec> grants) {
    final Group existing = groups.get(id);
    if (existing == null) {
      return Optional.empty();
    }
    final Group updated = existing.with(description, roleIds, grants);
    requireRolesExist(updated.roles());
    groups.put(id, updated);
    persist();
    return Optional.of(updated);
  }

  /** Delete a group. @return whether one was removed. */
  public synchronized boolean deleteGroup(final String id) {
    final boolean removed = groups.remove(id) != null;
    if (removed) {
      persist();
    }
    return removed;
  }

  // ---- Accounts (humans + service accounts) --------------------------------------------------

  /**
   * Create a human with an operator-chosen id (e.g. a username). Humans hold no secret here.
   *
   * @throws IllegalStateException    if the id already exists.
   * @throws IllegalArgumentException if it references a missing group/role.
   */
  public synchronized Account createHuman(final String id, final String displayName,
                                          final boolean admin, final List<String> memberOf,
                                          final List<String> roleIds, final List<GrantSpec> grants) {
    final Account account = new Account(id, PrincipalKind.HUMAN, displayName, admin, true,
        memberOf, roleIds, grants, null);
    if (accounts.containsKey(account.id())) {
      throw new IllegalStateException("account already exists: " + account.id());
    }
    requireMembershipsExist(account.memberOf(), account.roles());
    accounts.put(account.id(), account);
    persist();
    return account;
  }

  /**
   * Create a service account with a generated id and a generated one-time secret (Argon2id-hashed
   * before storage). The plaintext secret is returned in the {@link Registration} and must be
   * captured by the caller now; it is never recoverable later.
   *
   * @throws IllegalArgumentException if it references a missing group/role.
   */
  public synchronized Registration createServiceAccount(final String displayName, final boolean admin,
                                                        final List<String> memberOf,
                                                        final List<String> roleIds,
                                                        final List<GrantSpec> grants) {
    requireMembershipsExist(
        memberOf == null ? List.of() : memberOf, roleIds == null ? List.of() : roleIds);
    String id = ids.newServiceAccountId();
    while (accounts.containsKey(id)) {
      id = ids.newServiceAccountId();
    }
    final char[] secret = ids.newSecret();
    final SecretHash secretHash = hasher.hash(secret);
    final Account account = new Account(id, PrincipalKind.SERVICE_ACCOUNT, displayName, admin, true,
        memberOf, roleIds, grants, secretHash);
    accounts.put(id, account);
    persist();
    return new Registration(account, secret);
  }

  /** @return all accounts, in insertion order. */
  public synchronized List<Account> listAccounts() {
    return new ArrayList<>(accounts.values());
  }

  /** @return the account with this id, if present. */
  public synchronized Optional<Account> getAccount(final String id) {
    return Optional.ofNullable(accounts.get(id));
  }

  /** Delete an account. @return whether one was removed. */
  public synchronized boolean deleteAccount(final String id) {
    final boolean removed = accounts.remove(id) != null;
    if (removed) {
      persist();
    }
    return removed;
  }

  /**
   * Replace an account's authorization assignment: enabled flag, admin capability, group
   * memberships, assigned roles, and direct grants. Identity (id/kind/displayName) and any stored
   * secret are untouched.
   *
   * @return the updated account, or empty if no such account.
   * @throws IllegalArgumentException if it references a missing group/role.
   */
  public synchronized Optional<Account> assign(final String id, final boolean enabled,
                                               final boolean admin, final List<String> memberOf,
                                               final List<String> roleIds,
                                               final List<GrantSpec> grants) {
    final Account existing = accounts.get(id);
    if (existing == null) {
      return Optional.empty();
    }
    final Account updated = existing
        .withAssignment(admin, memberOf, roleIds, grants)
        .withEnabled(enabled);
    requireMembershipsExist(updated.memberOf(), updated.roles());
    accounts.put(id, updated);
    persist();
    return Optional.of(updated);
  }

  /**
   * Verify a service account's secret for the client-credentials flow, with no credential oracle.
   *
   * <p>Returns the account only when it exists, is an enabled service account, and the secret
   * matches. An unknown id (or a human, or a secretless service account) still incurs a hash
   * verification against a throwaway hash, so timing does not reveal which check failed — the caller
   * surfaces a single generic error regardless.
   *
   * @param id     the presented account id.
   * @param secret the presented secret (caller should zero it afterwards).
   * @return the authenticated account, or empty on any failure.
   */
  public synchronized Optional<Account> authenticate(final String id, final char[] secret) {
    final Account account = id == null ? null : accounts.get(id);
    if (account == null || account.kind() != PrincipalKind.SERVICE_ACCOUNT
        || account.secretHash() == null) {
      // Spend comparable effort on a dummy verification so timing does not reveal existence/kind.
      hasher.verify(secret, DUMMY_HASH);
      return Optional.empty();
    }
    final boolean ok = account.enabled() && hasher.verify(secret, account.secretHash());
    return ok ? Optional.of(account) : Optional.empty();
  }

  // ---- Resolution (the reason the directory exists) ------------------------------------------

  /**
   * Resolve an account into a mini-policy {@link Principal} plus its fully-expanded grants:
   * directly-assigned grants, the grants of directly-assigned roles, and everything inherited from
   * group membership (each group's direct grants plus its roles' grants). Roles expand to grants;
   * the result is flattened and de-duplicated, preserving first-seen order.
   *
   * <p>Dangling references (a role/group id that no longer exists) are skipped rather than failing,
   * so a deleted role can never break resolution of an account that still cited it.
   *
   * @param id the account id.
   * @return the resolved principal, or empty if no such account.
   */
  public synchronized Optional<ResolvedPrincipal> resolve(final String id) {
    final Account account = accounts.get(id);
    if (account == null) {
      return Optional.empty();
    }
    final LinkedHashSet<GrantSpec> effective = new LinkedHashSet<>(account.grants());
    account.roles().forEach(roleId -> addRoleGrants(roleId, effective));
    for (final String groupId : account.memberOf()) {
      final Group group = groups.get(groupId);
      if (group != null) {
        effective.addAll(group.grants());
        group.roles().forEach(roleId -> addRoleGrants(roleId, effective));
      }
    }
    final List<Grant> policyGrants = new ArrayList<>();
    for (final GrantSpec spec : effective) {
      final Grant grant = spec.toPolicyGrant();
      if (!policyGrants.contains(grant)) {
        policyGrants.add(grant);
      }
    }
    return Optional.of(new ResolvedPrincipal(new Principal(account.id(), account.admin()), policyGrants));
  }

  private void addRoleGrants(final String roleId, final LinkedHashSet<GrantSpec> into) {
    final Role role = roles.get(roleId);
    if (role != null) {
      into.addAll(role.grants());
    }
  }

  // ---- Helpers -------------------------------------------------------------------------------

  private void requireMembershipsExist(final List<String> groupIds, final List<String> roleIds) {
    for (final String groupId : groupIds) {
      if (!groups.containsKey(groupId)) {
        throw new IllegalArgumentException("no such group: " + groupId);
      }
    }
    requireRolesExist(roleIds);
  }

  private void requireRolesExist(final List<String> roleIds) {
    for (final String roleId : roleIds) {
      if (!roles.containsKey(roleId)) {
        throw new IllegalArgumentException("no such role: " + roleId);
      }
    }
  }

  private void persist() {
    store.save(new DirectoryDocument(
        new ArrayList<>(accounts.values()),
        new ArrayList<>(groups.values()),
        new ArrayList<>(roles.values())));
  }

  /**
   * The result of creating a service account: the stored record plus the one-time plaintext secret.
   *
   * @param account the persisted account.
   * @param secret  the plaintext secret, shown to the operator exactly once; zero it after use.
   */
  public record Registration(Account account, char[] secret) {
  }

  // A fixed, well-formed hash used only to keep timing uniform for unknown/secretless lookups. Its
  // parameters are tiny on purpose; it never authenticates anything (no secret hashes to it).
  private static final SecretHash DUMMY_HASH = new SecretHash(
      SecretHash.ALGORITHM_ARGON2ID,
      "AAAAAAAAAAAAAAAAAAAAAA==",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      8, 1, 1);
}
