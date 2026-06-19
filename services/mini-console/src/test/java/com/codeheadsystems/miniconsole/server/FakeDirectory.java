package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.HealthStatus;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.PrincipalKind;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import java.util.List;

/**
 * A canned, in-memory {@link MiniDirectoryClient} for console tests — no real directory is booted.
 * Reads return a fixed alice-in-billing fixture; mutations <b>capture</b> their argument (so a test
 * can assert the handler called the client correctly) and return a canned result. Set
 * {@link #failMutations} to make every mutation throw {@link ClientException}, exercising the
 * console's no-oracle collapse.
 */
final class FakeDirectory implements MiniDirectoryClient {

  /** A canned one-time secret the create-result banner renders (a fixed test value, not real). */
  static final String SERVICE_ACCOUNT_SECRET = "one-time-secret-value";

  /** When true, every mutation throws — used to prove the console degrades without an oracle. */
  boolean failMutations;

  NewHuman createdHuman;
  NewServiceAccount createdServiceAccount;
  String assignedId;
  Assignment assignment;
  String deletedAccountId;
  String deletedGroupId;
  String deletedRoleId;
  NewGroup createdGroup;
  NewRole createdRole;

  private final Account alice = new Account("alice", PrincipalKind.HUMAN, "Alice", false, true,
      List.of("billing-team"), List.of(), List.of());

  @Override
  public List<Account> listAccounts() {
    return List.of(alice);
  }

  @Override
  public Account getAccount(final String id) {
    return alice;
  }

  @Override
  public List<Group> listGroups() {
    return List.of(new Group("billing-team", "billing", List.of("billing-reader"), List.of()));
  }

  @Override
  public List<Role> listRoles() {
    return List.of(new Role("billing-reader", "read billing",
        List.of(new GrantSpec("DECRYPT", "billing"))));
  }

  @Override
  public Resolution resolve(final String id) {
    return new Resolution("alice", false, List.of(new GrantSpec("DECRYPT", "billing")));
  }

  @Override
  public HealthStatus health() {
    return new HealthStatus("ok");
  }

  @Override
  public Account createHuman(final NewHuman request) {
    guard();
    createdHuman = request;
    return new Account(request.id(), PrincipalKind.HUMAN, request.displayName(), request.admin(),
        true, request.memberOf(), request.roles(), request.grants());
  }

  @Override
  public ServiceAccountCreated createServiceAccount(final NewServiceAccount request) {
    guard();
    createdServiceAccount = request;
    final Account created = new Account("svc-generated", PrincipalKind.SERVICE_ACCOUNT,
        request.displayName(), request.admin(), true, request.memberOf(), request.roles(), request.grants());
    return new ServiceAccountCreated("svc-generated", SERVICE_ACCOUNT_SECRET, request.displayName(), created);
  }

  @Override
  public Account updateAssignment(final String id, final Assignment request) {
    guard();
    assignedId = id;
    assignment = request;
    return new Account(id, PrincipalKind.HUMAN, null, request.admin(), request.enabled(),
        request.memberOf(), request.roles(), request.grants());
  }

  @Override
  public void deleteAccount(final String id) {
    guard();
    deletedAccountId = id;
  }

  @Override
  public Group createGroup(final NewGroup request) {
    guard();
    createdGroup = request;
    return new Group(request.id(), request.description(), request.roles(), request.grants());
  }

  @Override
  public void deleteGroup(final String id) {
    guard();
    deletedGroupId = id;
  }

  @Override
  public Role createRole(final NewRole request) {
    guard();
    createdRole = request;
    return new Role(request.id(), request.description(), request.grants());
  }

  @Override
  public void deleteRole(final String id) {
    guard();
    deletedRoleId = id;
  }

  private void guard() {
    if (failMutations) {
      throw new ClientException("mutation failed");
    }
  }
}
