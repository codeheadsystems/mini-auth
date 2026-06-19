package com.codeheadsystems.minidirectory.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.HealthStatus;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import java.net.URI;
import java.util.List;

/**
 * A client for mini-directory's admin + resolution API.
 *
 * <p>Slice 1 exposed the read surface; Slice 2 adds the Identities mutations a console needs
 * (create / assign / delete). Every method may throw {@link ClientException} (the no-oracle
 * collapse): a missing principal, a refused token, an id collision, and an unreachable directory are
 * indistinguishable to the caller, by design.
 *
 * <p>The admin endpoints require the directory's admin bearer token, which the caller supplies when
 * constructing the client; {@code /health} is public but the token is harmlessly sent anyway.
 */
public interface MiniDirectoryClient {

  /** @return all accounts (humans + service accounts), secret-free. */
  List<Account> listAccounts();

  /**
   * @param id the account id.
   * @return that account.
   * @throws ClientException if it does not exist or the request fails (no distinction — no oracle).
   */
  Account getAccount(String id);

  /** @return all groups. */
  List<Group> listGroups();

  /** @return all roles. */
  List<Role> listRoles();

  /**
   * @param id the principal id.
   * @return the principal resolved to its fully-expanded, de-duplicated grants.
   * @throws ClientException if it does not exist or the request fails.
   */
  Resolution resolve(String id);

  /** @return the directory's liveness status. */
  HealthStatus health();

  // ---- Mutations (Slice 2) -------------------------------------------------------------------

  /**
   * Create a human principal.
   *
   * @param request the new human's id, label, and authorization.
   * @return the created account (secret-free; humans carry no secret).
   * @throws ClientException on any failure (id collision, dangling reference, refused — no oracle).
   */
  Account createHuman(NewHuman request);

  /**
   * Create a service account; the directory generates its id and one-time secret.
   *
   * @param request the new service account's label and authorization.
   * @return the created account plus its <b>one-time</b> plaintext secret (display once, never
   *     re-fetchable). The caller must not log or persist the secret beyond showing it once.
   * @throws ClientException on any failure (no oracle).
   */
  ServiceAccountCreated createServiceAccount(NewServiceAccount request);

  /**
   * Replace an account's authorization wholesale.
   *
   * @param id      the principal id.
   * @param request the complete desired authorization (enabled/admin/memberships/roles/grants).
   * @return the updated account.
   * @throws ClientException on any failure (unknown principal, dangling reference — no oracle).
   */
  Account updateAssignment(String id, Assignment request);

  /**
   * Delete a principal (human or service account).
   *
   * @param id the principal id.
   * @throws ClientException on any failure (unknown principal, refused — no oracle).
   */
  void deleteAccount(String id);

  /**
   * Create a group.
   *
   * @param request the new group's id, label, roles, and direct grants.
   * @return the created group.
   * @throws ClientException on any failure (no oracle).
   */
  Group createGroup(NewGroup request);

  /**
   * Delete a group.
   *
   * @param id the group id.
   * @throws ClientException on any failure (no oracle).
   */
  void deleteGroup(String id);

  /**
   * Create a role.
   *
   * @param request the new role's id, label, and grants.
   * @return the created role.
   * @throws ClientException on any failure (no oracle).
   */
  Role createRole(NewRole request);

  /**
   * Delete a role.
   *
   * @param id the role id.
   * @throws ClientException on any failure (no oracle).
   */
  void deleteRole(String id);

  /**
   * Build an HTTP-backed client.
   *
   * @param baseUri    the directory origin (e.g. {@code http://127.0.0.1:8466}).
   * @param adminToken the directory admin bearer token (held in memory only, never logged).
   * @return a client over a loopback-friendly {@link HttpTransport}.
   */
  static MiniDirectoryClient http(final URI baseUri, final String adminToken) {
    return new HttpMiniDirectoryClient(new HttpTransport(baseUri, adminToken));
  }
}
