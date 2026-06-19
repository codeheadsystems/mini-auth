package com.codeheadsystems.minidirectory.client;

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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The HTTP implementation of {@link MiniDirectoryClient} — each method is one request to the real
 * directory path, (de)serialized by the shared {@link HttpTransport}. Paths mirror mini-directory's
 * {@code ApiHandlers} exactly:
 *
 * <ul>
 *   <li>{@code GET/POST/PUT/DELETE /admin/principals…} → read/create/assign/delete accounts</li>
 *   <li>{@code POST /admin/humans}, {@code POST /admin/service-accounts} → create principals</li>
 *   <li>{@code GET /admin/principals/{id}/resolution} → expanded grants</li>
 *   <li>{@code GET/POST/DELETE /admin/groups…} / {@code …/roles…}</li>
 *   <li>{@code GET /health}</li>
 * </ul>
 */
final class HttpMiniDirectoryClient implements MiniDirectoryClient {

  private final HttpTransport transport;

  HttpMiniDirectoryClient(final HttpTransport transport) {
    this.transport = transport;
  }

  @Override
  public List<Account> listAccounts() {
    return transport.getList("/admin/principals", Account.class);
  }

  @Override
  public Account getAccount(final String id) {
    return transport.get("/admin/principals/" + encode(id), Account.class);
  }

  @Override
  public List<Group> listGroups() {
    return transport.getList("/admin/groups", Group.class);
  }

  @Override
  public List<Role> listRoles() {
    return transport.getList("/admin/roles", Role.class);
  }

  @Override
  public Resolution resolve(final String id) {
    return transport.get("/admin/principals/" + encode(id) + "/resolution", Resolution.class);
  }

  @Override
  public HealthStatus health() {
    return transport.get("/health", HealthStatus.class);
  }

  @Override
  public Account createHuman(final NewHuman request) {
    return transport.post("/admin/humans", request, Account.class);
  }

  @Override
  public ServiceAccountCreated createServiceAccount(final NewServiceAccount request) {
    return transport.post("/admin/service-accounts", request, ServiceAccountCreated.class);
  }

  @Override
  public Account updateAssignment(final String id, final Assignment request) {
    return transport.put("/admin/principals/" + encode(id) + "/assignment", request, Account.class);
  }

  @Override
  public void deleteAccount(final String id) {
    transport.delete("/admin/principals/" + encode(id));
  }

  @Override
  public Group createGroup(final NewGroup request) {
    return transport.post("/admin/groups", request, Group.class);
  }

  @Override
  public void deleteGroup(final String id) {
    transport.delete("/admin/groups/" + encode(id));
  }

  @Override
  public Role createRole(final NewRole request) {
    return transport.post("/admin/roles", request, Role.class);
  }

  @Override
  public void deleteRole(final String id) {
    transport.delete("/admin/roles/" + encode(id));
  }

  /** Percent-encode an id for use as a single path segment (defends against path injection). */
  private static String encode(final String id) {
    return URLEncoder.encode(id, StandardCharsets.UTF_8);
  }
}
