package com.codeheadsystems.minidirectory.client;

import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.HealthStatus;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The HTTP implementation of {@link MiniDirectoryClient} — each method is one GET to the real
 * directory path, parsed by the shared {@link HttpTransport}. Paths mirror mini-directory's
 * {@code ApiHandlers} exactly:
 *
 * <ul>
 *   <li>{@code GET /admin/principals} → list accounts</li>
 *   <li>{@code GET /admin/principals/{id}} → one account</li>
 *   <li>{@code GET /admin/principals/{id}/resolution} → expanded grants</li>
 *   <li>{@code GET /admin/groups} / {@code GET /admin/roles}</li>
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

  /** Percent-encode an id for use as a single path segment (defends against path injection). */
  private static String encode(final String id) {
    return URLEncoder.encode(id, StandardCharsets.UTF_8);
  }
}
