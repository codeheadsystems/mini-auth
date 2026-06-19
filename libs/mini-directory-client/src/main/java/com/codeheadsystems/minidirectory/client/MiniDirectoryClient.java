package com.codeheadsystems.minidirectory.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.HealthStatus;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import java.net.URI;
import java.util.List;

/**
 * A read client for mini-directory's admin + resolution API.
 *
 * <p>Slice 1 exposes the read surface a console needs; mutations come later. Every method may throw
 * {@link ClientException} (the no-oracle collapse): a missing principal, a refused token, and an
 * unreachable directory are indistinguishable to the caller, by design.
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
