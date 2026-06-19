package com.codeheadsystems.miniconsole.kms;

import com.codeheadsystems.minikms.client.KmsClient;
import com.codeheadsystems.minikms.client.KmsClientException;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import java.util.List;

/**
 * The production {@link KeyGroupAdmin}, adapting mini-kms's socket {@link KmsClient}.
 *
 * <p><b>Connect-per-operation.</b> {@code KmsClient} holds one socket and is single-threaded; the
 * console is virtual-thread-per-request. So every method opens a fresh connection, performs the one
 * operation, and closes it (try-with-resources) — a connection is never shared across request
 * threads. The cost is one short-lived loopback socket per admin action, which is negligible for an
 * occasional-use admin console.
 *
 * <p><b>Two tokens, two planes.</b> {@code health()} is a data-plane call (the API token); the
 * key-group control operations are control-plane (the admin token). The adapter connects with the
 * token matching the plane, exactly as the {@code kms-admin}/{@code client} CLIs do.
 *
 * <p>Any {@link KmsClientException} collapses to {@link KeyAdminException} — no status or reason
 * leaks (no oracle). The tokens are held in memory only and never logged.
 */
public final class KmsKeyGroupAdmin implements KeyGroupAdmin {

  private final String host;
  private final int port;
  private final String apiToken;
  private final String adminToken;

  /**
   * @param host       the KMS loopback host.
   * @param port       the KMS TCP port.
   * @param apiToken   the data-plane API token (for {@code health}).
   * @param adminToken the control-plane admin token (for key-group operations).
   */
  public KmsKeyGroupAdmin(final String host, final int port, final String apiToken,
                          final String adminToken) {
    this.host = host;
    this.port = port;
    this.apiToken = apiToken;
    this.adminToken = adminToken;
  }

  @Override
  public boolean healthy() {
    // A health check is a status probe, not an operation: an unreachable KMS is "not healthy",
    // reported generically, never an error the operator must handle.
    try (KmsClient client = KmsClient.connectTcp(host, port, apiToken)) {
      return client.health();
    } catch (final KmsClientException e) {
      return false;
    }
  }

  @Override
  public List<KeyGroupView> listGroups() {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      return client.listKeyGroups();
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }

  @Override
  public void createGroup(final String keyId) {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      client.createKeyGroup(keyId);
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }

  @Override
  public void rotateGroup(final String keyId) {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      client.rotateKeyGroup(keyId);
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }

  @Override
  public void disableVersion(final String keyId, final long version) {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      client.disableVersion(keyId, version);
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }

  @Override
  public void enableVersion(final String keyId, final long version) {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      client.enableVersion(keyId, version);
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }

  @Override
  public void destroyVersion(final String keyId, final long version) {
    try (KmsClient client = KmsClient.connectTcp(host, port, adminToken)) {
      client.destroyVersion(keyId, version);
    } catch (final KmsClientException e) {
      throw new KeyAdminException(e);
    }
  }
}
