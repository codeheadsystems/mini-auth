package com.codeheadsystems.minica.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import com.codeheadsystems.minica.server.CaServer;
import com.codeheadsystems.minica.server.ServerConfig;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavior proof for {@link MiniCaClient}: boot the REAL mini-ca on an ephemeral loopback port
 * (plaintext-key mode — no mini-kms), then drive a full lifecycle over HTTP — fetch the trust anchor,
 * issue a cert from a generated CSR, renew it, revoke it, and confirm the serials surface in the
 * revocation list and issuance log. A garbage CSR and a refused admin token both collapse to
 * {@link ClientException} (no oracle).
 */
class HttpMiniCaClientTest {

  private static final String ADMIN_TOKEN = "ca-admin";

  private CaServer server;
  private MiniCaClient client;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    final ServerConfig config =
        ServerConfig.resolve(new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = CaServer.create(config, ADMIN_TOKEN, Clock.systemUTC());
    server.start();
    client = MiniCaClient.http(URI.create("http://127.0.0.1:" + server.address().getPort()),
        ADMIN_TOKEN);
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void caCertificate_isPublicPem() {
    final String pem = client.caCertificatePem();
    assertTrue(pem.contains("BEGIN CERTIFICATE"));
  }

  @Test
  void health_reportsOk() {
    assertEquals("ok", client.health().status());
  }

  @Test
  void issue_returnsALeafChainingToTheCa() {
    final Certificate cert = client.issue(Csr.generate("svc-one"), Duration.ofHours(1));
    assertNotNull(cert.serial());
    assertTrue(cert.certificate().contains("BEGIN CERTIFICATE"));
    assertTrue(cert.caCertificate().contains("BEGIN CERTIFICATE"));
    assertTrue(client.issuanceLog().stream().anyMatch(e -> e.serial().equals(cert.serial())));
  }

  @Test
  void renew_revokesThePreviousSerial() {
    final Certificate first = client.issue(Csr.generate("svc-two"), Duration.ofHours(1));
    final Certificate renewed = client.renew(Csr.generate("svc-two"), Duration.ofHours(1), first.serial());
    assertNotNull(renewed.serial());
    assertFalse(renewed.serial().equals(first.serial()));
    // Renewing with a previous serial revokes the replaced cert.
    assertTrue(revoked(first.serial()), "the renewed-from serial must be revoked");
  }

  @Test
  void revoke_addsTheSerialToTheRevocationList() {
    final Certificate cert = client.issue(Csr.generate("svc-three"), Duration.ofHours(1));
    assertFalse(revoked(cert.serial()));
    client.revoke(cert.serial(), "key compromise");
    assertTrue(revoked(cert.serial()));
  }

  @Test
  void issue_withGarbageCsr_collapsesToClientException() {
    assertThrows(ClientException.class, () -> client.issue("not a real csr", Duration.ofHours(1)));
  }

  @Test
  void issue_withWrongAdminToken_collapsesToClientException() {
    final MiniCaClient badAdmin = MiniCaClient.http(
        URI.create("http://127.0.0.1:" + server.address().getPort()), "wrong-admin-token");
    assertThrows(ClientException.class, () -> badAdmin.issue(Csr.generate("x"), Duration.ofHours(1)));
  }

  private boolean revoked(final String serial) {
    return client.revocations().stream().map(RevocationEntry::serial).anyMatch(serial::equals);
  }
}
