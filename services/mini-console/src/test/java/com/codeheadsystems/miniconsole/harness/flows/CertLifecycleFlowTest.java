package com.codeheadsystems.miniconsole.harness.flows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.HealthStatus;
import com.codeheadsystems.minica.client.model.IssuanceLogEntry;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import com.codeheadsystems.minica.server.CaServer;
import com.codeheadsystems.minica.server.ServerConfig;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for {@link CertLifecycleFlow}. The PASS path runs against a REAL mini-ca: the issued leaf must
 * genuinely chain to the published root (JDK PKIX), and the renewal must end up on the revocation
 * list. The FAIL path uses a fake CA whose leaf does not chain to its root, proving the headline
 * chain-validation assertion actually gates the result.
 */
class CertLifecycleFlowTest {

  private CaServer server;

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void run_againstRealCa_passesAndRevokesTheRenewal(@TempDir final Path dir) throws Exception {
    final ServerConfig config =
        ServerConfig.resolve(new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = CaServer.create(config, "ca-admin", Clock.systemUTC());
    server.start();
    final MiniCaClient ca = MiniCaClient.http(
        URI.create("http://127.0.0.1:" + server.address().getPort()), "ca-admin");

    final ExerciseResult result = new CertLifecycleFlow().run(ca);

    assertEquals(Status.PASS, result.status(), "a real CA leaf must chain to its root");
    // The chain-validation step is the headline assertion.
    assertTrue(result.steps().stream().anyMatch(
        s -> s.label().contains("Validate chain") && s.status() == Status.PASS));
    // The renewed serial must end up revoked.
    final String revokedSerial = result.steps().stream()
        .filter(s -> s.label().equals("Revoke certificate")).map(Step::detail).findFirst().orElse("");
    assertTrue(ca.revocations().stream().anyMatch(r -> revokedSerial.contains(r.serial())));
  }

  @Test
  void run_whenLeafDoesNotChain_fails() {
    final ExerciseResult result = new CertLifecycleFlow().run(new NonChainingCa());
    assertEquals(Status.FAIL, result.status());
    assertTrue(result.steps().stream().anyMatch(
        s -> s.label().contains("Validate chain") && s.status() == Status.FAIL));
  }

  /** A CA whose "issued" leaf is junk PEM — it parses/validates to nothing, so the chain check fails. */
  private static final class NonChainingCa implements MiniCaClient {
    private static final String JUNK = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n";

    @Override
    public String caCertificatePem() {
      return JUNK;
    }

    @Override
    public List<RevocationEntry> revocations() {
      return List.of();
    }

    @Override
    public Certificate issue(final String csrPem, final Duration ttl) {
      return new Certificate("serial-x", JUNK, JUNK, 0L);
    }

    @Override
    public Certificate renew(final String csrPem, final Duration ttl, final String previousSerial) {
      return new Certificate("serial-y", JUNK, JUNK, 0L);
    }

    @Override
    public void revoke(final String serial, final String reason) {
    }

    @Override
    public List<IssuanceLogEntry> issuanceLog() {
      return List.of();
    }

    @Override
    public HealthStatus health() {
      return new HealthStatus("ok");
    }
  }
}
