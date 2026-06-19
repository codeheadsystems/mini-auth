package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.HealthStatus;
import com.codeheadsystems.minica.client.model.IssuanceLogEntry;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A canned, in-memory {@link MiniCaClient} for console tests — no real CA is booted. It records
 * issuances and revocations so the Certificates page renders real-looking state. The PEMs it returns
 * are placeholders (the page only displays them); this fake therefore also serves the
 * certificate-lifecycle flow's <b>failure</b> path — its junk leaf/CA never chain-validate, so the
 * flow FAILs. Set {@link #failCalls} to make every call throw (the no-oracle path).
 */
final class FakeCaClient implements MiniCaClient {

  private static final String PLACEHOLDER_PEM =
      "-----BEGIN CERTIFICATE-----\nMIIBnot-a-real-cert\n-----END CERTIFICATE-----\n";

  /** When true, every call throws — used to prove the Certificates page degrades without an oracle. */
  boolean failCalls;

  private final List<IssuanceLogEntry> log = new ArrayList<>();
  private final List<RevocationEntry> revocations = new ArrayList<>();
  private int counter;

  @Override
  public String caCertificatePem() {
    guard();
    return PLACEHOLDER_PEM;
  }

  @Override
  public List<RevocationEntry> revocations() {
    guard();
    return List.copyOf(revocations);
  }

  @Override
  public Certificate issue(final String csrPem, final Duration ttl) {
    guard();
    return record("CN=issued");
  }

  @Override
  public Certificate renew(final String csrPem, final Duration ttl, final String previousSerial) {
    guard();
    return record("CN=renewed");
  }

  @Override
  public void revoke(final String serial, final String reason) {
    guard();
    revocations.add(new RevocationEntry(serial, Instant.now().getEpochSecond(), reason));
  }

  @Override
  public List<IssuanceLogEntry> issuanceLog() {
    guard();
    return List.copyOf(log);
  }

  @Override
  public HealthStatus health() {
    guard();
    return new HealthStatus("ok");
  }

  /** @return whether the given serial has been revoked (for test assertions). */
  boolean isRevoked(final String serial) {
    return revocations.stream().anyMatch(r -> r.serial().equals(serial));
  }

  private Certificate record(final String subject) {
    final String serial = "serial-" + (++counter);
    final long now = Instant.now().getEpochSecond();
    log.add(new IssuanceLogEntry(serial, subject, now, now + 3600, now, null));
    return new Certificate(serial, PLACEHOLDER_PEM, PLACEHOLDER_PEM, now + 3600);
  }

  private void guard() {
    if (failCalls) {
      throw new ClientException("ca unavailable");
    }
  }
}
