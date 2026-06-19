package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.kms.KeyAdminException;
import com.codeheadsystems.miniconsole.kms.KeyGroupAdmin;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import com.codeheadsystems.minikms.protocol.KekVersionView;
import java.util.ArrayList;
import java.util.List;

/**
 * A capturing, in-memory {@link KeyGroupAdmin} for console Keys tests — no real KMS, no socket. It
 * returns one canned key group (version 1 ENABLED, version 2 ACTIVE), records every operation, and —
 * when {@link #fail} is set — collapses operations to {@link KeyAdminException} (the no-oracle path).
 */
final class FakeKeyGroupAdmin implements KeyGroupAdmin {

  /** When true, every operation (and {@code listGroups}) throws — the no-oracle path. */
  boolean fail;
  /** What {@link #healthy()} reports. */
  boolean healthy = true;

  final List<String> created = new ArrayList<>();
  final List<String> rotated = new ArrayList<>();
  final List<String> disabled = new ArrayList<>();
  final List<String> enabled = new ArrayList<>();
  final List<String> destroyed = new ArrayList<>();

  @Override
  public boolean healthy() {
    return healthy;
  }

  @Override
  public List<KeyGroupView> listGroups() {
    guard();
    return List.of(new KeyGroupView("billing", 2, List.of(
        new KekVersionView(1, "ENABLED", 0), new KekVersionView(2, "ACTIVE", 0))));
  }

  @Override
  public void createGroup(final String keyId) {
    guard();
    created.add(keyId);
  }

  @Override
  public void rotateGroup(final String keyId) {
    guard();
    rotated.add(keyId);
  }

  @Override
  public void disableVersion(final String keyId, final long version) {
    guard();
    disabled.add(keyId + ":" + version);
  }

  @Override
  public void enableVersion(final String keyId, final long version) {
    guard();
    enabled.add(keyId + ":" + version);
  }

  @Override
  public void destroyVersion(final String keyId, final long version) {
    guard();
    destroyed.add(keyId + ":" + version);
  }

  private void guard() {
    if (fail) {
      throw new KeyAdminException(new RuntimeException("boom"));
    }
  }
}
