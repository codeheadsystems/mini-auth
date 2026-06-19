package com.codeheadsystems.miniconsole.kms;

import com.codeheadsystems.minikms.protocol.KeyGroupView;
import java.util.List;

/**
 * The console's port onto mini-kms key-group administration — the small slice of the KMS control
 * plane the Keys page drives, behind an interface so the handler is testable with a fake (no real
 * KMS, no socket).
 *
 * <p><b>Why a port (and not {@code KmsClient} directly):</b> {@code KmsClient} is a single socket
 * connection intended for single-threaded use, whereas the console serves each request on its own
 * virtual thread. The production adapter ({@link KmsKeyGroupAdmin}) therefore opens a fresh
 * connection per operation; this interface hides that, and lets tests inject a capturing fake.
 *
 * <p>Every mutating method may throw {@link KeyAdminException} (the no-oracle collapse). {@link
 * #healthy()} instead returns a boolean (an unreachable KMS is "not healthy", not an error).
 */
public interface KeyGroupAdmin {

  /** @return whether the KMS answered a health check (data-plane); false if unreachable. */
  boolean healthy();

  /**
   * @return every key group with its active version and version history.
   * @throws KeyAdminException on any failure (no oracle).
   */
  List<KeyGroupView> listGroups();

  /**
   * Create a new key group.
   *
   * @param keyId the group name.
   * @throws KeyAdminException on any failure (e.g. it already exists) — no oracle.
   */
  void createGroup(String keyId);

  /**
   * Rotate a key group (mint a new active version).
   *
   * @param keyId the group name.
   * @throws KeyAdminException on any failure.
   */
  void rotateGroup(String keyId);

  /**
   * Disable a non-active version.
   *
   * @param keyId   the group name.
   * @param version the version to disable.
   * @throws KeyAdminException on any failure.
   */
  void disableVersion(String keyId, long version);

  /**
   * Re-enable a disabled version.
   *
   * @param keyId   the group name.
   * @param version the version to enable.
   * @throws KeyAdminException on any failure.
   */
  void enableVersion(String keyId, long version);

  /**
   * Destroy a non-active version's key material. <b>Irreversible</b> (crypto-shredding): anything
   * encrypted under that version becomes permanently unrecoverable.
   *
   * @param keyId   the group name.
   * @param version the version to destroy.
   * @throws KeyAdminException on any failure.
   */
  void destroyVersion(String keyId, long version);
}
