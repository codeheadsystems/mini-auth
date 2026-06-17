package com.codeheadsystems.minioidc.auth;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link BackupCodeRepository} — the storage pk-auth's backup-code recovery flow needs.
 *
 * <p>Keyed by a stable base64 of the {@code UserHandle} bytes (never by the {@code UserHandle}
 * object, whose equality is not relied upon). Stored codes are Argon2id hashes produced by pk-auth's
 * {@code BackupCodeService}; this class only persists them. In-memory like the rest of mini-oidc's
 * ephemeral stores — the documented swap point for a persistent SPI in a real deployment.
 */
public final class InMemoryBackupCodeRepository implements BackupCodeRepository {

  private final Map<String, List<StoredBackupCode>> byUser = new ConcurrentHashMap<>();

  private static String key(final UserHandle handle) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(handle.value());
  }

  @Override
  public synchronized void save(final StoredBackupCode code) {
    byUser.computeIfAbsent(key(code.userHandle()), k -> new ArrayList<>()).add(code);
  }

  @Override
  public synchronized List<StoredBackupCode> findByUserHandle(final UserHandle userHandle) {
    return new ArrayList<>(byUser.getOrDefault(key(userHandle), List.of()));
  }

  @Override
  public synchronized boolean consume(final UserHandle userHandle, final String codeId,
                                      final Instant consumedAt) {
    final List<StoredBackupCode> codes = byUser.get(key(userHandle));
    if (codes == null) {
      return false;
    }
    for (int i = 0; i < codes.size(); i++) {
      final StoredBackupCode code = codes.get(i);
      if (code.codeId().equals(codeId) && !code.consumed()) {
        codes.set(i, new StoredBackupCode(code.codeId(), code.userHandle(), code.hashedCode(),
            true, code.createdAt(), consumedAt));
        return true;
      }
    }
    return false;
  }

  @Override
  public synchronized void deleteByUserHandle(final UserHandle userHandle) {
    byUser.remove(key(userHandle));
  }

  @Override
  public synchronized void replaceAll(final UserHandle userHandle, final List<StoredBackupCode> records) {
    byUser.put(key(userHandle), new ArrayList<>(records));
  }
}
