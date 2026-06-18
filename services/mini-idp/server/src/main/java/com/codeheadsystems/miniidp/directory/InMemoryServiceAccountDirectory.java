package com.codeheadsystems.miniidp.directory;

import com.codeheadsystems.minitoken.auth.Authorization;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link ServiceAccountDirectory} for tests and a zero-dependency local run.
 *
 * <p>It stands in for a live mini-directory: a test {@link #add}s service accounts (clientId, secret,
 * authorization), and {@link #authenticate} verifies the presented secret in constant time, with no
 * oracle — an unknown client still incurs a comparison so timing does not reveal existence. The
 * production path uses {@link HttpServiceAccountDirectory} against a running mini-directory instead;
 * both honor the same SPI, so mini-idp's token endpoint is identical regardless of the source.
 */
public final class InMemoryServiceAccountDirectory implements ServiceAccountDirectory {

  private record Account(byte[] secret, Authorization authorization) {
  }

  private static final byte[] DUMMY = "dummy-secret-for-uniform-timing".getBytes(StandardCharsets.UTF_8);

  private final Map<String, Account> accounts = new ConcurrentHashMap<>();

  /** Add a service account. @return this, for fluent test setup. */
  public InMemoryServiceAccountDirectory add(final String clientId, final String secret,
                                             final Authorization authorization) {
    accounts.put(clientId, new Account(secret.getBytes(StandardCharsets.UTF_8), authorization));
    return this;
  }

  @Override
  public Optional<ResolvedClient> authenticate(final String clientId, final char[] secret) {
    final Account account = clientId == null ? null : accounts.get(clientId);
    final byte[] presented = secret == null ? new byte[0]
        : new String(secret).getBytes(StandardCharsets.UTF_8);
    if (account == null) {
      MessageDigest.isEqual(DUMMY, presented); // spend comparable effort; reveal nothing
      return Optional.empty();
    }
    return MessageDigest.isEqual(account.secret(), presented)
        ? Optional.of(new ResolvedClient(clientId, account.authorization()))
        : Optional.empty();
  }
}
