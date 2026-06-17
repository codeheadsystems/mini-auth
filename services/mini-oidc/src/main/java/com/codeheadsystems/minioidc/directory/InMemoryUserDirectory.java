package com.codeheadsystems.minioidc.directory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link UserDirectory} for tests and a zero-dependency local run.
 *
 * <p>It stands in for a live mini-directory: an operator (or a test) {@link #put}s {@link
 * DirectoryUser}s keyed by username, and {@link #resolve} returns them. The production path uses
 * {@link HttpUserDirectory} against a running mini-directory instead; both honor the same SPI, so
 * mini-oidc's handlers are identical regardless of where identities come from.
 */
public final class InMemoryUserDirectory implements UserDirectory {

  private final Map<String, DirectoryUser> usersByName = new ConcurrentHashMap<>();

  /** Add or replace a resolvable user. @return this, for fluent test setup. */
  public InMemoryUserDirectory put(final DirectoryUser user) {
    usersByName.put(user.subject(), user);
    return this;
  }

  @Override
  public Optional<DirectoryUser> resolve(final String username) {
    return Optional.ofNullable(username == null ? null : usersByName.get(username));
  }
}
