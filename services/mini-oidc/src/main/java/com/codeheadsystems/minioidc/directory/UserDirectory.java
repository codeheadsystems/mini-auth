package com.codeheadsystems.minioidc.directory;

import java.util.Optional;

/**
 * The seam by which mini-oidc resolves an authenticated human to a {@link DirectoryUser} — its
 * principal, grants, and profile claims — <b>via mini-directory</b>, the family's identity source
 * of truth.
 *
 * <p>It is an SPI so the resolution source is pluggable: production wires {@link HttpUserDirectory}
 * (an HTTP client to mini-directory's {@code /admin/principals/{id}/resolution} endpoint), while
 * tests and a zero-dependency local run use {@link InMemoryUserDirectory}. Either way, the
 * authenticated username (from the passkey ceremony) becomes the directory account id whose grants
 * drive scope authorization. mini-oidc never invents identities; it only reads them.
 */
public interface UserDirectory {

  /**
   * @param username the authenticated username / directory account id.
   * @return the resolved user, or empty if the directory has no such (enabled) account.
   */
  Optional<DirectoryUser> resolve(String username);
}
