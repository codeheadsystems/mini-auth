package com.codeheadsystems.miniidp.directory;

import com.codeheadsystems.minitoken.auth.Authorization;
import java.util.Optional;

/**
 * The seam by which mini-idp resolves a client's credentials and grants <b>from mini-directory</b>,
 * the family's single source of service-account identity. mini-idp no longer keeps its own client
 * registry: at token issuance it asks the directory to authenticate the presented client credentials
 * and hand back the subject + the authorization the token should carry.
 *
 * <p>An SPI so the source is pluggable: production wires {@link HttpServiceAccountDirectory} (a client
 * to mini-directory's service-account authentication endpoint), while tests and a zero-dependency
 * local run use {@link InMemoryServiceAccountDirectory}. Either way, {@link #authenticate} returns
 * the resolved client only on success and empty on <em>any</em> failure — never revealing whether the
 * client was unknown, disabled, or the secret wrong (the token endpoint's single {@code
 * invalid_client}, preserved).
 */
public interface ServiceAccountDirectory {

  /**
   * Verify a client's credentials and resolve its authorization.
   *
   * @param clientId the presented client id (the token {@code sub}).
   * @param secret   the presented secret (the caller should zero it afterwards).
   * @return the resolved client on success, or empty on any failure (no oracle).
   */
  Optional<ResolvedClient> authenticate(String clientId, char[] secret);

  /**
   * A successfully authenticated service account, resolved to what the token needs.
   *
   * @param subject       the principal id (the token {@code sub}).
   * @param authorization the grants/control-plane authority the token's {@code grants} claim carries.
   */
  record ResolvedClient(String subject, Authorization authorization) {
  }
}
