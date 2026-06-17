package com.codeheadsystems.minioidc.directory;

import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Principal;
import java.util.List;

/**
 * A human resolved from the directory into exactly what mini-oidc needs to issue tokens and decide
 * scopes: a mini-policy {@link Principal} (subject + admin capability), the principal's grants (over
 * which {@link com.codeheadsystems.minioidc.service.ScopeAuthorizer} authorizes scopes), and the
 * profile claims {@code /userinfo} and the ID token expose per granted scope.
 *
 * <p>This mirrors mini-directory's {@code /admin/principals/{id}/resolution} output (id + admin +
 * grants). The profile fields ({@code name}/{@code email}) are looked up alongside; mini-directory
 * does not yet model email, so {@code email} may be null — {@code /userinfo} simply omits absent
 * claims.
 *
 * @param subject       the principal id (the token {@code sub}).
 * @param admin         whether the principal holds the control/admin capability.
 * @param grants        the principal's effective mini-policy grants.
 * @param name          the display name (for the {@code profile} scope), or null.
 * @param email         the email (for the {@code email} scope), or null.
 * @param emailVerified whether the email is verified.
 */
public record DirectoryUser(String subject, boolean admin, List<Grant> grants,
                            String name, String email, boolean emailVerified) {

  public DirectoryUser {
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /** @return the mini-policy principal this user resolves to. */
  public Principal principal() {
    return new Principal(subject, admin);
  }
}
