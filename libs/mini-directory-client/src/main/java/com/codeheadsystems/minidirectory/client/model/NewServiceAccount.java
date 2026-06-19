package com.codeheadsystems.minidirectory.client.model;

import java.util.List;

/**
 * The body of {@code POST /admin/service-accounts} — the client-side copy of mini-directory's
 * {@code CreateServiceAccountRequest}. The id and secret are generated server-side; the secret is
 * returned exactly once in {@link ServiceAccountCreated}.
 *
 * @param displayName optional human label (may be null).
 * @param admin       whether the service account holds the control/admin capability.
 * @param memberOf    group ids it joins (may be empty).
 * @param roles       role ids assigned directly (may be empty).
 * @param grants      direct grants (may be empty).
 */
public record NewServiceAccount(String displayName, boolean admin, List<String> memberOf,
                                List<String> roles, List<GrantSpec> grants) {
}
