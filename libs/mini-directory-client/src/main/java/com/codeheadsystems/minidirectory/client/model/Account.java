package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * An account as the directory's admin API returns it — the client-side copy of mini-directory's
 * {@code AccountView}. It carries <b>no secret material</b> (the directory never returns a secret
 * hash; the one-time service-account secret is only seen at creation, which this read client does
 * not do).
 *
 * @param id          the account id (a mini-policy principal id / token {@code sub}).
 * @param kind        whether this is a human or a service account.
 * @param displayName the human label, if any (omitted by the server when null).
 * @param admin       whether it holds the control/admin capability.
 * @param enabled     whether it is currently active.
 * @param memberOf    group memberships (ids).
 * @param roles       directly-assigned role ids.
 * @param grants      directly-assigned grants.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Account(String id, PrincipalKind kind, String displayName, boolean admin,
                      boolean enabled, List<String> memberOf, List<String> roles,
                      List<GrantSpec> grants) {
}
