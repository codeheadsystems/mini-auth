package com.codeheadsystems.minitoken.session;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The persisted SSO-session document ({@code sessions.json}) — the single JSON file holding every
 * live {@link BrowserSession}, written through a {@link com.codeheadsystems.minitoken.store.DocumentStore}.
 *
 * <p>Backing the sessions with a shared file (rather than per-process memory) is what lets the OP
 * and a separate forward-auth gateway see the <b>same</b> sessions: mini-oidc is the sole writer
 * (create on login, delete on logout), and any number of gateways read it.
 *
 * @param sessions the live sessions; never null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Sessions(List<BrowserSession> sessions) {

  public Sessions {
    sessions = sessions == null ? List.of() : List.copyOf(sessions);
  }
}
