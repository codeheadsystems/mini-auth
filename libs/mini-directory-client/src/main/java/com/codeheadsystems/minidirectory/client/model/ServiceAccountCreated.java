package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The response of {@code POST /admin/service-accounts} — the client-side copy of mini-directory's
 * {@code ServiceAccountCreated}. It carries the <b>one-time plaintext secret</b>: this is the only
 * moment the secret is ever returned, and it is not recoverable later.
 *
 * <p><b>Secret hygiene:</b> {@link #toString()} is overridden to <b>redact the secret</b>, so the
 * record can never leak it into a log line, an exception message, or a debugger dump. Only an
 * explicit {@link #secret()} call (the console's once-only banner) ever reads it.
 *
 * @param id          the generated service-account id.
 * @param secret      the one-time plaintext secret — display once, store now, never again.
 * @param displayName the human label, if any.
 * @param account     the created account as a (secret-free) view.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ServiceAccountCreated(String id, String secret, String displayName, Account account) {

  /** Redacts the secret — the record must never print it. */
  @Override
  public String toString() {
    return "ServiceAccountCreated[id=" + id + ", secret=<redacted>, displayName=" + displayName
        + ", account=" + account + "]";
  }
}
