package com.codeheadsystems.miniidp.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One audit log entry: a record of a security-relevant event (token issuance, grant change,
 * revocation, key rotation, client registration/removal).
 *
 * <p>Audit entries deliberately carry NO secret material — no client secrets, no private keys, no
 * raw tokens. A token issuance entry references the token by its {@code jti}, never its serialized
 * form, so the audit log is safe to read and retain.
 *
 * @param at      event time (epoch seconds).
 * @param event   a short event type, e.g. {@code "token.issued"}, {@code "client.registered"}.
 * @param clientId the client the event concerns, or null if not client-specific.
 * @param detail  a short human-readable detail string (no secrets), or null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuditEntry(long at, String event, String clientId, String detail) {
}
