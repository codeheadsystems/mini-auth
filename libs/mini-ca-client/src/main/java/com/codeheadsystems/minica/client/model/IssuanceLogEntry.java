package com.codeheadsystems.minica.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One entry in the CA's issuance log — the client-side copy of mini-ca's {@code IssuedCertificate}.
 * Carries no private material: just the serial, the subject, the validity window, when it was issued,
 * and the serial it renewed (if any).
 *
 * @param serial            the certificate serial (lowercase hex) — the revocation handle.
 * @param subject           the leaf subject distinguished name.
 * @param notBefore         validity start (epoch seconds).
 * @param notAfter          validity end (epoch seconds).
 * @param issuedAt          when the CA issued it (epoch seconds).
 * @param renewedFromSerial the serial this cert renewed, or null for a fresh issuance.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IssuanceLogEntry(String serial, String subject, long notBefore, long notAfter,
                               long issuedAt, String renewedFromSerial) {
}
