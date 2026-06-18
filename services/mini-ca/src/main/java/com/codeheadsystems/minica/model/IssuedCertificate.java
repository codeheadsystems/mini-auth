package com.codeheadsystems.minica.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One entry in the issuance log: a record that the CA signed a leaf certificate. Carries no private
 * material — just the serial (the handle used for revocation), the subject, the validity window, and
 * when it was issued. Safe to read and retain.
 *
 * @param serial            the certificate serial number (lowercase hex) — the revocation handle.
 * @param subject           the leaf subject distinguished name.
 * @param notBefore         validity start (epoch seconds).
 * @param notAfter          validity end (epoch seconds).
 * @param issuedAt          when the CA issued it (epoch seconds).
 * @param renewedFromSerial the serial this cert renewed, or null for a fresh issuance.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record IssuedCertificate(String serial, String subject, long notBefore, long notAfter,
                                long issuedAt, String renewedFromSerial) {
}
