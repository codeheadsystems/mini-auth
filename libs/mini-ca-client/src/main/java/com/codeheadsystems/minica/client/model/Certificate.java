package com.codeheadsystems.minica.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A freshly issued (or renewed) certificate — the client-side copy of mini-ca's {@code IssueResponse}.
 * Everything here is public material (certificates and serials are not secret): the CA never returns a
 * private key, only the leaf it signed and the trust anchor needed to validate it.
 *
 * @param serial        the issued certificate's serial (lowercase hex) — the revocation handle.
 * @param certificate   the issued leaf certificate, PEM.
 * @param caCertificate the CA root certificate, PEM (the trust anchor to validate the leaf).
 * @param notAfter      leaf expiry (epoch seconds).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Certificate(String serial, String certificate, String caCertificate, long notAfter) {
}
