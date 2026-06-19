package com.codeheadsystems.minica.client.model;

import java.util.List;

/**
 * Body of {@code POST /renew} — like {@link IssueRequest}, plus the serial of the cert being replaced
 * (which the CA revokes on success).
 *
 * @param csr            the PKCS#10 certificate signing request, PEM.
 * @param ttlSeconds     requested leaf lifetime in seconds (optional; null uses the CA default).
 * @param sans           subject alternative names (optional; null when unused).
 * @param previousSerial the serial of the cert being replaced (optional; revoked on success).
 */
public record RenewRequest(String csr, Long ttlSeconds, List<String> sans, String previousSerial) {
}
