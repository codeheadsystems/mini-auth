package com.codeheadsystems.minica.client.model;

import java.util.List;

/**
 * Body of {@code POST /issue} — mirrors mini-ca's request shape.
 *
 * @param csr        the PKCS#10 certificate signing request, PEM.
 * @param ttlSeconds requested leaf lifetime in seconds (optional; clamped to the CA's max — null uses
 *                   the CA default).
 * @param sans       subject alternative names (optional; null when unused).
 */
public record IssueRequest(String csr, Long ttlSeconds, List<String> sans) {
}
