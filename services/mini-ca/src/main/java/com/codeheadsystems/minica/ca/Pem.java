package com.codeheadsystems.minica.ca;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Minimal PEM (RFC 7468) encode/decode — the textual armor around DER for certificates and CSRs.
 *
 * <p>Hand-rolled, like the family's other formats: a PEM block is just
 * {@code -----BEGIN <label>-----}, the base64 of the DER wrapped at 64 columns, and
 * {@code -----END <label>-----}. Keeping it explicit avoids pulling in a PEM library and makes the
 * wire format auditable end to end.
 */
public final class Pem {

  /** PEM label for an X.509 certificate. */
  public static final String CERTIFICATE = "CERTIFICATE";

  /** PEM label for a PKCS#10 certification request (CSR). */
  public static final String CSR = "CERTIFICATE REQUEST";

  private Pem() {
  }

  /** Encode DER bytes as a PEM block with the given label. */
  public static String encode(final String label, final byte[] der) {
    final String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
        .encodeToString(der);
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
  }

  /** Decode a PEM block (any label) to its DER bytes; tolerant of surrounding whitespace. */
  public static byte[] decode(final String pem) {
    if (pem == null) {
      throw new IllegalArgumentException("PEM is null");
    }
    final StringBuilder base64 = new StringBuilder();
    boolean inBody = false;
    for (final String line : pem.split("\\R")) {
      final String trimmed = line.trim();
      if (trimmed.startsWith("-----BEGIN")) {
        inBody = true;
      } else if (trimmed.startsWith("-----END")) {
        break;
      } else if (inBody) {
        base64.append(trimmed);
      }
    }
    if (base64.isEmpty()) {
      throw new IllegalArgumentException("no PEM body found");
    }
    return Base64.getMimeDecoder().decode(base64.toString());
  }
}
