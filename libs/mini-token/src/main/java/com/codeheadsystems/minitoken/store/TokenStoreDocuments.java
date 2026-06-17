package com.codeheadsystems.minitoken.store;

import com.codeheadsystems.minitoken.model.AuditEntry;
import com.codeheadsystems.minitoken.model.Revocation;
import com.codeheadsystems.minitoken.model.SigningKeyRecord;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The top-level JSON document shapes the token plane persists through a {@link DocumentStore}, one
 * per file. Each is a thin {@code {"...": [ ... ]}} wrapper around a list so the on-disk file is a
 * single JSON object (easier to extend later with metadata fields than a bare top-level array).
 *
 * <p>These shapes are the on-disk contract: the field names here are exactly what mini-idp wrote
 * before the token plane was extracted, so existing {@code signing-keys.json} / {@code
 * revocations.json} / {@code audit.json} files load unchanged.
 */
public final class TokenStoreDocuments {

  private TokenStoreDocuments() {
  }

  /**
   * The signing-key set file (mini-idp: {@code signing-keys.json}). Holds every key (active +
   * retired-but-still-published) and records which kid is currently active.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record SigningKeys(String activeKid, List<SigningKeyRecord> keys) {
    public SigningKeys {
      keys = keys == null ? List.of() : List.copyOf(keys);
    }
  }

  /** The revocation denylist file (mini-idp: {@code revocations.json}). */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Revocations(List<Revocation> revocations) {
    public Revocations {
      revocations = revocations == null ? List.of() : List.copyOf(revocations);
    }
  }

  /** The audit log file (mini-idp: {@code audit.json}). */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Audit(List<AuditEntry> entries) {
    public Audit {
      entries = entries == null ? List.of() : List.copyOf(entries);
    }
  }
}
