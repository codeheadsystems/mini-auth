package com.codeheadsystems.miniidp.store;

import com.codeheadsystems.miniidp.model.AuditEntry;
import com.codeheadsystems.miniidp.model.ClientRecord;
import com.codeheadsystems.miniidp.model.Revocation;
import com.codeheadsystems.miniidp.model.SigningKeyRecord;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The top-level JSON document shapes persisted by {@link JsonStore}, one per file.
 *
 * <p>Each is a thin {@code {"...": [ ... ]}} wrapper around a list so the on-disk file is a single
 * JSON object (easier to extend later with metadata fields than a bare top-level array). They live
 * together here because they carry no behaviour — just structure.
 */
public final class StoreDocuments {

  private StoreDocuments() {
  }

  /** The client registry file: {@code clients.json}. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ClientRegistry(List<ClientRecord> clients) {
    public ClientRegistry {
      clients = clients == null ? List.of() : List.copyOf(clients);
    }
  }

  /**
   * The signing-key set file: {@code signing-keys.json}. Holds every key (active + retired-but-
   * still-published) and records which kid is currently active.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record SigningKeys(String activeKid, List<SigningKeyRecord> keys) {
    public SigningKeys {
      keys = keys == null ? List.of() : List.copyOf(keys);
    }
  }

  /** The revocation denylist file: {@code revocations.json}. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Revocations(List<Revocation> revocations) {
    public Revocations {
      revocations = revocations == null ? List.of() : List.copyOf(revocations);
    }
  }

  /** The audit log file: {@code audit.json}. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Audit(List<AuditEntry> entries) {
    public Audit {
      entries = entries == null ? List.of() : List.copyOf(entries);
    }
  }
}
