package com.codeheadsystems.miniidp.service;

import com.codeheadsystems.miniidp.model.AuditEntry;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.miniidp.store.StoreDocuments.Audit;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * An append-only audit log of security-relevant events (issuance, grant changes, revocations, key
 * rotation, client registration/removal).
 *
 * <p>Entries carry no secret material (see {@link AuditEntry}). The log is held in memory and
 * rewritten on each append via {@link JsonStore}; for this educational service a bounded in-memory
 * list rewritten atomically is plenty. Methods are {@code synchronized}.
 */
public final class AuditService {

  private final JsonStore<Audit> store;
  private final Clock clock;
  private final List<AuditEntry> entries = new ArrayList<>();

  /**
   * @param store the backing JSON store.
   * @param clock the clock used for entry timestamps.
   */
  public AuditService(final JsonStore<Audit> store, final Clock clock) {
    this.store = store;
    this.clock = clock;
    if (store.exists()) {
      entries.addAll(store.load().entries());
    }
  }

  /**
   * Append an audit entry.
   *
   * @param event    the event type (e.g. {@code "token.issued"}).
   * @param clientId the client the event concerns, or null.
   * @param detail   a short non-secret detail, or null.
   */
  public synchronized void record(final String event, final String clientId, final String detail) {
    entries.add(new AuditEntry(clock.instant().getEpochSecond(), event, clientId, detail));
    store.save(new Audit(new ArrayList<>(entries)));
  }

  /** @return all audit entries, oldest first. */
  public synchronized List<AuditEntry> list() {
    return new ArrayList<>(entries);
  }
}
