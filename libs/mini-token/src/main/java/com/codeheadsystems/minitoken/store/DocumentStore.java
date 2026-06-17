package com.codeheadsystems.minitoken.store;

/**
 * The persistence SPI for the token plane: load and save one JSON-shaped document per backing
 * store. This is the seam that lets different services persist the token plane differently.
 *
 * <p>The token-plane services ({@code SigningKeyService}, {@code RevocationService},
 * {@code AuditService}) depend only on this small interface, never on a concrete file/database
 * implementation. mini-idp backs it with an atomic, owner-only ({@code 0600}) JSON file store;
 * another consumer (e.g. mini-oidc) could back the same services with a different store entirely,
 * and a future deployment could wrap the at-rest signing keys under mini-kms behind this seam.
 *
 * <p>An implementation is expected to round-trip the document type {@code T} faithfully — the JSON
 * shapes in {@link TokenStoreDocuments} ARE the on-disk contract — and to fail loudly rather than
 * silently lose data on a write error.
 *
 * @param <T> the document type, a Jackson-serializable record (see {@link TokenStoreDocuments}).
 */
public interface DocumentStore<T> {

  /** @return whether a previously-saved document exists (controls first-run initialization). */
  boolean exists();

  /** Load and parse the document. Only called when {@link #exists()} is true. */
  T load();

  /** Persist the document, replacing any prior contents. */
  void save(T document);
}
