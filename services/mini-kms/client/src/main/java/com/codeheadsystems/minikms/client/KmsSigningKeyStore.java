package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minitoken.model.SigningKeyRecord;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;

/**
 * The recursive integration: a mini-token {@link DocumentStore} for signing keys whose <b>private
 * key material is envelope-encrypted under a mini-kms key group</b> instead of written
 * plaintext-at-{@code 0600}. It is a decorator — it wraps each {@link SigningKeyRecord}'s private key
 * via mini-kms on {@link #save} and unwraps it on {@link #load}, then delegates the actual file I/O
 * to an underlying store. So the token plane that secures the family's identities has its own signing
 * keys protected by another mini, and no plaintext signing key ever touches disk.
 *
 * <ul>
 *   <li><b>save</b>: for each record, {@code mini-kms encrypt(keyGroup, PKCS#8 DER, aad=kid)} →
 *       a {@code "kms1:"}-tagged envelope replaces the {@code privatePkcs8Base64} field; the public
 *       key is left untouched. The wrapped document is then persisted by the delegate (atomic 0600).</li>
 *   <li><b>load</b>: the delegate reads the document; each {@code "kms1:"} field is decrypted back to
 *       plaintext PKCS#8 in memory, so {@code SigningKeyService} sees normal keys.</li>
 *   <li><b>rewrap</b>: re-encrypt every stored key onto the group's current active version
 *       (server-side, plaintext never exposed) — the path to take after rotating the mini-kms key
 *       group, using mini-kms's ReEncrypt.</li>
 * </ul>
 *
 * <p>The {@code kid} is bound in as the encryption context (AAD), so a wrapped key cannot be swapped
 * between records. Fields without the {@code "kms1:"} tag are passed through untouched, so a store
 * that already holds plaintext keys (the default path) can be read and transparently migrated.
 * Connections are opened per operation through the supplied factory; mini-kms calls use the
 * <b>data-plane API token</b> (the key group must be created out of band — see {@code docs/DIRECTION.md}).
 */
public final class KmsSigningKeyStore implements DocumentStore<SigningKeys> {

  /** Marker tagging a {@code privatePkcs8Base64} field that holds a mini-kms envelope, not plaintext. */
  public static final String WRAPPED_PREFIX = "kms1:";

  private final DocumentStore<SigningKeys> delegate;
  private final Supplier<KmsClient> connections;
  private final String keyGroup;

  /**
   * @param delegate    the underlying store that performs the file I/O (e.g. an atomic-0600 JSON store).
   * @param connections opens a data-plane {@link KmsClient} (caller supplies host/socket + API token).
   * @param keyGroup    the mini-kms key group the signing keys are wrapped under.
   */
  public KmsSigningKeyStore(final DocumentStore<SigningKeys> delegate,
                            final Supplier<KmsClient> connections, final String keyGroup) {
    this.delegate = delegate;
    this.connections = connections;
    this.keyGroup = keyGroup;
  }

  /**
   * Build a TCP-backed store.
   *
   * @param delegate the underlying file store.
   * @param host     the mini-kms host.
   * @param port     the mini-kms TCP port.
   * @param apiToken the mini-kms data-plane API token.
   * @param keyGroup the key group to wrap under.
   * @return the KMS-backed store.
   */
  public static KmsSigningKeyStore overTcp(final DocumentStore<SigningKeys> delegate, final String host,
                                           final int port, final String apiToken, final String keyGroup) {
    return new KmsSigningKeyStore(delegate, () -> KmsClient.connectTcp(host, port, apiToken), keyGroup);
  }

  @Override
  public boolean exists() {
    return delegate.exists();
  }

  @Override
  public SigningKeys load() {
    final SigningKeys stored = delegate.load();
    if (stored.keys().stream().noneMatch(key -> isWrapped(key.privatePkcs8Base64()))) {
      return stored; // nothing wrapped (e.g. a plaintext store) — no mini-kms call needed.
    }
    try (KmsClient kms = connections.get()) {
      final List<SigningKeyRecord> unwrapped = new ArrayList<>();
      for (final SigningKeyRecord key : stored.keys()) {
        unwrapped.add(mapPrivateKey(key, field -> unwrap(kms, key.kid(), field)));
      }
      return new SigningKeys(stored.activeKid(), unwrapped);
    }
  }

  @Override
  public void save(final SigningKeys document) {
    try (KmsClient kms = connections.get()) {
      final List<SigningKeyRecord> wrapped = new ArrayList<>();
      for (final SigningKeyRecord key : document.keys()) {
        wrapped.add(mapPrivateKey(key, field -> wrap(kms, key.kid(), field)));
      }
      delegate.save(new SigningKeys(document.activeKid(), wrapped));
    }
  }

  /**
   * Re-wrap every stored signing key onto the key group's current active version, using mini-kms
   * ReEncrypt — the plaintext is never exposed. Run this after rotating the mini-kms key group so the
   * old version can later be retired/destroyed.
   */
  public void rewrap() {
    final SigningKeys stored = delegate.load();
    try (KmsClient kms = connections.get()) {
      final List<SigningKeyRecord> rewrapped = new ArrayList<>();
      for (final SigningKeyRecord key : stored.keys()) {
        rewrapped.add(mapPrivateKey(key, field -> isWrapped(field)
            ? WRAPPED_PREFIX + b64(kms.reEncrypt(keyGroup, unB64(strip(field)), aad(key.kid())))
            : field));
      }
      delegate.save(new SigningKeys(stored.activeKid(), rewrapped));
    }
  }

  private String wrap(final KmsClient kms, final String kid, final String plaintextPkcs8Base64) {
    final byte[] der = Base64.getDecoder().decode(plaintextPkcs8Base64);
    return WRAPPED_PREFIX + b64(kms.encrypt(keyGroup, der, aad(kid)));
  }

  private static String unwrap(final KmsClient kms, final String kid, final String field) {
    final byte[] der = kms.decrypt(unB64(strip(field)), aad(kid));
    return Base64.getEncoder().encodeToString(der);
  }

  private static SigningKeyRecord mapPrivateKey(final SigningKeyRecord key,
                                                final java.util.function.UnaryOperator<String> op) {
    return new SigningKeyRecord(key.kid(), op.apply(key.privatePkcs8Base64()), key.publicSpkiBase64(),
        key.active(), key.createdAt(), key.retiredAt());
  }

  private static boolean isWrapped(final String field) {
    return field != null && field.startsWith(WRAPPED_PREFIX);
  }

  private static String strip(final String field) {
    return field.substring(WRAPPED_PREFIX.length());
  }

  private static byte[] aad(final String kid) {
    return kid.getBytes(StandardCharsets.UTF_8);
  }

  private static String b64(final byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  private static byte[] unB64(final String value) {
    return Base64.getDecoder().decode(value);
  }
}
