package com.codeheadsystems.minidirectory.store;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Reads and writes a single JSON document to a file, owner-only (0600) and atomically.
 *
 * <p>This is the storage primitive for the directory document. It is a direct mirror of mini-kms's
 * {@code Keystore} and mini-idp's {@code JsonStore} (the family's atomic-write JSON store, a
 * documented {@code mini-common} extraction candidate — replicated here so the service stays
 * standalone): writes go to a temp file in the same directory, get their permissions restricted,
 * and are then swapped into place with {@link StandardCopyOption#ATOMIC_MOVE} so a crash mid-write
 * can never leave a half-written or world-readable file.
 *
 * <p>0600 matters because the directory file holds service-account secret hashes; a crash or an
 * errant umask must never expose it. We apply the restriction uniformly to the temp file before the
 * move and to the final file after.
 *
 * @param <T> the document type, a Jackson-serializable record.
 */
public final class JsonStore<T> {

  // INDENT_OUTPUT keeps the on-disk files human-readable (these are meant to be inspected).
  // Jackson 3: configure via the immutable builder (instance mutators were removed).
  private static final ObjectMapper MAPPER = JsonMapper.builder()
      .enable(SerializationFeature.INDENT_OUTPUT)
      .build();

  private static final Set<PosixFilePermission> OWNER_ONLY =
      EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private final Path path;
  private final Class<T> type;

  /**
   * @param path the file backing this store.
   * @param type the document type read/written.
   */
  public JsonStore(final Path path, final Class<T> type) {
    this.path = path;
    this.type = type;
  }

  /** @return whether the backing file exists. */
  public boolean exists() {
    return Files.isRegularFile(path);
  }

  /** @return the file backing this store. */
  public Path path() {
    return path;
  }

  /** Load and parse the document. */
  public T load() {
    try {
      return MAPPER.readValue(Files.readAllBytes(path), type);
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to read " + path, e);
    }
  }

  /** Atomically write the document with owner-only (0600) permissions. */
  public void save(final T document) {
    try {
      final Path parent = path.toAbsolutePath().getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      final byte[] json = MAPPER.writeValueAsBytes(document);
      final Path tmp = Files.createTempFile(parent, ".store", ".tmp");
      try {
        Files.write(tmp, json);
        restrictPermissions(tmp);
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      } finally {
        Files.deleteIfExists(tmp);
      }
      restrictPermissions(path);
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to write " + path, e);
    }
  }

  private static void restrictPermissions(final Path path) {
    try {
      Files.setPosixFilePermissions(path, OWNER_ONLY);
    } catch (final UnsupportedOperationException | IOException ignored) {
      // Non-POSIX filesystem: best effort (mirrors mini-kms's Keystore).
    }
  }
}
