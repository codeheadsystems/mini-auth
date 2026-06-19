package com.codeheadsystems.miniconsole.server.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * Loads a classpath resource fully into memory (for the vendored Swagger UI assets and the OpenAPI
 * spec).
 *
 * <p>These resources are small and static, so reading them once into a byte array is simpler and
 * faster than streaming. A missing resource is a packaging error, surfaced loudly at startup rather
 * than as a confusing 404 at request time. A verbatim copy of the family's {@code StaticResource}.
 */
public final class StaticResource {

  private StaticResource() {
  }

  /** Read a classpath resource (absolute path, e.g. {@code /swagger-ui/swagger-ui.css}). */
  public static byte[] bytes(final String resourcePath) {
    try (InputStream in = StaticResource.class.getResourceAsStream(resourcePath)) {
      if (in == null) {
        throw new IllegalStateException("missing bundled resource: " + resourcePath);
      }
      return in.readAllBytes();
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to read bundled resource: " + resourcePath, e);
    }
  }
}
