package com.codeheadsystems.miniclient.common;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Resolves a bearer token from an environment variable or a file — never from a CLI argument, and
 * never logged.
 *
 * <p>This is the client-side mirror of the {@code resolveToken} pattern every family {@code
 * ServerMain} uses for its own admin token: prefer the env var, fall back to a file, strip
 * whitespace. A console that calls several downstream admin APIs resolves each downstream token this
 * way. (One of the documented {@code mini-common} candidates; lives here, client-side, until that
 * server-side library exists, at which point the two should converge.)
 */
public final class TokenResolver {

  private TokenResolver() {
  }

  /**
   * Resolve a token, or {@code null} if neither source provides one (the caller decides whether it
   * is required).
   *
   * @param fromEnv the value of the relevant environment variable (may be null/blank).
   * @param file    a file to read the token from if the env var is absent (may be null).
   * @return the trimmed token, or {@code null} if neither is present.
   * @throws IOException if the file is named but cannot be read.
   */
  public static String resolve(final String fromEnv, final Path file) throws IOException {
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (file != null) {
      final String fromFile = Files.readString(file, StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    return null;
  }

  /**
   * Resolve a token that must be present.
   *
   * @param fromEnv         the value of the relevant environment variable (may be null/blank).
   * @param file            a file to read the token from if the env var is absent (may be null).
   * @param missingMessage  the message for the thrown exception when neither source provides a token.
   * @return the trimmed token (never null).
   * @throws IOException           if the file is named but cannot be read.
   * @throws IllegalStateException if neither source provides a token.
   */
  public static String require(final String fromEnv, final Path file, final String missingMessage)
      throws IOException {
    final String token = resolve(fromEnv, file);
    if (token == null) {
      throw new IllegalStateException(missingMessage);
    }
    return token;
  }
}
