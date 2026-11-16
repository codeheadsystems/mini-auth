package com.codeheadsystems.miniidp.directory;

import java.util.LinkedHashSet;
import java.util.Set;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds an {@link InMemoryServiceAccountDirectory} from a JSON seed, for running mini-idp
 * <b>without mini-directory</b>: the container image, other projects' integration tests, and a
 * zero-dependency local run.
 *
 * <p>The seed is a JSON array, one object per service account:
 *
 * <pre>{@code
 * [
 *   {
 *     "clientId":  "billing",                       // required; becomes the token's sub
 *     "secret":    "s3cret",                        // required
 *     "audiences": ["config-server"],               // optional; extra audiences it may request
 *     "admin":     false,                           // optional; grants.control
 *     "grants":    [{"action": "ENCRYPT", "resource": "billing"}]  // optional; mini-directory shape
 *   }
 * ]
 * }</pre>
 *
 * <p>{@code grants} uses mini-directory's flat {@code (action, resource)} shape and goes through the
 * same {@link Authorizations} reassembly, so a seeded account yields exactly the token a
 * directory-backed one would. A {@code token:audience} grant in {@code grants} is honored too, so
 * {@code audiences} is only a convenience.
 *
 * <p>The seed carries secrets, so it is read from an env var or a file (never argv) by the caller,
 * and nothing here logs it; a parse error names the problem, never the content.
 */
public final class SeededServiceAccounts {

  private static final JsonMapper MAPPER = JsonMapper.builder().build();

  private SeededServiceAccounts() {
  }

  /**
   * @param json the seed (a JSON array as above).
   * @return a directory holding the seeded accounts.
   * @throws IllegalArgumentException if the seed is not valid (the message never echoes secrets).
   */
  public static InMemoryServiceAccountDirectory parse(final String json) {
    final JsonNode root;
    try {
      root = MAPPER.readTree(json);
    } catch (final JacksonException e) {
      throw new IllegalArgumentException("service-account seed is not valid JSON");
    }
    if (root == null || !root.isArray()) {
      throw new IllegalArgumentException("service-account seed must be a JSON array");
    }
    final InMemoryServiceAccountDirectory directory = new InMemoryServiceAccountDirectory();
    int index = 0;
    for (final JsonNode entry : root) {
      final String clientId = text(entry, "clientId");
      final String secret = text(entry, "secret");
      if (clientId == null || clientId.isBlank() || secret == null || secret.isEmpty()) {
        throw new IllegalArgumentException(
            "service-account seed entry " + index + " needs a clientId and a secret");
      }
      final Set<String> audiences = new LinkedHashSet<>(Authorizations.audiences(entry.get("grants")));
      final JsonNode listed = entry.get("audiences");
      if (listed != null && !listed.isNull()) {
        if (!listed.isArray()) {
          throw new IllegalArgumentException(
              "service-account seed entry " + index + ": audiences must be an array");
        }
        for (final JsonNode audience : listed) {
          final String value = audience.asString();
          if (value == null || value.isBlank() || "*".equals(value)) {
            throw new IllegalArgumentException(
                "service-account seed entry " + index + ": audiences must be non-blank and explicit");
          }
          audiences.add(value);
        }
      }
      final boolean admin = entry.has("admin") && entry.get("admin").asBoolean();
      directory.add(clientId, secret,
          Authorizations.fromResolution(admin, entry.get("grants")), audiences);
      index++;
    }
    return directory;
  }

  private static String text(final JsonNode node, final String field) {
    return node.has(field) && !node.get(field).isNull() ? node.get(field).asString() : null;
  }
}
