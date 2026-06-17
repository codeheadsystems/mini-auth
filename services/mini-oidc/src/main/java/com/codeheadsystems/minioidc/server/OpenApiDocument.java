package com.codeheadsystems.minioidc.server;

import com.codeheadsystems.minioidc.server.http.Json;
import com.codeheadsystems.minioidc.server.http.StaticResource;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * The served OpenAPI 3.1 spec, loaded once from the checked-in {@code /openapi.yaml} resource.
 *
 * <p>The YAML file is the single authoritative contract. We serve it verbatim at
 * {@code /openapi.yaml}, and — because some tools prefer JSON — also parse it once and re-emit it
 * as JSON for {@code /openapi.json}. Both come from the same source file, so the two
 * representations can never disagree. The contract test parses these bytes and checks the
 * documented paths against the live routes.
 */
public final class OpenApiDocument {

  private static final String RESOURCE = "/openapi.yaml";

  private final byte[] yaml;
  private final byte[] json;

  private OpenApiDocument(final byte[] yaml, final byte[] json) {
    this.yaml = yaml;
    this.json = json;
  }

  /** Load and parse the bundled spec (fails loudly if it is missing or not valid YAML). */
  public static OpenApiDocument load() {
    final byte[] yamlBytes = StaticResource.bytes(RESOURCE);
    try {
      final JsonNode tree = new YAMLMapper().readTree(yamlBytes);
      final byte[] jsonBytes = Json.MAPPER.writeValueAsBytes(tree);
      return new OpenApiDocument(yamlBytes, jsonBytes);
    } catch (final JacksonException e) {
      throw new IllegalStateException("bundled openapi.yaml is not valid YAML", e);
    }
  }

  /** @return the spec as YAML bytes. */
  public byte[] yaml() {
    return yaml.clone();
  }

  /** @return the spec as JSON bytes. */
  public byte[] json() {
    return json.clone();
  }
}
