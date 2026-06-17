package com.codeheadsystems.minioidc.directory;

import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Resource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The production {@link UserDirectory}: resolves a human <b>via mini-directory</b> over HTTP, by
 * calling its {@code GET /admin/principals/{id}/resolution} endpoint (the resolved principal +
 * fully-expanded grants) with the bootstrap admin token, plus {@code GET /admin/principals/{id}} for
 * the display name.
 *
 * <p>This is the concrete wiring of the runtime relationship from {@code docs/DIRECTION.md}: the
 * issuer reads identities and grants from the directory rather than keeping its own registry. Any
 * non-200 (including an unknown principal) resolves to {@link Optional#empty()} — no oracle about
 * why. The admin token is never logged.
 */
public final class HttpUserDirectory implements UserDirectory {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final HttpClient http = HttpClient.newBuilder()
      .connectTimeout(Duration.ofSeconds(5)).build();
  private final String baseUrl;
  private final String adminToken;

  /**
   * @param baseUrl    the mini-directory base URL (e.g. {@code http://127.0.0.1:8466}).
   * @param adminToken the mini-directory bootstrap admin token (sent as a bearer; never logged).
   */
  public HttpUserDirectory(final String baseUrl, final String adminToken) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.adminToken = adminToken;
  }

  @Override
  public Optional<DirectoryUser> resolve(final String username) {
    if (username == null || username.isBlank()) {
      return Optional.empty();
    }
    final String enc = URI.create("/").resolve(java.net.URLEncoder.encode(username, StandardCharsets.UTF_8)).getRawPath();
    final Optional<JsonNode> resolution = get("/admin/principals/" + enc + "/resolution");
    if (resolution.isEmpty()) {
      return Optional.empty();
    }
    final JsonNode body = resolution.get();
    final List<Grant> grants = new ArrayList<>();
    final JsonNode grantsNode = body.get("grants");
    if (grantsNode != null) {
      for (final JsonNode grant : grantsNode) {
        grants.add(new Grant(Action.of(grant.get("action").asString()),
            Resource.of(grant.get("resource").asString())));
      }
    }
    final String name = get("/admin/principals/" + enc)
        .map(account -> account.has("displayName") ? account.get("displayName").asString(null) : null)
        .orElse(null);
    return Optional.of(new DirectoryUser(
        body.get("id").asString(), body.get("admin").asBoolean(false), grants, name, null, false));
  }

  private Optional<JsonNode> get(final String path) {
    try {
      final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
          .header("Authorization", "Bearer " + adminToken)
          .timeout(Duration.ofSeconds(5))
          .GET().build();
      final var response = http.send(request, BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        return Optional.empty();
      }
      return Optional.of(MAPPER.readTree(response.body()));
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      return Optional.empty();
    } catch (final java.io.IOException | RuntimeException e) {
      // A directory outage must not be an oracle; resolution simply fails closed.
      return Optional.empty();
    }
  }
}
