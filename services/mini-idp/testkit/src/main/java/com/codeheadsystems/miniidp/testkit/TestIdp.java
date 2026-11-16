package com.codeheadsystems.miniidp.testkit;

import com.codeheadsystems.miniidp.directory.InMemoryServiceAccountDirectory;
import com.codeheadsystems.miniidp.server.IdpServer;
import com.codeheadsystems.miniidp.server.ServerConfig;
import com.codeheadsystems.minitoken.auth.Authorization;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The real mini-idp, embedded for tests: started in-process on an ephemeral loopback port, with an
 * in-memory service-account directory (no mini-directory) and a throwaway data directory.
 *
 * <p>The issuer is derived from the bound port ({@code http://127.0.0.1:<port>}), so discovery
 * ({@code /.well-known/openid-configuration}), {@code jwks_uri} and every token's {@code iss} all
 * name the address a verifier actually fetches from. Tokens come from the real client-credentials
 * endpoint over HTTP, so a test exercises exactly what a deployed issuer does.
 *
 * <pre>{@code
 * try (TestIdp idp = TestIdp.builder().audienceAlgorithm("config-server", "ES256").start()) {
 *   idp.addServiceAccount("billing", "s3cret", "config-server");
 *   String token = idp.token("billing", "s3cret", "config-server");   // ES256, aud=config-server
 *   // trust issuer idp.issuer() with audience "config-server"; the subject is "billing"
 *   idp.rotateKeys();                                                // new kids for every algorithm
 * }
 * }</pre>
 *
 * <p>For tests only: the admin token is random per instance and the data directory is deleted on
 * {@link #close()}.
 */
public final class TestIdp implements AutoCloseable {

  private static final JsonMapper JSON = JsonMapper.builder().build();

  private final IdpServer server;
  private final InMemoryServiceAccountDirectory directory;
  private final Path dataDir;
  private final String adminToken;
  private final HttpClient http = HttpClient.newHttpClient();

  private TestIdp(final IdpServer server, final InMemoryServiceAccountDirectory directory,
                  final Path dataDir, final String adminToken) {
    this.server = server;
    this.directory = directory;
    this.dataDir = dataDir;
    this.adminToken = adminToken;
  }

  /** @return a running issuer with the defaults (audience {@code mini-kms}, EdDSA only). */
  public static TestIdp start() {
    return builder().start();
  }

  /** @return a builder for a customized issuer. */
  public static Builder builder() {
    return new Builder();
  }

  /** @return the issuer URL ({@code iss}; append {@code /.well-known/openid-configuration} for discovery). */
  public String issuer() {
    return server.config().issuer();
  }

  /** @return the bound port. */
  public int port() {
    return server.address().getPort();
  }

  /** @return the default audience (tokens requested without an audience carry it). */
  public String defaultAudience() {
    return server.config().audience();
  }

  /**
   * Add (or replace) a service account. It can be used immediately, also after {@link Builder#start()}.
   *
   * @param clientId  the client id; it is the {@code sub} of its tokens.
   * @param secret    its client secret.
   * @param audiences the audiences it may request besides the default one.
   * @return this, for chaining.
   */
  public TestIdp addServiceAccount(final String clientId, final String secret, final String... audiences) {
    directory.add(clientId, secret, new Authorization(false, List.of()), Set.of(audiences));
    return this;
  }

  /**
   * Get a token for the default audience through the client-credentials grant.
   *
   * @return the compact JWS access token.
   * @throws IllegalStateException if the issuer refuses (the message carries the OAuth error code).
   */
  public String token(final String clientId, final String secret) {
    return token(clientId, secret, null);
  }

  /**
   * Get a token through the client-credentials grant, for {@code audience} (sent as RFC 8707
   * {@code resource}) or the default audience when null.
   *
   * @return the compact JWS access token.
   * @throws IllegalStateException if the issuer refuses (the message carries the OAuth error code).
   */
  public String token(final String clientId, final String secret, final String audience) {
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    form.put("client_id", clientId);
    form.put("client_secret", secret);
    if (audience != null) {
      form.put("resource", audience);
    }
    final HttpResponse<String> response = send(HttpRequest.newBuilder(endpoint("/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(formBody(form))).build());
    final JsonNode body = JSON.readTree(response.body());
    if (response.statusCode() != 200) {
      final JsonNode error = body.get("error");
      throw new IllegalStateException("token request refused: HTTP " + response.statusCode()
          + (error == null ? "" : " " + error.asString()));
    }
    return body.get("access_token").asString();
  }

  /**
   * Rotate every signing-key set (each algorithm gets a new active kid; retired keys stay published
   * for twice the token TTL, so tokens already issued keep verifying).
   *
   * @return the new active kid per JWS algorithm name, e.g. {@code {EdDSA=..., ES256=...}}.
   */
  public Map<String, String> rotateKeys() {
    final HttpResponse<String> response = send(HttpRequest.newBuilder(endpoint("/admin/keys/rotate"))
        .header("Authorization", "Bearer " + adminToken)
        .POST(BodyPublishers.noBody()).build());
    if (response.statusCode() != 200) {
      throw new IllegalStateException("key rotation failed: HTTP " + response.statusCode());
    }
    final Map<String, String> kids = new LinkedHashMap<>();
    JSON.readTree(response.body()).get("activeKids").properties()
        .forEach(entry -> kids.put(entry.getKey(), entry.getValue().asString()));
    return kids;
  }

  /** Stop the server and delete its data directory. */
  @Override
  public void close() {
    server.stop();
    try (Stream<Path> paths = Files.walk(dataDir)) {
      paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
    } catch (final IOException e) {
      // Best effort: a leftover temp directory is harmless.
    }
  }

  private URI endpoint(final String path) {
    return URI.create("http://127.0.0.1:" + port() + path);
  }

  private HttpResponse<String> send(final HttpRequest request) {
    try {
      return http.send(request, BodyHandlers.ofString());
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted", e);
    }
  }

  private static String formBody(final Map<String, String> form) {
    final StringBuilder body = new StringBuilder();
    form.forEach((key, value) -> {
      if (!body.isEmpty()) {
        body.append('&');
      }
      body.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append('=')
          .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    });
    return body.toString();
  }

  /** Configures a {@link TestIdp} before it starts. */
  public static final class Builder {

    private final List<String> args = new ArrayList<>();

    private Builder() {
    }

    /** Set the default audience (default {@code mini-kms}). */
    public Builder defaultAudience(final String audience) {
      args.add("--audience");
      args.add(audience);
      return this;
    }

    /** Sign tokens for {@code audience} with {@code algorithm} ({@code "EdDSA"} or {@code "ES256"}). */
    public Builder audienceAlgorithm(final String audience, final String algorithm) {
      args.add("--audience-algorithm");
      args.add(audience + "=" + algorithm);
      return this;
    }

    /** Set the access-token lifetime in seconds (default 300). */
    public Builder tokenTtlSeconds(final int seconds) {
      args.add("--token-ttl-seconds");
      args.add(Integer.toString(seconds));
      return this;
    }

    /** @return the started issuer; close it to stop it. */
    public TestIdp start() {
      try {
        final Path dataDir = Files.createTempDirectory("mini-idp-testkit");
        final List<String> all = new ArrayList<>(List.of(
            "--host", "127.0.0.1", "--port", "0", "--data-dir", dataDir.toString()));
        all.addAll(args);
        final ServerConfig config = ServerConfig.resolve(all.toArray(String[]::new), Map.of());
        final byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        final String adminToken = HexFormat.of().formatHex(random);
        final InMemoryServiceAccountDirectory directory = new InMemoryServiceAccountDirectory();
        final IdpServer server = IdpServer.create(config, adminToken, directory, Clock.systemUTC());
        server.start();
        return new TestIdp(server, directory, dataDir, adminToken);
      } catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    }
  }
}
