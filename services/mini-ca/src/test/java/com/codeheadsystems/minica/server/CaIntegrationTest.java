package com.codeheadsystems.minica.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minica.ca.Pem;
import com.codeheadsystems.minica.support.TestCsr;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Full HTTP flow: a registered admin issues, renews, and revokes leaf certificates, and the issued
 * leaf chains to the CA root served at {@code /ca}. Covers the deny cases (no token, bad CSR).
 */
class CaIntegrationTest {

  private static final String ADMIN = "ca-admin-token";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private CaServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = CaServer.create(config, ADMIN, Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newHttpClient();
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void issuesALeafThatChainsToThePublishedRoot() throws Exception {
    final HttpResponse<String> issued = post("/issue",
        body(TestCsr.create("alpha.svc").csrPem(), 3600, "alpha.svc"), ADMIN);
    assertEquals(201, issued.statusCode(), issued.body());
    final JsonNode body = MAPPER.readTree(issued.body());

    final X509Certificate leaf = parse(body.get("certificate").asString());
    final X509Certificate root = parse(get("/ca", null).body());          // public trust anchor
    leaf.verify(root.getPublicKey());                                     // chains to the CA
    assertEquals(body.get("caCertificate").asString(), get("/ca", null).body());
    assertTrue(body.get("serial").asString().length() > 0);

    // The issuance is recorded in the log.
    final JsonNode log = MAPPER.readTree(get("/log", ADMIN).body());
    assertTrue(log.valueStream().anyMatch(e -> e.get("serial").asString().equals(body.get("serial").asString())));
  }

  @Test
  void revokeAddsTheSerialToThePublicRevocationList() throws Exception {
    final JsonNode issued = MAPPER.readTree(post("/issue", body(TestCsr.create("b.svc").csrPem(), 3600, null), ADMIN).body());
    final String serial = issued.get("serial").asString();

    assertEquals(200, post("/revoke", "{\"serial\":\"" + serial + "\",\"reason\":\"test\"}", ADMIN).statusCode());
    final JsonNode revocations = MAPPER.readTree(get("/revocations", null).body());
    assertTrue(revocations.valueStream().anyMatch(r -> r.get("serial").asString().equals(serial)));
  }

  @Test
  void renewIssuesAFreshCertAndRevokesThePrevious() throws Exception {
    final String firstSerial = MAPPER.readTree(
        post("/issue", body(TestCsr.create("c.svc").csrPem(), 3600, null), ADMIN).body()).get("serial").asString();

    final HttpResponse<String> renewed = post("/renew",
        "{\"csr\":" + quote(TestCsr.create("c.svc").csrPem()) + ",\"previousSerial\":\"" + firstSerial + "\"}", ADMIN);
    assertEquals(201, renewed.statusCode(), renewed.body());
    final String newSerial = MAPPER.readTree(renewed.body()).get("serial").asString();
    assertNotEquals(firstSerial, newSerial);

    // The previous cert is now revoked.
    final JsonNode revocations = MAPPER.readTree(get("/revocations", null).body());
    assertTrue(revocations.valueStream().anyMatch(r -> r.get("serial").asString().equals(firstSerial)));
  }

  @Test
  void issuanceRequiresTheAdminToken() throws Exception {
    final String b = body(TestCsr.create("d.svc").csrPem(), 3600, null);
    assertEquals(401, post("/issue", b, null).statusCode());
    assertEquals(401, post("/issue", b, "wrong-token").statusCode());
    assertEquals(201, post("/issue", b, ADMIN).statusCode());
  }

  @Test
  void aMalformedCsrIsRejectedWithGeneric400() throws Exception {
    final HttpResponse<String> response = post("/issue", "{\"csr\":\"not-a-csr\"}", ADMIN);
    assertEquals(400, response.statusCode());
    assertFalse(response.body().contains("not-a-csr"), "no echo / oracle of the bad input");
  }

  @Test
  void caCertificateIsPublic() throws Exception {
    final HttpResponse<String> response = get("/ca", null);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("BEGIN CERTIFICATE"));
  }

  // ---- helpers -------------------------------------------------------------------------------

  private static String body(final String csrPem, final long ttl, final String san) {
    final String sans = san == null ? "" : ",\"sans\":[\"" + san + "\"]";
    return "{\"csr\":" + quote(csrPem) + ",\"ttlSeconds\":" + ttl + sans + "}";
  }

  private static String quote(final String value) {
    return MAPPER.writeValueAsString(value);
  }

  private static X509Certificate parse(final String pem) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(Pem.decode(pem)));
  }

  private HttpResponse<String> post(final String path, final String json, final String token) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json").POST(BodyPublishers.ofString(json));
    if (token != null) {
      builder.header("Authorization", "Bearer " + token);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> get(final String path, final String token) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (token != null) {
      builder.header("Authorization", "Bearer " + token);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }
}
