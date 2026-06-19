package com.codeheadsystems.miniclient.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link HttpTransport}: JSON round-trips (single + list) and the no-oracle error
 * collapse, driven against a tiny in-process {@link HttpServer} stub.
 */
class HttpTransportTest {

  @JsonIgnoreProperties(ignoreUnknown = true)
  record Widget(String id, int size) {
  }

  private HttpServer server;
  private HttpTransport transport;
  private final AtomicReference<String> lastAuthHeader = new AtomicReference<>();

  @BeforeEach
  void setUp() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/one", exchange -> {
      lastAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
      respond(exchange, 200, "{\"id\":\"a\",\"size\":3,\"extra\":\"ignored\"}");
    });
    server.createContext("/many", exchange ->
        respond(exchange, 200, "[{\"id\":\"a\",\"size\":1},{\"id\":\"b\",\"size\":2}]"));
    server.createContext("/boom", exchange -> respond(exchange, 500, "{\"error\":\"secret detail\"}"));
    server.createContext("/garbage", exchange -> respond(exchange, 200, "not json at all"));
    server.start();
    final URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    transport = new HttpTransport(base, "test-token");
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  @Test
  void get_parsesJsonAndIgnoresUnknownFields() {
    final Widget widget = transport.get("/one", Widget.class);
    assertEquals("a", widget.id());
    assertEquals(3, widget.size());
  }

  @Test
  void get_sendsBearerToken() {
    transport.get("/one", Widget.class);
    assertEquals("Bearer test-token", lastAuthHeader.get());
  }

  @Test
  void getList_parsesJsonArray() {
    final List<Widget> widgets = transport.getList("/many", Widget.class);
    assertEquals(2, widgets.size());
    assertEquals("b", widgets.get(1).id());
  }

  @Test
  void non2xx_collapsesToClientException_withNoOracle() {
    final ClientException thrown =
        assertThrows(ClientException.class, () -> transport.get("/boom", Widget.class));
    // The server's "secret detail" body must NOT leak into the surfaced message.
    assertTrue(thrown.getMessage() != null && !thrown.getMessage().contains("secret"));
  }

  @Test
  void unparseableBody_collapsesToClientException() {
    assertThrows(ClientException.class, () -> transport.get("/garbage", Widget.class));
  }

  @Test
  void connectionRefused_collapsesToClientException() {
    // A port nothing listens on: a transport failure must look like every other failure.
    final HttpTransport dead = new HttpTransport(URI.create("http://127.0.0.1:1"), "t");
    assertThrows(ClientException.class, () -> dead.get("/one", Widget.class));
  }

  private static void respond(final com.sun.net.httpserver.HttpExchange exchange, final int status,
                              final String body) throws IOException {
    final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }
}
