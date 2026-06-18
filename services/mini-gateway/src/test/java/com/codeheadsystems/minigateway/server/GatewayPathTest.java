package com.codeheadsystems.minigateway.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Path canonicalization for route matching. The forward-auth gateway must see the same path the
 * upstream will resolve, or a hostile {@code /public/../admin} (or its percent-encoded form) could
 * dodge a prefix rule and fall through to a permissive one.
 */
class GatewayPathTest {

  @Test
  void collapsesDotAndDoubleSlashSegments() {
    assertEquals("/a/b", GatewayHandlers.normalizePath("/a/./b"));
    assertEquals("/a/c", GatewayHandlers.normalizePath("/a/b/../c"));
    assertEquals("/a/b", GatewayHandlers.normalizePath("/a//b"));
    assertEquals("/admin", GatewayHandlers.normalizePath("/admin/"));
    assertEquals("/", GatewayHandlers.normalizePath("/"));
    assertEquals("/", GatewayHandlers.normalizePath(""));
  }

  @Test
  void decodesOnceSoEncodedTraversalCannotHide() {
    // %2e%2e -> "..", %2f -> "/": the encoded form canonicalizes to the SAME path the upstream sees.
    assertEquals("/admin", GatewayHandlers.normalizePath("/public/%2e%2e/admin"));
    assertEquals("/admin/x", GatewayHandlers.normalizePath("/admin%2Fx"));
  }

  @Test
  void refusesTraversalAboveRootAndNulBytes() {
    assertNull(GatewayHandlers.normalizePath("/../etc/passwd"));
    assertNull(GatewayHandlers.normalizePath("/a/../../b"));
    assertNull(GatewayHandlers.normalizePath("/a%00b"));
  }
}
