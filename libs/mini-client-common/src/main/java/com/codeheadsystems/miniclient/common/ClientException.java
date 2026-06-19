package com.codeheadsystems.miniclient.common;

/**
 * The single, generic client-side failure — the no-oracle error collapse for every family HTTP
 * client.
 *
 * <p>A request can fail in many ways (the service refused auth, returned a 4xx/5xx, was unreachable,
 * or sent a body that did not parse). The transport deliberately flattens <b>all</b> of them into
 * this one type with a generic message and <b>no status code or response body exposed</b>, so a
 * caller — and anything it renders — cannot distinguish "unknown principal" from "wrong secret" from
 * "server down". Detail that would leak an oracle is dropped; the cause is retained only for local
 * debugging and is never surfaced to a remote user.
 */
public final class ClientException extends RuntimeException {

  /** A failure with no underlying exception (e.g. a non-2xx status). */
  public ClientException(final String message) {
    super(message);
  }

  /** A failure wrapping a transport/parse cause (retained for local logs only, never surfaced). */
  public ClientException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
