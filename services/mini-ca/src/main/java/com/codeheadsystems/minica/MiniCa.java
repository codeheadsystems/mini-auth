package com.codeheadsystems.minica;

/**
 * Placeholder for mini-ca, a future internal certificate authority (mTLS between the minis,
 * workload identity in the homelab).
 *
 * <p><b>Roadmap only.</b> This module deliberately contains no certificate logic. It reserves the
 * name and package so the umbrella build and the direction doc can refer to it as a real,
 * compiling module before any code exists. See {@code docs/DIRECTION.md}.
 */
public final class MiniCa {

  /** Marks this module as a not-yet-implemented roadmap track. */
  public static final boolean IMPLEMENTED = false;

  private MiniCa() {
  }
}
