/**
 * The raw symmetric crypto — the <b>only</b> place AES-GCM happens.
 *
 * <p>{@link com.codeheadsystems.minikms.crypto.AesGcm} is AES-256-GCM (AEAD) with a fresh random
 * 96-bit nonce per encryption (never caller-supplied — nonce reuse under one key catastrophically
 * breaks GCM), and {@link com.codeheadsystems.minikms.crypto.EnvelopeFormat} is the self-describing
 * binary container (version + algorithm id + nonce + ciphertext+tag) every higher layer nests inside.
 * Decryption failures collapse to one generic error — never an oracle for why.
 */
package com.codeheadsystems.minikms.crypto;
