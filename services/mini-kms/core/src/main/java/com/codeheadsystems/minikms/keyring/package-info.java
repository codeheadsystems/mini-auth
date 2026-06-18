/**
 * The keyring: key management and the nested envelope formats, all I/O-free.
 *
 * <p>The key hierarchy is {@code passphrase --Argon2id--> root key --wraps--> KEK versions --wrap-->
 * DEKs --AES-GCM--> data}. Start with {@link com.codeheadsystems.minikms.keyring.KekId} and
 * {@link com.codeheadsystems.minikms.keyring.KekEnvelope} (the client-facing "which KEK wrapped me" +
 * authenticated ciphertext), then {@link com.codeheadsystems.minikms.keyring.LocalKeyring} — the heart,
 * implementing both the data-plane {@code MasterKeyProvider} (wrap/unwrap/encrypt/decrypt, binding the
 * {@link com.codeheadsystems.minikms.keyring.KekId} into the AEAD AAD) and the control-plane
 * {@code KeyringManager} (create/rotate/disable/destroy). {@link
 * com.codeheadsystems.minikms.keyring.KeystoreIntegrity} HMACs the keystore metadata so offline
 * tampering is detected.
 */
package com.codeheadsystems.minikms.keyring;
