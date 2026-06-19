# Sequence — KMS wrap-on-save (the recursive integration)

> How the family secures **its own** signing keys: a `DocumentStore` decorator envelope-wraps each
> private key under mini-kms so **no plaintext key touches disk.** Concept:
> [`envelope-encryption-and-kms.md`](../concepts/envelope-encryption-and-kms.md). Lab:
> [`06`](../tutorials/06-protect-the-signing-keys.md).

```mermaid
sequenceDiagram
    autonumber
    participant SVC as SigningKeyService<br/>(mini-token)
    participant WS as KmsSigningKeyStore<br/>(decorator)
    participant KC as KmsClient
    participant KMS as mini-kms (data plane)
    participant FS as JsonStore (disk, 0600)

    rect rgb(245,245,245)
    Note over SVC,FS: SAVE — a new/rotated signing key is persisted
    SVC->>WS: save(SigningKeys{activeKid, records[ kid, privatePkcs8, publicSpki ]})
    loop each record
        WS->>KC: encrypt(keyGroup, pkcs8Bytes, aad = kid)
        KC->>KMS: ENCRYPT {keyGroup, plaintext, aad}  (data-plane token)
        Note right of KMS: fresh DEK → AES-GCM → wrap DEK under active KEK;<br/>aad=kid bound into the ciphertext
        KMS-->>KC: ciphertext
        KC-->>WS: ciphertext
        Note right of WS: privatePkcs8 := "kms1:" + base64(ciphertext)
    end
    WS->>FS: delegate.save(...)  → atomic temp → ATOMIC_MOVE → 0600
    Note right of FS: on disk: only "kms1:<ciphertext>" — never plaintext
    end

    rect rgb(245,245,245)
    Note over SVC,FS: LOAD — keys are unwrapped into memory at startup
    SVC->>WS: load()
    WS->>FS: delegate.load()
    FS-->>WS: SigningKeys (private fields are "kms1:…")
    alt any field starts with "kms1:"
        loop each wrapped record
            WS->>KC: decrypt(ciphertext, aad = kid)
            KC->>KMS: DECRYPT {ciphertext, aad}
            Note right of KMS: unwrap DEK under the KEK version named in the blob;<br/>aad MUST equal kid or decrypt fails
            KMS-->>KC: pkcs8Bytes
            KC-->>WS: pkcs8Bytes
        end
    else no wrapped fields
        Note right of WS: pass through (plaintext mode)
    end
    WS-->>SVC: SigningKeys (plaintext PKCS#8, in memory only)
    end
```

**Key points**

- **The decorator is transparent.** `SigningKeyService` deals in normal PKCS#8; it has *no idea* the
  keys are wrapped. The `KmsSigningKeyStore` decorator sits between it and the on-disk `JsonStore`.
- **`kid` as AAD** binds each wrapped key to its record: a wrapped blob can't be swapped between
  records, because decrypt with the wrong `kid` fails (AEAD). This is the *encryption context* idea.
- **The `kms1:` envelope** is just the marker + base64 ciphertext stored in the private-key field.
  Without `--kms-*`, the field is plaintext base64 and no mini-kms call happens.
- **Rotation (`rewrap`)** decrypts-under-old, re-encrypts-under-new *inside mini-kms* — the plaintext
  key never leaves the KMS. (KEK rotation; see the concept doc.)
- **Recursive, and reused verbatim** by mini-idp, mini-oidc, *and* mini-ca (whose CA private key is
  just a PKCS#8 in a one-record `SigningKeys`).

> This is wired and end-to-end runnable (lab 06). It is the family's keystone integration: envelope
> encryption, the `DocumentStore` SPI, and `kid`-as-AAD all show up at once.
