# Password-bound encryption (0.3)

New downloads and upload inboxes require an encryption password of at least the configured minimum (16 characters minimum). The creation form generates a random password by default. Share passwords separately from links. The owner dashboard displays the share code and encryption key independently; a full link contains both, never the password.

## Format and key derivation

The complete download binding is `D2.<id>.<access-token>.<32-byte-random-key>.<16-byte-salt>`. The compact share code omits the random key; the public form then requires it in the separate key field. The complete inbox binding is `U2.<id>.<32-byte-box-public-key>.<16-byte-salt>`; the compact version omits the public key. All binary components use URL-safe base64 without padding; IDs remain 128-bit hex. Parameters are fixed by version, never supplied by untrusted ciphertext.

Derive a 32-byte root with libsodium Argon2id v1.3, operations=3, memory=64 MiB, using UTF-8 password bytes and the 16-byte salt. Domain-separated keyed BLAKE2b-256 derives:

* Retrieval/upload authorization: `BLAKE2b("NextShuttle/v2/authorization\0" || binding, root)`.
* Download stream key: `BLAKE2b("NextShuttle/v2/file\0" || binding, root)`.
* Upload stream key: `BLAKE2b("NextShuttle/v2/upload\0" || binding || fresh_random_seed, root)`.

The authorization value is encoded as URL-safe base64 and sent to the relay, which stores its scrypt verifier. It is deliberately separate from the stream key; it is a replayable authorization credential, not a PAKE or a file key. The actual password and download encryption key never go to the relay. HTTPS and expiry/rate limiting remain necessary.

`NSH2D` contains the salt, secretstream header and authenticated chunk framing. `NSH2U` additionally contains the per-file seed sealed to the pinned inbox public key; Nextcloud needs its private box key and the encryption password to derive the stream key. Both retain the existing manifest, bounded chunks and mandatory FINAL record. Prefixes are authenticated as associated data. The binding includes transfer identity and key material, and the reader verifies the salt. A v2 operation rejects legacy envelopes and the wrong v2 direction; no fallback decryption is attempted. Fixed parameters and cryptographic domains must remain identical in PHP and JavaScript.

Uploads still require private authentication/decryption, content policy and both scanners before import. Download snapshots are scanned before encryption.

## Password rotation and compatibility

Changing a v2 upload password creates a new salt/code and authorization value. Share the new link. Received uploads retain the old salt in their authenticated envelope; encrypted password history allows import after rotation. History is bounded at 32 versions; create a new inbox after that. Rotation intent is durable and retried after relay outages. The private relay admin cannot change inbox passwords independently; use Nextcloud so encryption history stays synchronized.

Legacy D/U codes remain readable for existing transfers and are clearly labelled in the dashboard. They cannot gain password-bound encryption without republishing/recreating them. Passwordless legacy downloads can be revoked by the stricter effective password policy during background reconciliation. Source files are not deleted. Never describe an old share as protected by the v2 password scheme.

A full random-key download code already resists guessing. V2 additionally requires the password even if someone obtains the code and encrypted bytes. Weak human passwords can still be guessed offline after all other required material is obtained; use the generated random password. Browser-delivered JavaScript, Nextcloud and private ingestion remain trusted endpoints. These changes do not constitute an independent cryptographic audit.
