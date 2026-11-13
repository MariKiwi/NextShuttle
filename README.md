# NextShuttle

Private Nextcloud, public encrypted file transfers.

Target: **Nextcloud 35.0.2**. Public URL:
`https://helios-public.tail43e437.ts.net/nextshuttle/`.
Private relay: `https://shuttle.helios.lan/`.

This repository is under development. See [DESIGN.md](docs/DESIGN.md) for the
security boundary, protocol, requirements and release gates. Do not expose an
unfinished build publicly. A working component is not a security audit.

The relay has separate public and private applications. It never receives a
Nextcloud credential or a file decryption key. Nextcloud initiates every
connection. Expiry is checked on access, independently of cleanup jobs.

## Current implementation

The initial relay implements bounded opaque-object storage, unique download
credentials, password-protected upload inboxes, expiry, revocation, atomic
download limits, persistent rate limiting, storage reservations and private
management. The Nextcloud app and browser encryption integration are not yet
implemented; the relay API deliberately accepts **ciphertext only** and must
not be exposed as a general plaintext file-sharing server.

Run the security behavior tests with `python3 -m unittest discover -s tests -v`.
See [deployment.md](docs/deployment.md) before configuring the container.
