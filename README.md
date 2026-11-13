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
management and a durable audit journal. The initial Nextcloud app includes an
event page, admin status and native notifications for admins and mapped owners.
Private ClamAV/native-LMD scan adapters and a strict text-file test gate exist.
File sharing, browser encryption and import integration remain unfinished;
the relay API deliberately accepts **ciphertext only** and must
not be exposed as a general plaintext file-sharing server.

Run the security behavior tests with `python3 -m unittest discover -s tests -v`.
See [deployment.md](docs/deployment.md) before configuring the container.

## Mandatory upload protection

Before an end-to-end test deployment, uploads must pass private quarantine,
authenticated decryption, strict content policy, **ClamAV and a second independent
antivirus engine** before Nextcloud import. Scanner errors, stale definitions and
uninspectable files must block import. Adapters exist, but the complete
quarantine/decryption/import pipeline is not yet integrated;
see [upload-protection.md](docs/upload-protection.md) for requirements and tests.
See [staging.md](docs/staging.md) for staged testing and remaining release gates,
and [events-and-notifications.md](docs/events-and-notifications.md) for event
audiences, offline replay, push prerequisites and delivery semantics.
