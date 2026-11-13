# NextShuttle implementation specification

## Deployment contract

* App ID `nextshuttle`, namespace `OCA\\NextShuttle`, Nextcloud 35.x only
  until later versions are tested. Initial installation target 35.0.2.
* Public origin `https://helios-public.tail43e437.ts.net`, path `/nextshuttle/`.
* Private origin `https://shuttle.helios.lan`, private API `/api/v1/`, admin `/`.
* The existing proxy routes to two distinct backend listeners. Public routing
  must never select the private listener, including through path normalization.
* Public frontend uses relative URLs beneath its configured base path. No public
  URL may contain a Nextcloud hostname, internal file path or internal username.
* HTTPS required on both origins. Validate the private CA; never disable peer or
  hostname verification. Tailscale complements application authentication.
* No relay-to-Nextcloud callbacks, mounted Nextcloud data or Nextcloud credentials.

## Trust model

Nextcloud is the trusted file endpoint. Files in ordinary Nextcloud storage
remain readable by Nextcloud. Transfer encryption protects file contents from
the relay/storage operator, not from Nextcloud, a compromised endpoint or a
recipient retaining a downloaded copy. This is end-to-end encryption between
Nextcloud and the recipient/sender browser, not user-device-to-user-device
encryption across Nextcloud itself.

The browser frontend delivered by the relay remains a trust dependency: a
compromised web server can replace its JavaScript and steal future secrets.
No CSP or integrity hash served by that same compromised origin solves this.
A separately distributed/verifiable client is required for that stronger threat
model. Relay admins can observe timing, size, IP addresses and access counts.

## Outgoing transfer

1. Resolve a file through the authenticated user's Nextcloud filesystem API.
   Recheck read/share permissions, resharing restrictions and admin policies.
2. Generate independent random transfer ID, access token and 256-bit content key.
3. Encrypt a snapshot, including its original filename and manifest, in bounded
   chunks using libsodium secretstream XChaCha20-Poly1305. Require the FINAL tag
   and reject truncation, reordering, appended bytes and invalid authentication.
4. Register an opaque relay transfer; push its ciphertext through the private
   API. Transition `pending -> ready` only after a complete size-checked write.
5. Show a copyable combined code (ID, access token, content key) or a link with
   all secrets in the URL fragment. Never place credentials in query strings.
   The browser submits only the access token to the relay in a request header.
6. Decrypt in the recipient browser and offer an attachment. Never render
   untrusted HTML, SVG or documents inline on either authenticated origin.

Transfer IDs are random 128-bit hex; access tokens contain at least 256 bits
of entropy. The relay stores token digests. A code is unique per shared snapshot;
limits govern retrievals. Single-use means one authorized retrieval attempt,
including one interrupted transfer, rather than provable delivery to a person.
Limits are claimed atomically before serving bytes. Revocation stops new access;
an already-running response may finish.

## Incoming upload inbox

The Nextcloud owner selects a writable destination folder by node ID. The app
creates a separate sodium box keypair per inbox, retains the private key in
Nextcloud protected storage, and sends only the public key to the relay.
Inbox passwords are reusable, individually rotatable, and never encryption keys.
The app must not send a global Nextcloud password to the relay.

After password authorization, the browser receives the inbox public key and
limits. It generates a fresh content key per file, secretstream-encrypts the file
and manifest, and seals the content key to the inbox public key with sodium
crypto_box_seal. Only Nextcloud can open that envelope. Credentials and upload
contents never authorize listing, retrieval, overwriting or deleting inbox files.

The private app polls encrypted uploads. It validates ownership and current folder
write permissions, safely decrypts to a bounded staging area, verifies FINAL,
validates filename/size, quarantines and requires clean verdicts from both ClamAV
and a second independent antivirus engine, and only then imports via
Nextcloud's filesystem API. Use unique names, never overwrite by default. A durable
receipt keyed by upload ID prevents duplicate imports after retries. Acknowledge
only after the file and receipt are committed. Missing/deleted owners and folders
must fail closed. Revoke imports if required permission has been removed.

Inbox expiry disables new authorizations AND unfinished uploads. Already-complete
uploads have their own bounded retention deadline so an inbox expiring while
Nextcloud is offline does not silently lose accepted files. Relay storage quotas
still apply. Expired retained uploads are eventually deleted even if not imported.

## Nextcloud user interface

* Files context action and Sharing sidebar action: Share with NextShuttle.
* Folder action: Receive files with NextShuttle.
* Navigation page: authenticated user's downloads and inboxes only; never trust
  client-supplied owner IDs. Filter every query and mutation by session UID.
* Display preparing/available/expired/revoked/import pending/import failed states,
  creation/expiry, usage, retryable errors, revoke, rotate password and copy code.
* Admin section: private/public URLs, credentials/certificate configuration,
  connectivity status, group eligibility, TTL/default TTL, password rules,
  file/inbox/user/global quotas, download limits, upload scanning requirements,
  retention and policy changes affecting existing transfers.
* Private relay admin: authenticated operational overview, capacity, failed jobs,
  revocation, cleanup and credential rotation. No file contents or decryption keys.

Use Nextcloud's supported Files/Sharing packages, ISettings interfaces, migrations,
IConfig/ICrypto facilities and background jobs. No direct reads of its data folder.
Preserve CSRF checks, session auth and native permission restrictions. Encryption
keys must never appear in activity/audit events. Deleting app configuration must
not silently destroy undecrypted uploads: provide an explicit recovery/export plan.

## Security requirements

Private API: distinct random service token, HTTPS, private network binding, and
preferably mutual TLS at the private proxy. Relay administrator credentials must
be separate from the app token. A single installation's service token may manage
all its relay records, so end-user authorization stays in Nextcloud. Future
multi-installation support needs scoped installation identities.

Passwords: scrypt with random salts, fixed resource cost, constant-time compare;
rate-limit before hashing to bound CPU exhaustion. Bound request body lengths,
connections, timeouts, object counts, disk reservations and retention. Global
limits complement per-source limits; forwarded IP headers are not trusted by
default. Credential rotation invalidates subsequent access immediately.

Container: non-root UID, read-only root, no added capabilities, no Docker socket,
limited writable data volume, resource limits, pinned dependency/build review,
no request/access logs with credentials, no runtime CDN/analytics. Use a dedicated
public origin if stronger isolation from sibling public apps is required: a base
path shares the browser origin and service worker/cookie risks with those apps.

Serve a restrictive CSP and Referrer-Policy: no-referrer, nosniff, no-store for
sensitive responses, no cross-origin API access and no public administrator cookies.
Reject cross-origin browser mutations. TLS protects credentials but is additional
to file encryption. Backups include ciphertext and metadata; Nextcloud key backup
is essential for recovery. Document storage deletion and backup retention honestly.

## API v1 initial relay

Public listener uses `/nextshuttle/api/v1/` only. Private listener uses `/api/v1/`.
Authorization headers never belong in URLs. All object IDs are validated hex.

| Side | Method / path | Meaning |
|---|---|---|
| Private | POST /downloads | Reserve a download and return its access token once |
| Private | PUT /downloads/{id}/blob | Write the reserved opaque ciphertext once |
| Public | POST /downloads/{id}/fetch | Authorize and retrieve the ciphertext |
| Private | POST /inboxes | Create inbox with password and public encryption key |
| Public | POST /inboxes/{id}/uploads | Reserve one bounded encrypted upload |
| Public | PUT /uploads/{id}/blob | Complete reserved upload with one-time upload token |
| Private | GET /uploads | List completed uploads awaiting import |
| Private | GET /uploads/{id}/blob | Retrieve encrypted upload for import |
| Private | DELETE /uploads/{id} | Acknowledge/remove uploaded ciphertext |
| Private | GET /transfers | Operational metadata, not end-user authorization |
| Private | DELETE /downloads/{id} | Revoke download |
| Private | DELETE /inboxes/{id} | Revoke inbox and pending uploads |
| Private | POST /inboxes/{id}/password | Rotate inbox password |
| Private | POST /cleanup | Remove expired ciphertext and stale reservations |

## Release gates

The initial relay is an independently tested foundation, not a complete product.
Before a deployable release: implement/test the browser and PHP crypto together,
Nextcloud app authorization/settings/UI/jobs, private relay admin UI, real proxy
prefix behavior, app package installation against 35.0.2, corruption/interruption
and race testing, credential rotation/recovery, operational limits, and external
security review. Mandatory quarantine and dual-antivirus acceptance gates are
specified in [upload-protection.md](upload-protection.md). Fail closed if the
crypto format is unsupported. Never claim
compatibility based solely on PHP syntax checks or a mocked Nextcloud environment.

## Official implementation references

* https://docs.nextcloud.com/server/stable/developer_manual/basics/controllers.html
* https://docs.nextcloud.com/server/stable/developer_manual/basics/storage/filesystem.html
* https://docs.nextcloud.com/server/stable/developer_manual/basics/backgroundjobs.html
* https://docs.nextcloud.com/server/stable/developer_manual/digging_deeper/settings.html
* https://docs.nextcloud.com/server/stable/developer_manual/release_notes/previous/upgrade_to_33.html
* https://doc.libsodium.org/secret-key_cryptography/secretstream
