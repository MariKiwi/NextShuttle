# Test deployment acceptance

Use a disposable **Nextcloud 35.0.2** with synthetic files and the exact candidate commit. No deployment has been made on the user's server. Follow deployment.md for packaging, secrets, private CA, proxy routes and cron.

## Automated evidence

| Workflow | Coverage | Limit |
|---|---|---|
| Relay checks | Python security/content tests, Compose/image build, PHP lint/event catalog, JS crypto, PHP/JS interoperability, built app artifact | Unit fixtures are not a security audit |
| Nextcloud integration | Actual 35.0.2 installation/migrations, unattended jobs, outgoing/incoming encryption, HTTPS private transport, import retry/rejection, owner isolation and native notification records; native session/CSRF checks | CI scanner transport is synthetic; no mobile device |
| Browser integration | Chromium desktop/mobile viewport, CSP, password-protected download/decrypt, encrypted upload, pinned inbox key mismatch, private admin/CSRF/export | Viewport emulation is not every physical browser/device |
| Real antivirus staging | Built isolated containers, real definitions, two-engine clean verdicts and harmless EICAR rejection | Does not prove detection of all malware |

Require successful results for the commit you install. Local sandbox runs may skip the Unix-socket test. Live scanners require outbound signature downloads and enough memory; absence of readiness blocks transfer preparation/import rather than bypassing inspection.

## Environment checks still required

1. Keep the public route restricted during staging. Confirm the existing proxy preserves `/nextshuttle/`, redirects the no-slash path, and cannot route public requests to private admin, management or ingestion APIs, including encoded/normalized paths. Check limits, HTTPS, no caching, logging redaction and private DNS/CA from the actual Nextcloud container.
2. Install the built app; verify Files action and sharing-sidebar action on files/folders. Create Alice, Bob and two global admins. Alice must see only her transfers/events; Bob cannot operate on Alice's node IDs or transfer IDs. Check denied groups, resharing restrictions, read/share/create permission changes and disabled public uploads.
3. Create a download with one use and one with a separate password. Open a fragment link in a clean browser, download/decrypt the original bytes, and confirm expiry/revoke/second claim fails. An interrupted authorized attempt consumes a use. Opening a second link in the same tab must select the second code.
4. Create an upload inbox with reusable password, small file/byte quotas and short lifetime. Upload an allowed file and wait for cron: validation and both scanners must finish before exactly one file appears in the destination. Test password rotation, expiry and explicit revoke (which discards pending uploads). Public visitors must never list/read prior submissions or choose a server path.
5. Test corrupt/tampered ciphertext, malformed allowed types, extension mismatch, unsafe archive entries, macros, active PDF content and harmless EICAR. Stop each scanner separately; deny updates until definitions are stale; restart workers mid-job. No such failure may import a file. Use no live malware.
6. Exercise native admin policy settings and separate private relay password-form login, logout and session expiry. Check cross-origin/private CSRF rejection, denied public admin access, audit export and acknowledged-history pruning. Verify backups restore Nextcloud keys/DB and relay history without reimporting files. Never reset a journal simply to clear continuity errors.
7. Register real Nextcloud mobile clients for both admins and the owner. Trigger page access, wrong code, upload, download, rejection, scanner failure/recovery, password/policy change and revoke. Check all enabled admins and the affected owner receive notifications, Bob does not, and lock-screen messages contain no filename/code. Unknown visits alert admins only.
8. Pause Nextcloud polling, generate events, resume and verify replay. Disconnect the relay after collection and ensure the local notification outbox still drains. Remove an admin/disable a user before delivery and verify audiences are rechecked. Handoff may repeat after a crash and cannot prove device display/read.
9. Measure real CPU/RAM/temp/disk consumption and queue latency. Check cron, signature age, capacity alerts, journal export/retention, native quotas and recovery from full disk. Get an independent security review before treating this development build as a hardened public production service.

## Feature coverage

Implemented: separate public/private relay, public base-path website, upload/download codes, browser/private encryption, native file/folder actions, owner dashboard, expiry/use limits, inbox quotas/password rotation, native policy settings, private admin, conservative content validation, dual independent scanners, durable collision-safe import, audit retention/export and admin/owner notification queues.

Environment acceptance and independent security review remain separate from implementation completeness. Antivirus and validators cannot guarantee every file is harmless. Browser-delivered encryption code remains trusted; see DESIGN.md.
