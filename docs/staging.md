# Staged test deployment

Current milestone: relay API, initial Nextcloud event bridge and private scanning
adapters. This is NOT a complete transfer release. No deployment has been made
on the user's server. Use synthetic data and a disposable Nextcloud 35.0.2 clone.

## Automated checks

Run `python3 -m unittest discover -s tests -v`. CI also validates Compose, builds
the relay image, lints PHP, checks the event catalog and packages the development
notification app as an Actions artifact. Scanner tests use a simulated ClamAV
daemon and LMD report fixtures; they are not live antivirus acceptance tests.
A UNIX-socket protocol test is skipped if the local sandbox prohibits sockets.

## Private relay

Follow deployment.md. Keep the public route unpublished or restricted to your
private network during staging. Preserve `/nextshuttle/` when testing the public
listener and ensure its virtual host cannot select the private listener. Confirm
private HTTPS connectivity and CA trust from the staging Nextcloud container.

The landing page currently returns a JSON development status, not a transfer UI.
Test opaque storage with synthetic bytes only. Successful upload does not import
anything into Nextcloud. Test private event reads/acknowledgements, wrong-code
events and rejection of public management routes or missing credentials.

## Initial Nextcloud app

Enable the Notifications app and create at least two test users: admin and owner.
Install `nextcloud/nextshuttle` as `custom_apps/nextshuttle` in the staging instance
with web-server-readable permissions. Do not overwrite an unrelated directory.
As the web-server user run:

```sh
php occ app:enable nextshuttle
php occ nextshuttle:configure
```

The configure command prompts invisibly for the relay token and stores it using
Nextcloud ICrypto. Do not pass credentials in URL/query strings or command-line
arguments. The target is pinned to `https://shuttle.helios.lan/`. Import the
private root CA through Nextcloud's supported certificate facilities. TLS uses
its verified bundle. Optional mutual-TLS identity paths are trusted system
settings `nextshuttle_client_cert` and `nextshuttle_client_key`. Never disable
certificate verification or globally permit local remote requests as a workaround.

For initial synthetic transfers, run this before collecting associated events:

```sh
php occ nextshuttle:owner OBJECT_ID USER_ID
```

Normal transfer creation must eventually make these mappings automatically.
The command does not reassign already-collected events. Let ordinary cron run.
Check Administration → Additional settings → NextShuttle for configuration,
last collection and cursor. Open the event page as admin, owner and another user;
the other user must not see the owner's events.

Trigger a landing-page visit, a wrong code for a ready synthetic transfer, an
opaque upload and a private `scan_unavailable` report. Verify all admins and the
mapped owner receive appropriate notifications, without duplicate recipients
when the owner is also admin. Test an actual registered mobile client. Pause
collection, generate events and resume to verify replay. Disconnect the relay
after collection and verify existing outbox delivery continues. Test role/user
removal and restarts. Check records contain no attempted code or token.

Do not reset relay volumes to silence journal-continuity errors. Reconcile
histories deliberately; audit export/retention tooling remains a release gate.

## Free private scanner workers

The selected pair is ClamAV plus Linux Malware Detect's native engine. LMD is
GPLv2 and adds independent Linux/web-malware detection; its coverage is narrower
than a broad commercial antivirus product. It is not comprehensive cross-platform
protection. Disable its ClamAV integration so the second pass is independent.

The adapter targets LMD 2.0.1 JSON schema 1.2. Source reviewed:
`rfxn/linux-malware-detect` commit `88dd694891ac52a11a6e6ac45546545d5b1c813f`.
Pin/review the engine build before installation. It disables ClamAV/YARA passes,
root-owner exclusions, cleaning, alert channels, auto-updates during scans and
post-scan executable hooks. HEX depth covers the 32 MiB cap. Verify global ignore
rules do not skip staging inputs. Update signatures separately from scan jobs.

ClamAV uses a private UNIX socket and INSTREAM with strict daemon settings from
upload-protection.md. LMD requires nonempty, recent version/hash/HEX signature
files. The default definition age limit is 48 hours; verify update behavior and
clocks. A missing/skipped/old/wrong-file/non-native/unknown report blocks clearance.

Keep scanners out of the public relay image. Run private workers with read-only
input, no processing-time network, restricted privileges and resource limits.
Measure actual scanner RAM/CPU use before choosing concurrency. The initial
ScanGate accepts only nonempty valid UTF-8 `.txt` files, validates safe names,
requires both verdicts and rechecks hashes after each scan. Other formats are
blocked pending validators. Approval does not import files: the future importer
must import the identical immutable bytes and recheck ownership/policy.

Test both actual engines independently with harmless EICAR and ordinary text,
stale updates, outages, excluded/skipped files, timeouts and modified content.
Never use live malware. Confirm rejected files cannot be imported, previewed,
downloaded or reshared. The adapters have not yet passed these live checks.

## Remaining end-to-end gates

Browser/PHP encryption interoperability; Files/share actions; automatic owner
mapping; quarantine/decryption/import worker and scan-to-event wiring; editable
policies; private relay admin UI; durable import receipts; audit export/retention;
real proxy and recovery tests; security review. Passing the notification milestone
does not authorize public file transfers before these are implemented and tested.
