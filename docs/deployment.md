# Test deployment

Deploy the exact reviewed `nextshuttle-foundation` commit to a disposable Nextcloud **35.0.2** first. The existing reverse proxy remains operator-managed. This is a single-host SQLite deployment; do not put the relay database on NFS or scale writable replicas across hosts.

## Secrets and containers

Generate three independent credentials on the Docker host. Never commit them:

```sh
mkdir -p secrets
chmod 700 secrets
umask 077
python3 - <<'PY'
from pathlib import Path
import secrets
for name in ('service_token', 'scanner_token', 'admin_password'):
    p = Path('secrets') / name
    if p.exists():
        raise SystemExit('Refusing to replace existing credential: ' + name)
    p.write_text(secrets.token_urlsafe(48) + '\n')
    p.chmod(0o600)
PY
```

Allow container UID 10001 to read each secret using ownership or an ACL appropriate to your Docker/user namespace mapping (for ordinary rootful Docker, `setfacl -m u:10001:r secrets/service_token secrets/scanner_token secrets/admin_password`). Keep the parent directory private. Do not make production credentials world-readable. CI fixture credentials are deliberately synthetic.

```sh
docker compose config --quiet
docker compose build
docker compose up -d
docker compose logs --tail=50 shuttle-signatures shuttle-clamd shuttle-ingestion
```

The first signature download and ClamAV database load can take several minutes. Both engines must be ready; a running HTTP process alone does not prove readiness. Failed updates retry, and ClamAV definitions or an LMD upstream verification older than 48 hours block scanning. Budget about 6 GiB across configured container memory limits, plus Nextcloud and the host. LMD is free software with narrower Linux/web-malware coverage; it is not a broad commercial scanner replacement.

Root filesystems are read-only, privileges dropped, and plaintext staging uses bounded tmpfs. Disable or encrypt host swap and protect host crash dumps if plaintext-at-rest exposure is in scope. The public relay has no service secrets. The isolated signature updater has no uploaded files or application credentials.

## Existing reverse proxy

The NPM container reaches backend ports through its host gateway **172.19.0.1**. Compose defaults to binding only that address; `NEXTSHUTTLE_BIND_IP` can select a different existing host interface. Do not use `0.0.0.0`. No direct NPM-to-NextShuttle Docker network connections are required.

| HTTPS frontend | HTTP backend | Path |
|---|---|---|
| helios-public.tail43e437.ts.net/nextshuttle/ | 172.19.0.1:9080 | Preserve `/nextshuttle/` |
| shuttle.helios.lan/ | 172.19.0.1:9081 | Preserve root and `/api/v1/` |
| shuttle.helios.lan/ingestion/v1/ | 172.19.0.1:9082 | Preserve `/ingestion/v1/`; more specific route |

The gateway address must exist on the Docker host before starting Compose. Restrict access to these backend ports to your proxy/network policy. Keep private/scanner routes absent from every public virtual host and tunnel. A host-interface bind does not replace firewall policy. Leave the ingestion worker on its isolated scanner network. The small `shuttle-scanner-gateway` publishes port 9082 and forwards only the two ingestion endpoints into that internal network; Docker does not publish the worker’s ports directly on an internal-only network. It has no credentials, disables request-body buffering, and uses bounded tmpfs for temporary paths.

Require verified HTTPS, preserve Authorization, disable caching and API CORS, and exclude authorization headers, bodies and codes from proxy logs. Use finite connection/read/send limits and a body allowance of **34 MiB ciphertext** (32 MiB plaintext hard cap). Requests require a unique Content-Length; chunked request bodies are rejected. Disable automatic retries for mutations and download claims. Add per-client abuse limits at the proxy: application limits see the proxy source IP and do not trust X-Forwarded-For. Limit request-header sizes too. Do not enable content previews or inline execution of received files.

Private relay administration uses a password form with the separate `admin_password`, only over private HTTPS. There is no HTTP Basic authentication. Server-side sessions use Secure, HttpOnly, SameSite=Strict host-only cookies, rotate on sign-in, expire after 30 idle minutes or eight hours total, and are invalidated on logout or relay restart. Login and mutations require origin and session-bound CSRF checks. Do not add NPM Basic Auth or interactive proxy authentication to the service API. Management API uses `service_token`; ingestion uses `scanner_token`. Add mutual TLS at the private proxy if required, while preserving browser admin access through a separately controlled client identity.

## Nextcloud app

Download the `nextshuttle-development` artifact from the successful **Relay checks** workflow for the chosen commit. It contains the built app archive. Alternatively, run `npm ci && npm run build` in the repository before copying `nextcloud/nextshuttle` into the staging instance's `custom_apps/nextshuttle`. Do not overwrite an unrelated directory. Set ownership/read permissions for the Nextcloud web user.

Run as that web user from the Nextcloud directory:

```sh
php occ app:enable notifications
php occ app:enable nextshuttle
php occ nextshuttle:configure
```

The configure command prompts invisibly for the relay and scanner tokens. Alternatively use Administration settings → NextShuttle. Credentials and transfer secrets are encrypted with Nextcloud ICrypto. Leave existing secret fields blank to keep them. Never put secrets in URLs, shell arguments or screenshots.

Nextcloud initiates connections to the fixed private hostname. Import/trust your private root CA, or configure server-only `nextshuttle_ca_file` pointing to a readable PEM bundle. Optional `nextshuttle_client_cert` and `nextshuttle_client_key` supply a private client identity. Never disable TLS verification. Enable Nextcloud file locking, configure normal background cron, and confirm private DNS/connectivity from the actual Nextcloud container. PHP's temporary directory must be private, adequately sized, and outside web roots; encryption/decryption uses private temporary files there.

Set sharing eligibility, maximum/default lifetime, file size, quotas, allowed types and password policy in the app's admin section. Native sharing restrictions also apply. Default plaintext limit is 16 MiB; hard maximum 32 MiB. Default lifetime is one day, hard maximum seven days. Queued transfers and policy revocations advance through background jobs. Job eligibility is 60 seconds; actual execution follows Nextcloud cron cadence.

## Retention, recovery and backups

Expiry blocks new public access immediately. An in-progress download may finish and an interrupted claim consumes a use. Downloads default to one use. Inbox budgets are lifetime reservations, not replenished by import. Incomplete reservations expire after 15 minutes but consume the inbox's lifetime budget. Completed incoming ciphertext remains for up to seven days after receipt even if its inbox expires. Explicit inbox revocation discards pending uploads. Cleanup runs each minute on the private service.

Back up the relay data volume and the Nextcloud database **together with Nextcloud config.php/ICrypto secret material**. Losing private keys makes pending uploads unrecoverable. Protect backups as secrets and test restoration. Deleting a file is logical deletion, not physical erasure or backup removal.

The relay journal is bounded at 100,000 records and fails closed when full. Export and verify history in private administration before pruning acknowledged older events. Emergency admin access/export remains available at capacity; an access event may not fit at that boundary. Audit storage is not tamper-proof against relay compromise. Use independent append-only logging for that threat. Never reset the relay volume to silence journal-continuity errors; reconcile histories deliberately.

Finish [staging.md](staging.md) before opening the public route.

Native LMD scans hold a shared definition lock. The updater holds an exclusive lock and records hashes of the complete definition set after a successful upstream check. Missing/stale receipts, partial updates or changed definition files block clearance; archive publication timestamps alone do not represent the last update check.

Incoming creation uses exclusive `xb` mode through Nextcloud storage and updates its native file cache. Storage backends that cannot provide exclusive creation block import. Test your actual local/external/encrypted storage backend during staging; no overwrite fallback is provided. LMD verification age measures a successful upstream update check; it does not imply that the publisher released new signatures that day. Engine and signature versions accompany scan receipts.


## Upgrading to 0.3

Build/package the app with its JavaScript, replace the existing app code in `custom_apps/nextshuttle` using your normal app update procedure, and run `php occ upgrade` as the Nextcloud web user. Preserve Nextcloud data/configuration and the relay volume/secrets. The new migration adds nullable visitor metadata columns. Rebuild/recreate the relay services and reload Nextcloud to load the new JS/CSS. This does not require changing your NPM host-gateway routing.

Create a fresh share to use v2 password-bound encryption; existing legacy links cannot be upgraded in place. The creation form generates a password; retain it and send it separately. For original visitor IPs and country, complete [visitor-attribution.md](visitor-attribution.md), including local database download and authenticated trusted-proxy headers. Unknown/private proxy locations remain explicit until the real-IP chain is correctly configured. Passwords for v2 inboxes must be rotated in Nextcloud, not the relay admin.
