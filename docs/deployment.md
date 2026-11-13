# Development deployment

**Not a public release.** The current relay is an API foundation. Browser crypto,
Files integration, the complete ingestion pipeline and the private relay admin
interface remain release gates. The initial notification app can be tested
separately; see [staging.md](staging.md).
The mandatory private quarantine and dual-antivirus pipeline is also a release
gate; see [upload-protection.md](upload-protection.md). A successful opaque upload
is not a malware clearance or approval to import into Nextcloud.

The image provides two execution modes. Compose runs them as two services from
one image so public and private HTTP route registration cannot overlap. Both use
one local Docker volume and SQLite. This initial topology is single-host only;
do not use SQLite on NFS or scale replicas across hosts.

Generate a service credential, never commit it:

```sh
mkdir -p secrets
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > secrets/service_token
```

Ensure UID 10001 can read the secret mounted by Compose, using ownership or an
ACL appropriate to your Docker/user-namespace configuration. Keep its parent
directory private. Do not make the credential world-readable to work around a
permission error. The named volume is initialized with container UID 10001.

```sh
docker compose build
docker compose up -d
```

Both listeners publish to **127.0.0.1 only**, at 9080 (public) and 9081 (private).
Docker-host loopback is not reachable from a separate reverse-proxy container.
For a containerized proxy, attach it to the corresponding backend networks and
use `shuttle-public:8080` and `shuttle-private:8081` instead. Do not change the
published binding to 0.0.0.0. Keep the private backend unreachable from every
public virtual host and public tunnel.

Existing proxy routing requirements (no proxy changes have been made):

| Frontend | Backend | Path behavior |
|---|---|---|
| helios-public.tail43e437.ts.net/nextshuttle/ | public listener | Preserve `/nextshuttle/` prefix |
| shuttle.helios.lan/api/v1/ | private listener | Preserve `/api/v1/` prefix |

The private hostname must only route on your private network. Require HTTPS and
the service Bearer token for the management API. Add mutual TLS on the private
proxy for the Nextcloud service identity. The app must trust your private root CA
and validate `shuttle.helios.lan`. Never publish the private listener merely
because it has authentication.

Proxy request constraints: bounded body size (32 MiB ciphertext by default),
finite read/send timeouts, bounded connections, no caching, no credentials in
logs, no API CORS. Public fetch is POST, not GET. Requests require exactly one
Content-Length; chunked request bodies are not accepted. Preserve Authorization.
Do not enable proxy automatic retries for mutating requests or download claims.
Disable upstream response buffering if you want download claims tied closely to
the actual client connection. The app-level rate limiter sees the proxy IP and
therefore applies a shared per-source budget; add per-client limits at the proxy.
The relay intentionally does not trust arbitrary X-Forwarded-For headers.

Data retention defaults: download/inbox lifetime at most seven days; incomplete
uploads at most 15 minutes; completed incoming files remain encrypted for up to
seven days after upload completion even if the inbox closes. Inbox counters are
lifetime accepted/reserved budgets and are not replenished by importing files;
this prevents a public party from bypassing the inbox's intended total quota.
Unfinished reservations consume that budget too. Create/rotate an inbox for a
fresh operational window. Global disk reservations include failed/expired files
until cleanup removes them. Cleanup runs once per minute on the private service.

The initial implementation bounds ciphertext, not plaintext, sizes. The future
app/browser must account for headers, encrypted manifest and per-chunk overhead
before requesting a reservation. Relay storage is opaque: encryption validity
must be checked by the trusted endpoint before importing any file.

Back up the Nextcloud-side private keys separately from relay ciphertext.
Filesystem unlink is logical deletion, not a promise of physical erasure or
removal from backups. Expiry blocks new reads immediately; active reads may finish.

## Local validation

```sh
python3 -m unittest discover -s tests -v
```

No dependencies are required for these tests. They use temporary storage and
ephemeral loopback HTTP ports; no production service is contacted. Docker build
and live Nextcloud/proxy checks need an environment providing those services.
