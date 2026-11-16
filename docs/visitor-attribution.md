# Visitor IP and estimated country

Public access events carry `client_ip`, `country` (ISO alpha-2 or null), `ip_source`, and `country_status`. The fields survive relay export, Nextcloud migration/import and notification handoff. Enabled admins and the affected owner receive the IP and estimated country. These fields are personal data; protect audit exports and apply your retention policy.

The default IP is the directly observed TCP peer. With NPM/Funnel this may be a private proxy address. We never trust arbitrary X-Forwarded-For, country headers or a browser-supplied address. To accept an asserted original IP, BOTH the actual relay peer must match `NEXTSHUTTLE_TRUSTED_PROXIES` AND an independent proxy verification token must match. Exactly one token/IP header is required. Forged/malformed/duplicate headers fall back to the observed peer.

## Local GeoIP data

From the repository on Helios:

```sh
python3 tools/update-geoip.py
```

This downloads the current monthly DB-IP Country Lite MMDB into `geoip/country.mmdb`, mounted read-only by the public relay. No visitor IP is sent to DB-IP or another lookup service. Free data is CC BY 4.0; the event page includes the required attribution link. The updater is bounded, checks gzip/MMDB structure and installs atomically. Schedule it monthly if desired; no schedule is installed automatically.

MaxMind country/city MMDB files with a compatible `country.iso_code` record can also be used, subject to their own license/account/update requirements. Private/reserved/Tailscale addresses, missing/outdated/unavailable databases or unmapped addresses produce an explicit unknown/private result. Data more than 90 days old is not used. Location describes the observed address, not a person's physical location; VPN/proxy egress may be in another country.

## NPM authentication of client-IP headers

Create a separate proxy verification token locally, without replacing an existing one:

```sh
python3 - <<'PY'
from pathlib import Path
import secrets
p=Path('proxy/forwarded_token')
with p.open('x') as f:
    f.write(secrets.token_urlsafe(48)+'\n')
p.chmod(0o600)
PY
sudo setfacl -m u:10001:rx proxy
sudo setfacl -m u:10001:r proxy/forwarded_token
```

Set `NEXTSHUTTLE_TRUSTED_PROXIES` in `.env` to the specific peer address(es) or tightly scoped CIDRs actually observed by the public relay. Docker host-port NAT may change the peer to a bridge gateway; inspect an access event rather than assuming the peer is 172.19.0.1. The verification token remains mandatory even when traffic is NATed through a shared gateway. Do not put this token in browser code or URLs, and do not send it to chat/support.

In NPM's `/nextshuttle/` location, overwrite these headers (replace the placeholder locally with the file's value):

```nginx
proxy_set_header X-NextShuttle-Client-IP $remote_addr;
proxy_set_header X-NextShuttle-Proxy-Token "YOUR_LOCAL_PROXY_VERIFICATION_TOKEN";
```

Recreate the public service after changing its environment:

```sh
docker compose up -d --build shuttle-public
```

**Funnel / gateway / NPM chain:** `$remote_addr` must already represent the original client at NPM. Only configure Nginx real-IP processing for the exact trusted upstream peers and the forwarding mechanism they actually supply. Do not use `set_real_ip_from 0.0.0.0/0`, blindly forward `$http_x_forwarded_for`, or enable PROXY protocol on a listener without matching the sender. Depending on Funnel mode, HTTP forwarding headers or PROXY protocol may be involved. Review the existing Funnel and gateway configs before changing this chain. Without that configuration the app honestly reports the peer/proxy address and cannot reconstruct a visitor IP that was discarded upstream.
