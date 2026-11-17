# Helios interface and network update (0.3.2)

The release is visibly identified as **0.3.2** on the public footer, relay admin footer and Nextcloud workspace. If those labels are absent, the old code is still being served. The native app must be copied separately; rebuilding Compose does not install it into AIO.

From `~/containers/NextShuttle`, stop the old project **before pulling the new network topology**. This removes its five old project networks while preserving volumes and credentials:

```sh
docker compose down
git fetch origin
git switch nextshuttle-foundation
git pull --ff-only
docker run --rm --user "$(id -u):$(id -g)" \
  -e npm_config_cache=/tmp/npm-cache -v "$PWD:/work" -w /work \
  node:24-bookworm-slim sh -c 'npm ci --ignore-scripts && npm run build'
chmod 644 ingestion/gateway.conf
sudo setfacl -m u:10001:r secrets/service_token secrets/scanner_token secrets/admin_password
docker compose up -d --build --force-recreate
```

The new topology creates **two** networks: a shared backend bridge for public/private relay, scanner gateway and signature updater, plus an internal scanner-only bridge for ingestion/ClamAV and the gateway. Scanner workers still have no internet route or published host ports. Backend sharing means less lateral network isolation than before; API tokens, separate listener modes and process hardening remain required. Keep all host bindings on `172.19.0.1`, not `0.0.0.0`. NPM continues using ports 9080/9081/9082 without joining the project networks.

## Optional: reuse an existing bridge

Only reuse a network whose members you trust. This does not require connecting NPM directly. Inspect existing network names locally:

```sh
docker network ls
```

Set `NEXTSHUTTLE_BACKEND_NETWORK` in `.env` to the exact existing bridge name. Then use the override for **every** Compose command:

```sh
docker compose -f compose.yaml -f compose.existing-network.yaml config --quiet
docker compose -f compose.yaml -f compose.existing-network.yaml up -d --build --force-recreate
```

With this option only the scanner-isolation network is newly allocated. The external network is never deleted by Compose. Do not attach scanner workers directly to the reused bridge. When switching from the new default topology to the override, first run `docker compose down` with the configuration that originally created it.

## Install the native app

With Nextcloud running normally, execute the whole chain. If a step fails, it stops and may leave maintenance mode enabled for diagnosis:

```sh
docker exec -u www-data nextcloud-aio-nextcloud php occ maintenance:mode --on &&
docker cp nextcloud/nextshuttle/. nextcloud-aio-nextcloud:/var/www/html/custom_apps/nextshuttle/ &&
docker exec -u root nextcloud-aio-nextcloud chown -R www-data:www-data /var/www/html/custom_apps/nextshuttle &&
docker exec -u www-data nextcloud-aio-nextcloud php occ upgrade &&
docker exec -u www-data nextcloud-aio-nextcloud php occ maintenance:mode --off
```

If the app has been removed, copy its directory, set ownership as above, then run `php occ app:enable nextshuttle` as www-data instead. There is no need to remove/reinstall an existing app for this update. Removal is not a guaranteed purge of its database/configuration.

Verify:

```sh
docker exec -u www-data nextcloud-aio-nextcloud php occ config:app:get nextshuttle installed_version
curl -fsS http://172.19.0.1:9080/nextshuttle/ | rg 'Interface 0.3.2'
docker compose ps
```

Expect version `0.3.2`, a split public transfer portal, a full-width relay operations dashboard after sign-in, and a themed Nextcloud workspace with side navigation. Hard-refresh the browser. Check new download and upload flows and scanner readiness before using real files. Network changes can change the observed relay peer: revisit `NEXTSHUTTLE_TRUSTED_PROXIES` if verified visitor attribution stops working. Never broaden the trust range just to make it pass.
