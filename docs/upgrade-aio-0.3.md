# Upgrade the Helios AIO app to 0.3

The relay and the native app both need the update. These commands update application code; keep your existing Nextcloud data directory, Docker volumes, service/scanner/admin credentials and NPM host-gateway routing. New cryptographic protection applies to newly created shares/inboxes. Existing legacy shares are labelled; recreate them when password-bound encryption is required.

On Helios:

```sh
cd ~/containers/NextShuttle
git fetch origin
git switch nextshuttle-foundation
git pull --ff-only

docker run --rm --user "$(id -u):$(id -g)" \
  -e npm_config_cache=/tmp/npm-cache -v "$PWD:/work" -w /work \
  node:24-bookworm-slim sh -c 'npm ci --ignore-scripts && npm run build'

docker compose up -d --build
```

Allow a short maintenance window to replace the native app. Back up its current code outside `custom_apps`; duplicate app IDs inside that directory must be avoided. The command chain stops on failure and leaves maintenance mode enabled for diagnosis. It does not overwrite an existing backup directory. The application-code backup is not a substitute for normal AIO/database backups.

```sh
nextshuttle_backup="../nextshuttle-app-backup-$(date +%Y%m%d-%H%M%S)"
test ! -e "$nextshuttle_backup" &&
docker cp nextcloud-aio-nextcloud:/var/www/html/custom_apps/nextshuttle "$nextshuttle_backup" &&
docker exec -u www-data nextcloud-aio-nextcloud php occ maintenance:mode --on &&
docker cp nextcloud/nextshuttle/. nextcloud-aio-nextcloud:/var/www/html/custom_apps/nextshuttle/ &&
docker exec -u root nextcloud-aio-nextcloud chown -R www-data:www-data /var/www/html/custom_apps/nextshuttle &&
docker exec -u www-data nextcloud-aio-nextcloud php occ upgrade &&
docker exec -u www-data nextcloud-aio-nextcloud php occ maintenance:mode --off
```

The overlay is sufficient for this update: existing app files are replaced and the new service/migration files are added. If any command fails, preserve the error for diagnosis instead of continuing or resetting containers/volumes. Reload Nextcloud after success (hard refresh if old styling remains). Create a new share: you should see separate code/key fields once ready, and a generated encryption password during creation. Keep that password and send it separately from the link.

The public website accepts a compact code plus separate encryption key, or a full link/code containing both. The encryption password is always required for new transfers. Its derived authorization credential is sent to the relay; the plaintext password and download encryption key stay local/private.

## Original visitor IP and country

Run `python3 tools/update-geoip.py` to install the local database. Then follow [visitor-attribution.md](visitor-attribution.md) for the separate proxy verification token and trusted-peer configuration. A relay restart is not needed for database replacement, but environment changes require recreating the public service.

Your Funnel gateway and NPM must preserve a trustworthy original IP before NPM asserts it to NextShuttle. Until that chain is configured, notifications explicitly show the observed proxy/peer address and an unknown/private country, rather than guessing. Review the relevant Funnel/gateway server block and public NPM location with secrets redacted before choosing real-IP directives. No new direct NPM-to-NextShuttle Docker network connections are needed.
