#!/usr/bin/env bash
set -euo pipefail
mkdir -p ci-state
python3 - <<'PY'
from pathlib import Path
p=Path('ci-state')
for name,char in [('service_token','r'),('scanner_token','s'),('admin_password','a')]:
 (p/name).write_text(char*64);(p/name).chmod(0o444)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=shuttle.helios.lan' -addext 'subjectAltName=DNS:shuttle.helios.lan,DNS:localhost' -keyout ci-state/key.pem -out ci-state/ca.crt
cat > ci-state/nginx.conf <<'NGINX'
events {}
http { server { listen 443 ssl; server_name shuttle.helios.lan;
 ssl_certificate /certs/ca.crt; ssl_certificate_key /certs/key.pem; client_max_body_size 34m;
 location /api/v1/ { proxy_pass http://relay-private:8081; }
 location /ingestion/v1/ { proxy_pass http://stub-scanner:8082; }
}
server { listen 443 ssl; server_name localhost;
 ssl_certificate /certs/ca.crt; ssl_certificate_key /certs/key.pem;
 location / { proxy_pass http://nextcloud-test:80; proxy_set_header Host $http_host; proxy_set_header X-Forwarded-Proto https; }
} }
NGINX
docker network create nextshuttle-ci
docker build -t nextshuttle:ci .
docker run -d --name relay-private --network nextshuttle-ci -e NEXTSHUTTLE_DATA=/data -v nextshuttle-ci-data:/data -v "$PWD/ci-state/service_token:/run/secrets/service_token:ro" -v "$PWD/ci-state/admin_password:/run/secrets/admin_password:ro" nextshuttle:ci --mode private --bind 0.0.0.0 --port 8081
docker run -d --name relay-public --network nextshuttle-ci -v nextshuttle-ci-data:/data -e NEXTSHUTTLE_DATA=/data nextshuttle:ci --mode public --bind 0.0.0.0 --port 8080
docker run -d --name stub-scanner --network nextshuttle-ci -v "$PWD/tests/stub_scanner.py:/stub.py:ro" python:3.12-slim-bookworm python3 /stub.py
docker run -d --name nextcloud-test --network nextshuttle-ci -e NEXTCLOUD_ADMIN_USER=admin -e NEXTCLOUD_ADMIN_PASSWORD=ephemeral-ci-admin-password-246810 -e OVERWRITEPROTOCOL=https -e SQLITE_DATABASE=nextcloud -e 'NEXTCLOUD_TRUSTED_DOMAINS=localhost 127.0.0.1' -v "$PWD/nextcloud/nextshuttle:/var/www/html/custom_apps/nextshuttle:ro" nextcloud:35.0.2-apache
docker run -d --name private-proxy -p 127.0.0.1:9083:443 --network nextshuttle-ci --network-alias shuttle.helios.lan -v "$PWD/ci-state/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$PWD/ci-state:/certs:ro" nginx:stable-alpine
ready=0
for attempt in $(seq 1 90); do
 if docker exec -u www-data nextcloud-test php occ status --output=json 2>/dev/null | python3 -c 'import json,sys;sys.exit(0 if json.load(sys.stdin).get("installed") else 1)' 2>/dev/null; then ready=1;break;fi
 sleep 3
done
test "$ready" = 1
docker cp ci-state/ca.crt nextcloud-test:/tmp/ci-ca.crt
docker cp tests/nextcloud-integration.php nextcloud-test:/tmp/nextshuttle-integration.php
docker exec -u www-data nextcloud-test php occ app:enable notifications
docker exec -u www-data nextcloud-test php occ app:enable nextshuttle
docker exec -u www-data nextcloud-test php /tmp/nextshuttle-integration.php

docker cp nextcloud-test:/tmp/http-fixture.json ci-state/http-fixture.json
python3 tests/nextcloud_http.py
