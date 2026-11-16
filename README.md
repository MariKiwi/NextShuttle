# NextShuttle

Encrypted file transfers for a private **Nextcloud 35.0.2** installation.

Public: **https://helios-public.tail43e437.ts.net/nextshuttle/**  
Private administration and service API: **https://shuttle.helios.lan/**

## Features

* Files actions and sharing-sidebar integration: publish an encrypted file snapshot or open an upload inbox for a folder.
* Unique download codes, optional separate passwords, download limits, expiry and revocation. Upload inboxes have reusable passwords, pinned public encryption keys and lifetime file/byte budgets.
* Browser-to-Nextcloud authenticated encryption. The public relay stores ciphertext; private keys remain in Nextcloud. Uploads are decrypted only inside the private network.
* Private quarantine, bounded format validation, ClamAV **and Linux Malware Detect's independent native engine**, then collision-safe import with durable receipts. Both scanners must approve the identical bytes. Outgoing snapshots also require clearance.
* Owner-only transfer dashboard, retries, password rotation and event history. Nextcloud admin settings control sharing policies, groups, expiry, types and quotas while respecting native sharing permissions.
* Separate private relay admin page with its own session login, CSRF protection, revocation and audit export/retention controls.
* Durable event and notification queues for every enabled global admin and the affected owner. Covers access, wrong codes, transfers, rejection, scanner outages, policy changes and other noteworthy events.

The Compose stack separates public/private relay processes, ingestion, ClamAV and signature updates. Only the updater needs Internet access; scanners receive no Nextcloud credentials or decryption keys.

## Start a test deployment

Follow [deployment.md](docs/deployment.md), then [staging.md](docs/staging.md).
Use a disposable Nextcloud and synthetic files first. No deployment has been made on your server.
The app package is produced by the **Relay checks** workflow; source installs require `npm ci && npm run build` before copying the app.

The implementation is a development build, not an independently audited production release. The remaining environment acceptance checks are tracked in staging.md. No scanner can guarantee that a file is harmless. Browser encryption also trusts the JavaScript delivered by the public site; a compromised relay could replace that code. See [DESIGN.md](docs/DESIGN.md).

## Validation

```sh
python3 -m pip install -r ingestion/requirements.txt
python3 -m unittest discover -s tests -v
npm ci
npm test
npm run build
npx playwright install chromium
npx playwright test
```

CI additionally checks PHP syntax, PHP/browser crypto interoperability, real Nextcloud 35.0.2 transfer processing and live antivirus startup/clearance/EICAR rejection. Browser tests use synthetic data on isolated loopback services. Read workflow results for the exact commit being deployed.

Details: [upload protection](docs/upload-protection.md), [events and notifications](docs/events-and-notifications.md), [security policy](SECURITY.md).
