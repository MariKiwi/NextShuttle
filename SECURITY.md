# Security status

NextShuttle is development software with implemented encrypted transfer, private scanning/import and administration paths. It has not received an independent security audit. Require successful CI for the exact commit and complete the environment acceptance checks in docs/staging.md before broader use.

The public relay stores ciphertext and does not receive Nextcloud credentials, plaintext or decryption keys. Browser-to-Nextcloud encryption trusts the JavaScript delivered by the public origin; a compromised site could replace that code. Nextcloud itself is a trusted endpoint. Code secrecy, TLS, private routing and protected endpoint devices remain necessary.

ClamAV and native Linux Malware Detect must both return clean completed verdicts. Stale/unavailable scanners, malformed encrypted data and uninspectable formats block import. LMD offers narrower Linux/web-malware coverage. No scanner pair or structural validator can guarantee that every file is harmless. Keep host/container dependencies and definitions updated and use only synthetic data during staging.

Report vulnerabilities privately through GitHub private vulnerability reporting if enabled, or contact the repository owner privately. Do not publish credentials, private keys, personal files or exploitable deployment details in public issues. See docs/DESIGN.md for trust boundaries.
