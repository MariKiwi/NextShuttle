# Mandatory upload protection

## Status

The private decryption, quarantine, dual-engine scan and Nextcloud import pipeline is implemented. Browser/PHP interoperability and actual Nextcloud 35.0.2 transfer/import tests run in CI. The real-antivirus workflow separately tests actual engines; require its successful result for the commit being deployed. A relay upload receipt alone never authorizes import.

## Private ingestion pipeline

1. Claim an upload by durable job ID. Check owner, inbox, size and resource budget.
2. Authenticate/decrypt into private quarantine, outside web roots, user files,
   synchronization, preview and indexing services. Reject invalid envelopes,
   oversized chunks, invalid authentication tags, truncation, missing FINAL,
   appended bytes and manifest/size mismatches. Bound work while streaming;
   incomplete plaintext must be cleaned up and never sent to content parsers.
3. Validate filename and content policy. Use generated staging paths, never
   submitted paths. Detect content from bytes; extensions and submitted MIME are
   untrusted. Use a type allowlist and isolated format validators. Never execute,
   include, deserialize as application code or serve active uploads inline.
4. Scan the SAME immutable plaintext bytes with **ClamAV AND a distinct maintained
   antivirus engine**. Require explicit completed clean results from both. Record
   content hash, engine/signature versions, policy version and verdict time.
5. Recheck hash, current owner/folder write permission, policy and quota. Import
   exactly the scanned bytes through Nextcloud's filesystem API with collision
   protection and a durable receipt preventing duplicate imports after retries.
6. Acknowledge the relay after durable import. Rejected content is never imported.
   Retention/cleanup cover rejected ciphertext, plaintext quarantine and crashes.

Decryption and scanning run inside the trusted private Nextcloud boundary. The
public relay never receives decryption keys or plaintext. Antivirus cannot inspect
file contents through the transfer encryption. Use a separate private ingestion
worker; do not parse untrusted files inside the public relay or PHP web process.

Quarantine files are inaccessible to normal users and previews while awaiting a
verdict. Their status is awaiting scan, scanning, accepted, rejected or unavailable;
users can see only their own records. Public inbox visitors cannot list uploads.
Existing files selected for outgoing shares also require clearance before an
encrypted snapshot is published; reuse verdicts only for identical content under
the current policy and sufficiently recent signature/engine versions.

## Scanner selection and failure behavior

ClamAV plus another ClamAV instance or additional signatures is NOT two engines.
YARA is useful supplementary detection, but does not replace independent antivirus.
The selected free second scanner is Linux Malware Detect (LMD), GPLv2, using its
native engine with `scan_clamscan=0`. Its Linux/web-malware focus is narrower than
broad commercial antivirus coverage. It is an additional independent malware
pass, not proof of comprehensive detection. See staging.md for pinned-version
adapter details. Do not enable external sample submission.

Use clamd for ongoing scanning on a private socket/network, never publicly exposed.
Adapters must map documented results to CLEAN, DETECTED, UNINSPECTABLE or ERROR.
Unknown responses block import. LMD clearance requires a completed native-engine
report for the exact single file, no hits, no cleaning/quarantine and current
signatures, not simply a successful process exit.
Do not automatically clean and import a replacement: modification invalidates the
original hash/verdict. Submission to an asynchronous scanner is not a verdict.

Both engines are mandatory. Offline/unlicensed engines, stale definitions,
timeouts, resource limits, skipped bytes and incomplete scans must block import
or leave the job quarantined for bounded retries. Never fail open or promote on
retention expiry. Health checks must verify actual engine/license/update health,
not merely a responsive process. Define signature-age limits per adapter.

Configure ClamAV heuristic alerts and reject encrypted archives/documents,
malformed executables, configured macro content and exceeded scan limits. Check
AlertExceedsMax, AlertEncryptedArchive, AlertEncryptedDoc, AlertBrokenExecutables
and AlertOLE2Macros against the installed clamd version. clamscan CLI flags are
not clamd.conf directives. Match stream/file/aggregate scan limits to upload caps:
skipping an oversized file is not clean inspection.

## Content policy and containment

The implemented allowlist is UTF-8 text, PNG/JPEG, constrained PDF, macro-free DOCX/XLSX/PPTX and bounded ZIP. Pillow verifies and decodes images; pikepdf checks PDF structure and rejects active actions, embedded files and encryption; defusedxml checks Office XML and relationships. ZIP inspection rejects unsafe names, duplicates, special entries, encryption and trailing data, and enforces three levels, 1,000 entries, 128 MiB expanded bytes and a 100:1 ratio. Both engines scan the original and every extracted member. No extension or MIME claim alone permits a file. Unsupported formats and validator uncertainty block import. These conservative validators can reject valid files and cannot establish complete semantic correctness or absence of vulnerabilities.

Archive support must enforce depth, entry count, actual expanded bytes, compression
ratio, CPU, disk and time limits. Reject encrypted/unsupported archives, unsafe
entry paths, symlinks/hardlinks and uninspectable nested content. Never extract
into a Nextcloud destination or trust declared expanded sizes.

Scanner and validation workers get read-only input, no application credentials,
no Docker socket/host filesystem mounts, no network during processing, no added
privileges and bounded CPU/RAM/processes/descriptors/time. Keep signature update
traffic separate. Plaintext quarantine needs restricted access, encrypted storage,
noexec/nodev/nosuid where applicable, fixed retention and crash cleanup. These
mount flags do not replace the rule against executing content.

Scan locally. Do not submit private files to VirusTotal/public multiscanners or
vendor sample-upload services without an explicit privacy decision. Check vendor
cloud lookup/sample settings; running a CLI locally alone does not prove privacy.
Admin settings expose health, update age, policies, queue, retention and safe
rejection details; normal controls cannot bypass mandatory scanning. Logs exclude
credentials, encryption keys, uploaded content and unnecessary private paths.

A corrupt file is not necessarily malicious; a well-formed file can be malicious.
No scanner pair or validator can guarantee that every upload is harmless. Isolation
also limits damage from vulnerabilities in the scanners and validators themselves.

## Acceptance gates

* Harmless allowed files pass BOTH real engines and import once after scanning.
* Harmless EICAR antivirus test files are blocked by each engine independently;
  do not use live malware. Scan exceptions never authorize import.
* Tampered/truncated ciphertext never reaches scanners or format parsers.
* Corrupt allowed types, extension/content mismatches, traversal, active content,
  macros, oversized input and archive bypass cases fail according to policy.
* Engine outage, stale updates, invalid license, timeout, partial scan and unknown
  results leave content quarantined and inaccessible.
* Content changed between validation, either scan or import cannot be promoted.
* Permission revocation, full disks, restarts, concurrent jobs and retry races do
  not bypass scanning or produce duplicate imports.
* Public routes cannot reach private quarantine/scanners/admin endpoints.

## Primary references

* https://docs.clamav.net/manual/Usage/Scanning.html
* https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamd.conf.5.in
* https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/antivirus_configuration.html
* https://docs.sophos.com/esg/spl/en-US/index.html?contextID=protect-devices-server-Linux-agent
* https://help.eset.com/essl/11.1/en-US/on_demand_scan_via_terminal.html
* https://help.eset.com/essl/11.1/en-US/activate.html
* https://github.com/rfxn/linux-malware-detect
