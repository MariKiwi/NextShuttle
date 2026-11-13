# Security status

NextShuttle is pre-release software and has not received an independent security
audit. The current repository contains an opaque storage relay, not a completed
end-to-end encrypted sharing product. An initial Nextcloud notification app and
private scan adapters exist, but browser crypto, Files integration, the
quarantine/import pipeline and private relay admin interface are unfinished.

Do not send plaintext files to the relay or expose a development instance publicly.
The relay cannot tell ciphertext from plaintext. That boundary must be enforced by
the trusted app/browser clients before a release.

Report suspected vulnerabilities privately to the repository owner through
GitHub's private vulnerability reporting if enabled; otherwise contact the owner
privately. Do not put access tokens, private keys or personal file contents into
public issues.

The threat model and outstanding release gates are in docs/DESIGN.md. Security
tests cover behavior of implemented components; they do not establish security of
an incomplete application or of a live proxy configuration.
