# Security requirements and verification mapping

Use OWASP MASVS https://mas.owasp.org/MASVS/ and MASTG https://mas.owasp.org/MASTG/ as verification references, not certifications.

- STORAGE/PRIVACY: no persistent inputs/results; private temporary APK deletion; backup disabled. Verify crash leftovers and device backups.
- PLATFORM: exported share intake treats data as hostile; explicit picker; no broad package permission; no app installs or deletes.
- CODE: length/file/entry/decompression limits; deterministic parser regression and seeded fuzz cases; Android lint and device tests required.
- NETWORK: the manifest requests INTERNET (needed by the VPN service to forward DNS to the upstream resolver); there is no feed download, server, analytics or TLS interception, and DNS forwarding sends only the lookups the person's phone makes. Device packet capture remains pending.
- CRYPTO: SHA-256 for identity only. Certificate hashes do not prove trusted publisher. No signature update trust claim until authenticated feed implementation and tests exist.
- AUTH: no privileged actions. Future agent integration must bind caller identity, action digest, nonce, expiry and one-use authorization; no authorization through untrusted text.
- RESILIENCE: release signing key must remain outside repository; independent review and supply-chain scan required before commercial release.

Release gates are not passed merely by writing a requirement. See TEST_RESULTS.md and KNOWN_LIMITATIONS.md.
