# Threat bundle format `AEGIS-THREATDB 1`

A bundle is printable ASCII, LF line ends, at most 16 MiB and 500,000 entries.

```
AEGIS-THREATDB 1
key-id: <16 hex = first 8 bytes of SHA-256 of the X.509 public key>
sequence: <positive integer, strictly increasing per key>
issued: <ISO-8601 UTC instant>
expires: <ISO-8601 UTC instant, after issued, at most 100 days later>
entries: <N>
<N entry lines>
END
SIGNATURE <base64 ECDSA P-256 / SHA-256 (DER, canonical base64) over every byte before this line>
```

Entry line: `<type> <value> <category> <confidence> <label>`

| field | values |
|---|---|
| type | `H` APK SHA-256, `D` domain, `C` APK signing-certificate SHA-256 |
| value | `H`/`C`: 64 lowercase hex. `D`: lowercase punycode host, 2+ labels, no wildcard, no IP, not a listed public suffix, **not a protected domain** (see below) |
| category | `MALWARE` `PHISHING` `SCAM` `UNWANTED` |
| confidence | `SUSPICIOUS` < `STRONG` < `CONFIRMED` (publisher's claim; maps to the app verdicts) |
| label | `[A-Za-z0-9._-]{1,64}`; no spaces, so feed text can never carry instructions into UI or AI prompts |

## Acceptance rules (ThreatBundleVerifier)
1. Size, ASCII and line-ending checks; final line must be `SIGNATURE`.
2. `key-id` (read from the first two short lines) must match a trusted anchor; the signature is verified over the raw bytes **before** the body is split or parsed.
3. **At install:** `sequence` must be greater than that key's floor and the active bundle's sequence if it is the same key, and may be at most 100,000 above it; not expired; not issued more than 24 h in the future.
4. `expires` must be after `issued` and at most 100 days later.
5. Strict entry grammar, exact entry count, no duplicates, single-label/public-suffix/IP domains refused, **protected domains refused** (`ProtectedDomains`: about 80 big-platform and Norwegian-service registrable domains plus connectivity-check names; a feed may still list abusive *sub*-domains such as `sites.google.com`, and the DNS filter additionally never blocks protected names even if an older bundle lists them; the person's own block list is unrestricted).

Replay protection applies **at install and at startup**. Stored bundles are re-verified on every start (signature, structure) without expiry checks, so a clock that is days behind does not discard a valid database. At startup a correctly signed `current.bundle` whose sequence is below that key's floor is refused as a replayed old file (database empty, warning shown; the older `previous.bundle` is not used either). A deliberate `rollback()` writes a `rolledback` marker so the restored bundle is accepted after a restart. Someone who can write all of app storage (root) can still edit the floor and marker files; clearing app data also resets the floors.

## Storage, floors and rollback (ThreatStore)
`current.bundle`, `previous.bundle`, `floors` in app-private storage. **Floors are per signing key** (`<keyid> <highest installed sequence>`), so a rotated key starts from its own floor and can never be locked out by what an earlier or compromised key signed. A tampered current file falls back to `previous`, then to an empty database (flagged). `rollback()` restores `previous` but keeps the floors. Expired bundles remain usable offline but are reported stale. Clearing app data resets the floors (inherent: the floors live in app storage).

## Key custody, rotation and compromise runbook
- Generate the signing key offline (`ThreatBundleTool keygen`; the private key file is unencrypted base64: keep it on an offline/encrypted medium or move signing to an HSM). There is no threshold signing and no key expiry yet.
- Anchors ship inside the app (`trusted_threat_keys.txt`, X.509 base64, EC P-256 only). **Rotation:** release an app version containing both the old and new key, start signing with the new key (its sequence starts independently), later release a version without the old key. **Revocation / compromise:** release an app version without the compromised key; stored bundles signed by it fail re-verification and the database falls back to empty. There is no revocation channel faster than an app update; this is a known limitation.
- Mistakes are bounded: a bundle cannot advance a key's sequence by more than 100,000, cannot be valid for more than 100 days, cannot list protected domains. `ThreatBundleTool sign` enforces the same limits.
- Not yet rehearsed: a full compromise drill on a test key. Do that before the first production key is used.

## Publishing
Build the entry list from licence-cleared sources with `FeedBuilder` (see DATA_SOURCES.md and `tools/feed-sources.example.txt`), then `ThreatBundleTool keygen <prefix>` / `sign <prefix> <seq> <days 1..100> <entries.txt> <out>`. **No production key exists yet**, so `app/src/main/assets/trusted_threat_keys.txt` is empty and the release app accepts no bundle. The debug build trusts the *published* test key in `tools/debug-test-key` (its private half is public on purpose): the debug build uses a different application id (`.debug`), shows a persistent "TEST BUILD" banner, and `tools/check_release_apk.py` fails any release APK that trusts that key id.
