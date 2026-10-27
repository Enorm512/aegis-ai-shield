# Aegis approval tokens for servers (preview)

**Status: token format, signing and the reference verifier are host-tested (`TokenTests`, 50 checks, including 2,000 mutated tokens of which none verify). Signing with the Android Keystore, the key export and the gateway wiring compile and pass lint but have never run on a device.**

## What it solves
Aegis' agent firewall runs on the phone, and an agent can ignore its answer. An approval token moves the check to where the call lands: a backend that requires a valid token refuses every agent call Aegis did not allow, or that the person did not approve, including calls from a hijacked agent that never asked Aegis at all.

## When Aegis issues one
- `MSG_RESULT` with verdict `ALLOW` (grant `POLICY_ALLOW`), and
- `MSG_REDEEMED` with `granted = true` after the person approved (grant `USER_APPROVED`),

in both cases only when the call's destination has a host (the token's audience). No token for denied, waiting or brokered actions (Aegis performs those itself). The audit log records `TOKEN_ISSUED` with host and grant, never the token.

## Format
`AT1.<base64url payload>.<base64url signature>`

The payload is UTF-8, one field per line, in this exact order:
```
aegis-approval-token/1
kid=<32 hex: first 16 bytes of SHA-256 of the phone's public key (X.509 SubjectPublicKeyInfo)>
jti=<32 hex, random, single use>
iat=<issued, epoch seconds>
exp=<expiry, epoch seconds; Aegis uses iat + 120>
agent=<Android package of the agent, as verified by Android>
aud=<destination host = the server this call is for>
type=<SEND_DATA | SHARE_FILE | ... action type>
dest=<destination exactly as the agent gave it; printable ASCII, at most 2048>
body=<SHA-256 hex of the exact request payload, UTF-8>
amount=<minor units, or -1>
currency=<ISO code in capitals, or empty>
grant=<USER_APPROVED | POLICY_ALLOW>
```
Signature: ECDSA P-256 with SHA-256, DER-encoded, over the payload bytes. The verifier accepts only this canonical spelling (no leading zeros, CRLF, extra fields or upper-case hosts), so the same claims cannot be written two ways.

## Key
Each phone has its own key in the Android Keystore. Only Aegis can use it for signing, and the private key cannot be exported. Protection → Proof for servers shows its fingerprint (`kid`), exports the public key as PEM, and can replace it. A server enrols each phone's PEM; check the fingerprint with the phone's owner when you do. Replacing the key makes all servers refuse the phone's tokens until they enrol the new key.

## Server checks (reference: `com.aegis.agentsdk.ApprovalToken.Verifier`, JDK only)
In this order, nothing from the payload is trusted before the signature checks out:
1. well-formed and canonical → else `MALFORMED`
2. `kid` is an enrolled phone → else `UNKNOWN_KEY`
3. signature valid → else `BAD_SIGNATURE`
4. lifetime ≤ 120 s → else `LIFETIME_TOO_LONG`; not issued in the future and not expired (30 s clock skew) → `NOT_YET_VALID` / `EXPIRED`
5. `aud` equals this server's host → else `WRONG_AUDIENCE`
6. SHA-256 of the received body equals `body` → else `BODY_MISMATCH`
7. optional: exact destination, allowed agents, allowed action types → `DESTINATION_MISMATCH`, `AGENT_NOT_ALLOWED`, `TYPE_NOT_ALLOWED`
8. `jti` not seen before → else `REPLAYED`. `MemoryReplayCache` works for one process; it refuses new tokens when full rather than forget unexpired ids. A cluster needs a shared store with the same contract.

```java
var verifier = new ApprovalToken.Verifier(List.of(ApprovalToken.fromPem(enrolledPem)), new ApprovalToken.MemoryReplayCache(100_000), 30);
var r = verifier.verify(request.getHeader("Aegis-Approval"),
        new ApprovalToken.Expect("api.example.org", requestBodyBytes, null, null, null), Instant.now().getEpochSecond());
if (!r.ok()) return reject(403, r.reason());
```

Command line, for trying it out (no replay memory):
```
java -cp agent-sdk.jar com.aegis.agentsdk.TokenVerifierCli phone.pem api.example.org <token> body.json [expected-destination]
```

## For agents
`AegisClient.evaluate(...)` returns `Result.token` for ALLOW, and `redeem(approvalId)` returns `Redeemed(granted, token)`. Send the token with the call (suggested header: `Aegis-Approval`) and send exactly the payload Aegis checked: the body hash must match byte for byte.

## Limits
- Nothing here has run on a device: Keystore key creation, signing speed, and key availability on different phones are unverified. If the Keystore is unavailable, no tokens are issued (calls to servers that require tokens then fail closed).
- The token proves that Aegis on an enrolled phone allowed or saw an approval for this call. It does not prove the phone is uncompromised. Code running as Aegis, or with root, could use the key. Android key attestation (proving the key is in secure hardware) is not implemented.
- The phone's clock must be roughly right (±30 s by default).
- The body must be byte-identical. Agents that re-serialise JSON differently after asking will fail `BODY_MISMATCH`.
- Only calls with a host destination get tokens. Local actions (commands, installs, settings) have no server to check them.
- Enrolment is manual (export a PEM and give it to the server). There is no revocation list beyond replacing the key on the phone and removing the old one on the server.
