# Stage 4 — DNS protection (VpnService)

**Status: engine host-tested; Android service compile-verified only. It has NOT run on any device or emulator.** The roadmap's rule "release only after extensive device testing" is therefore not met. Treat as a preview.

## Design
A DNS-only VPN. `AegisVpnService` creates a tunnel that owns two virtual resolver addresses (`10.111.222.2`, `fd00:ae91:5::2`), tells Android to use them as DNS servers, and **routes only those two host addresses** into the tunnel. All other traffic (web, apps, QUIC, TLS) never enters the tunnel, so it is not read, not slowed, and not at risk of breakage. `tools/check_privacy.py` fails the build if the service ever routes anything else, uses per-app lists, or the permission set changes. No certificate authority is installed and nothing is decrypted.

Pipeline (all in `core`, pure Java): `IpPacket` (IPv4/IPv6+UDP framing, rejects fragments, extension headers, other destinations/ports) → `DnsMessage` (strict one-question query parser, rejects compression pointers, odd characters, oversized names) → `DnsFilter` → blocked: local NXDOMAIN; allowed: `DnsUpstream.Plain` (UDP with TCP retry on truncation, failover across servers, every socket passed to `VpnService.protect`) → response validated (ID, question echo) → `DnsProxy` writes the reply packet with correct checksums.

Decision order: tripwire (canary) names, user allowlist → user blocklist → signed threat database (CONFIRMED/STRONG block; SUSPICIOUS only warns unless enabled) → allow. Fail-open: with no database, no provider or a provider error, lookups are allowed. The same holds when the service has to stop (for example the system refuses the foreground type): stopping means DNS is no longer filtered, which is deliberately fail-open for filtering, not 'fail closed'. A small protected list (connectivity checks, time, public DNS names) can never be blocked by a feed.

Upstream is the network's own resolver, discovered with a `NetworkCallback` (non-VPN networks, Wi-Fi/Ethernet preferred). Only the preferred network's resolvers are used and upstream sockets are bound to that network (`Network.bindSocket`) in addition to `protect()`, so a lookup cannot leave over a different network than the one whose resolver was chosen. When the worker pool and its queue are full, excess queries are answered with SERVFAIL immediately so clients move on instead of waiting out their timeout. A TCP DNS listener is still not provided (clients retry over UDP; large answers are truncated). No third-party resolver is used.

## Privacy
Allowed query names are never stored or logged; the proxy keeps counters and the last 200 blocked/warned events in memory only. Persisted: only your allow/block lists (app-private storage). Network permission is used solely to forward allowed lookups. Source scans in `DnsTests` forbid logging and file APIs in the DNS classes.

## Permissions added
`INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` (Android's documented type for VPN apps), `POST_NOTIFICATIONS` (persistent notice, requested at start, protection works if refused). The VPN consent screen is Android's own and appears every time the VPN is first prepared; Aegis never starts the tunnel silently.

## Known limits (Android and design)
- Apps/browsers with their own DNS-over-HTTPS/TLS, hard-coded resolvers, or IP-only connections bypass this. Android Private DNS in strict mode may bypass system DNS; behaviour with it is untested. In Automatic mode, lookups Aegis passes on are sent as ordinary unencrypted DNS (a downgrade from what the phone would otherwise do); the in-app disclosure says so.
- No DoT/DoH upstream yet (upstream queries are plain DNS to the network's resolver, as the phone would send anyway).
- CNAME chains are not inspected: a harmless name that CNAMEs to a listed name is allowed.
- No TCP service inside the tunnel: answers larger than ~1232 bytes are returned truncated (TC set) rather than served over TCP.
- Only one VPN can be active; starting this one replaces another VPN, and another VPN replaces this one. Captive portals, battery impact, network handover and Doze behaviour are unmeasured.
- Blocking is by name only. No IP-level blocking, no per-app attribution, no connection monitoring beyond DNS events.

## Required device test plan before any release
1. Install debug APK on API 26, 29, 33, 34/35 devices; start/stop 50 times; revoke consent from system settings; reboot with Always-on VPN.
2. Wi-Fi ↔ mobile handover, airplane toggle, captive-portal Wi-Fi, IPv6-only network (NAT64), VPN conflict with another VPN.
3. Import debug sample bundle; confirm `aegis-test-phish.example` is refused (`nslookup`/browser) while `example.com` resolves; confirm user allow/block lists.
4. Private DNS off/automatic/strict; Chrome with and without Secure DNS.
5. 24 h battery comparison on/off; packet capture on a test network confirming no non-DNS traffic enters the tunnel and no query names leave except to the network resolver.
