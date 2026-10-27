#!/usr/bin/env bash
# Builds and signs a threat feed bundle from tools/feed-sources.txt. Runs offline; the private key never enters the repo.
#   bash tools/build_feed.sh <key-prefix> <sequence> [--seed]
# <key-prefix> is the path of your offline key without extension (<prefix>.private / <prefix>.public, made with
# `ThreatBundleTool keygen`). <sequence> must be higher than every feed signed with that key before. Writes
# tools/feed/out/aegis.bundle and ATTRIBUTION.txt; --seed also copies the bundle to app/src/main/assets/threat_seed.bundle
# so the next APK installs it on first use. A bundle is valid 30 days; an APK seed older than that is ignored by the app.
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <key-prefix> <sequence> [--seed]" >&2; exit 2; }
KEY="$1"; SEQ="$2"; SEED="${3:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$KEY.private" ] && [ -f "$KEY.public" ] || { echo "missing $KEY.private / $KEY.public" >&2; exit 2; }
case "$(cd "$(dirname "$KEY")" && pwd)/" in "$ROOT"/*) echo "refusing: keep the signing key outside the repository" >&2; exit 2;; esac
grep -qxF "$(tr -d '\r\n' < "$KEY.public")" "$ROOT/app/src/main/assets/trusted_threat_keys.txt" \
  || echo "warning: this public key is not in app/src/main/assets/trusted_threat_keys.txt; release builds will reject the bundle" >&2
CLASSES="$(mktemp -d)"; OUT="$ROOT/tools/feed/out"; mkdir -p "$OUT"
javac -encoding UTF-8 --release 17 -d "$CLASSES" "$ROOT"/core/src/main/java/com/aegis/core/*.java
ALLOW="$ROOT/tools/feed-allowlist.txt"; [ -f "$ALLOW" ] || ALLOW=-
java -cp "$CLASSES" com.aegis.core.FeedBuilder "$ROOT/tools/feed-sources.txt" "$ALLOW" "$OUT/entries.txt" "$OUT/ATTRIBUTION.txt"
java -cp "$CLASSES" com.aegis.core.ThreatBundleTool sign "$KEY" "$SEQ" 30 "$OUT/entries.txt" "$OUT/aegis.bundle"
if [ "$SEED" = "--seed" ]; then cp "$OUT/aegis.bundle" "$ROOT/app/src/main/assets/threat_seed.bundle"; echo "seed copied into app assets"; fi
rm -rf "$CLASSES"
