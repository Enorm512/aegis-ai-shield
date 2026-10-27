# Debug test key (NOT a production key)
`debug.private` is committed deliberately so anyone can make test bundles for the **debug** build, which trusts `debug.public` via `app/src/debug/assets/trusted_threat_keys.txt`. The release build trusts no key. Never reuse this key for anything real.

Test on a device: copy `sample-v1.bundle` then `sample-v2.bundle` to the phone (Downloads), open Device tab, Import. Then check the link `https://aegis-test-phish.example` (expect "Known malicious match"). Importing v1 again must be rejected as not newer; "Restore previous database" returns to v1 and v2 stays refused afterwards.
Re-sign with: `java -cp <classes> com.aegis.core.ThreatBundleTool sign tools/debug-test-key/debug <seq> <days> <entries.txt> <out>`. Bundles are valid 60 days from creation (apps refuse bundles valid for more than 100 days); re-sign when they expire.
