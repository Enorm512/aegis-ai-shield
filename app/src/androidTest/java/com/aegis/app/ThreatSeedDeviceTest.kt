package com.aegis.app

import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.Analysis
import com.aegis.core.ThreatBundleTool
import com.aegis.core.ThreatBundleVerifier
import com.aegis.core.ThreatChecks
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64

/**
 * Bundled-seed and update path of the signed threat database on Android, with the debug build's published test key
 * (copied into the test APK's assets; the release build does not trust it). Bundles are signed at test time so they
 * never expire in the repository.
 */
class ThreatSeedDeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun testAsset(name: String) = InstrumentationRegistry.getInstrumentation().context.assets.open(name).use { String(it.readBytes(), Charsets.US_ASCII).trim() }

    private fun bundle(key: PrivateKey, publicB64: String, sequence: Long, entries: List<String>): ByteArray {
        val now = Instant.now()
        val keyId = ThreatBundleVerifier.TrustAnchors.keyId(Base64.getDecoder().decode(publicB64))
        return ThreatBundleTool.build(key, keyId, sequence, now, now.plus(30, ChronoUnit.DAYS), entries)
    }

    @Test fun signedSeedIsInstalledUsedAndNeverRolledBack() {
        val store = ThreatIntel.holder(context).store
        val pub = testAsset("debug-threat-key.public")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(testAsset("debug-threat-key.private"))))
        val keyId = ThreatBundleVerifier.TrustAnchors.keyId(Base64.getDecoder().decode(pub))
        val domain = "seed-" + ByteArray(5).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) } + ".example"
        val seq = maxOf(store.floorOf(keyId), store.current().sequence) + 1
        val seed = bundle(key, pub, seq, listOf("D $domain PHISHING CONFIRMED device-test"))

        assertEquals("OK", ThreatIntel.installSeed(store, seed))
        assertEquals(seq, store.current().sequence)
        assertEquals("the link check uses it", Analysis.Verdict.CONFIRMED_MALICIOUS, ThreatChecks.url("https://$domain/login", ThreatIntel.get(context)).verdict)

        // The same seed again (e.g. the app restarted) changes nothing.
        assertEquals("NOT_NEWER", ThreatIntel.installSeed(store, seed))
        // An older bundle is refused even though it is validly signed.
        assertEquals("NOT_NEWER", ThreatIntel.installSeed(store, bundle(key, pub, seq - 1, listOf("D other.example SCAM STRONG device-test"))))
        // An altered bundle and one from a key the build does not trust are refused; the installed database stays.
        val altered = bundle(key, pub, seq + 1, listOf("D $domain PHISHING CONFIRMED device-test")).also { it[it.size / 3] = (it[it.size / 3].toInt() xor 0x20).toByte() }
        assertEquals(true, ThreatIntel.installSeed(store, altered) in setOf("BAD_SIGNATURE", "MALFORMED", "BAD_ENTRY"))
        val stranger = ThreatBundleTool.generateKey()
        assertEquals("UNTRUSTED_KEY", ThreatIntel.installSeed(store, bundle(stranger.private, Base64.getEncoder().encodeToString(stranger.public.encoded), seq + 1, listOf("D x.example SCAM STRONG t"))))
        assertEquals(seq, store.current().sequence)
    }
}
