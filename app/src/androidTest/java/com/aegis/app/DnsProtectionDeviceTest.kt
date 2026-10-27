package com.aegis.app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.CanaryTokens
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.InetAddress
import java.net.UnknownHostException
import java.security.SecureRandom

/**
 * The DNS-only VPN on Android: the tunnel comes up, a name on the person's block list is answered NXDOMAIN by Aegis'
 * filter, a planted tripwire name is caught, and the tunnel shuts down cleanly.
 *
 * VPN consent is granted with `appops set <package> ACTIVATE_VPN allow` from the instrumentation shell, which stands
 * in for the person tapping OK on the system's VPN dialog. No upstream resolver is needed: only filtered names are looked up.
 */
class DnsProtectionDeviceTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun shell(cmd: String): String {
        val pfd = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(cmd)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().use { it.readText() }
    }

    private fun waitUntil(timeoutMs: Long = 15_000, what: String, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (!condition()) { if (System.currentTimeMillis() > end) fail("timed out waiting for $what"); Thread.sleep(100) }
    }

    private fun randomLabel() = ByteArray(6).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

    @Test fun blockListAndTripwireWorkThroughTheTunnel() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertNull("VPN consent in place", VpnService.prepare(context))
        Protection.load(context)
        // Fresh names each run, so no resolver cache can answer for the filter.
        val blockedName = "blocked-${randomLabel()}.aegis-device-test.net"
        assertTrue(Protection.block(context, blockedName))
        val token = Tripwires.load(context).plant(CanaryTokens.Kind.NOTE, SecureRandom(), System.currentTimeMillis())
        // Foreground, as when the person turns protection on from the Protection screen.
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            try {
                AegisVpnService.start(context)
                waitUntil(what = "tunnel up") { Protection.running.value && Protection.proxy != null }

                val before = Protection.snapshot().blocked
                try { InetAddress.getByName(blockedName); fail("blocked name resolved") } catch (_: UnknownHostException) { }
                waitUntil(what = "block counted") { Protection.snapshot().blocked > before }
                assertTrue(Protection.snapshot().recent.any { it.name() == blockedName })

                Tripwires.selfTest(context, token)
                waitUntil(what = "tripwire test finished") { !Tripwires.state.value.testRunning && Tripwires.state.value.testResult != null }
                assertEquals("tripwire seen by the DNS filter", "ok", Tripwires.state.value.testResult)
                assertTrue(Tripwires.state.value.trips.any { it.tokenId == token.id() && it.test })
            } finally {
                AegisVpnService.stop(context)
                waitUntil(what = "tunnel down") { !Protection.running.value }
                Protection.removeBlock(context, blockedName)
                Tripwires.remove(context, token.id())
                Tripwires.clearTrips(context)
            }
        }
    }
}
