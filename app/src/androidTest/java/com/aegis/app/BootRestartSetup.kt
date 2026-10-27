package com.aegis.app

import android.content.Intent
import android.net.VpnService
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Setup step of the CI boot-restart job (tools/ci/boot_restart.sh), not a test on its own: turns protection on and
 * leaves it recorded as wanted. Skipped unless the instrumentation argument bootSetup=1 is given, so a normal test run
 * never leaves protection switched on.
 */
class BootRestartSetup {
    @Test fun turnProtectionOnAndLeaveItWanted() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("bootSetup") == "1")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("VPN consent in place", VpnService.prepare(context))
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            AegisVpnService.start(context)
            val end = System.currentTimeMillis() + 15_000
            while (!Protection.running.value && System.currentTimeMillis() < end) Thread.sleep(100)
            assertTrue("tunnel up before the reboot", Protection.running.value)
            assertTrue(Protection.wanted(context))
        }
    }
}
