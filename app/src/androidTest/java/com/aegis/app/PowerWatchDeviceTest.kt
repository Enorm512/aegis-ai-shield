package com.aegis.app

import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.AppWatch
import com.aegis.core.CapabilityWatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The "who can control this phone" scan and the installed-app scan on Android, with Android's real package visibility.
 * What an emulator shows is not what a real phone shows (other preinstalled apps, OEM services).
 */
class PowerWatchDeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun scansSeeTheKeyboardAndOwnAppWithSignerAndVersion() {
        val holders = PowerWatch.scan(context)
        assertTrue("an enabled keyboard is always listed: ${holders.holders()}", holders.holders().any { it.capability() == CapabilityWatch.Capability.INPUT_METHOD })

        val apps = PowerWatch.scanApps(context)
        val own = apps.apps()[context.packageName]
        assertNotNull("own app visible to itself", own)
        assertTrue("signer digest read: ${own!!.signer()}", own.signer().matches(Regex("[0-9a-f]{64}")))
        assertTrue(own.versionCode() > 0)
        // Round trip of what is stored as the baseline.
        assertEquals(apps.apps(), AppWatch.Snapshot.parse(apps.serialize())!!.apps())
        // Against itself nothing has changed.
        assertTrue(AppWatch.diff(apps, apps, holders.holders().map { it.packageName() }.toSet(), context.packageName).isEmpty())
    }

    @Test fun refreshPublishesStateWithoutAlertsOnAnUnchangedPhone() {
        PowerWatch.refresh(context) // first call may set the baselines
        PowerWatch.refresh(context)
        val s = PowerWatch.state.value
        assertTrue(s.loaded)
        assertTrue("no app changes on an unchanged phone: ${s.appChanges}", s.appChanges.isEmpty())
    }
}
