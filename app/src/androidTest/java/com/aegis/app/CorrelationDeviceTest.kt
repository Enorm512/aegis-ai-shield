package com.aegis.app

import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.CapabilityWatch
import com.aegis.core.Correlator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/** Correlation on Android: signals are kept encrypted, linked into an incident, and hidden once the person dismisses them. */
class CorrelationDeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun installThenScreenControlBecomesOneHighIncidentUntilDismissed() {
        val pkg = "com.example.devtest.rogue"
        val now = Instant.now()
        Signals.record(context, listOf(
            Correlator.Signal(now.minusSeconds(600), Correlator.Kind.APP_RISKY_CHANGE, pkg, "INSTALLED"),
            Correlator.Signal(now.minusSeconds(60), Correlator.Kind.POWER_GRANTED, pkg, "ACCESSIBILITY")))
        val i = Signals.incidents.value.single { pkg in it.packages() }
        assertEquals(Correlator.Rule.NEW_APP_GAINED_POWER, i.rule())
        assertEquals(CapabilityWatch.Risk.HIGH, i.risk())

        val saved = SealedStore.read(context, "correlation_signals")
        assertTrue("signals saved encrypted", saved is SealedStore.Read.Ok && saved.text.contains(pkg))

        Signals.dismiss(context)
        Signals.evaluate(context)
        assertTrue("dismissed incidents stay hidden", Signals.incidents.value.none { pkg in it.packages() })
    }
}
