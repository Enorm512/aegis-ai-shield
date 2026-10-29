package com.aegis.app

import android.content.Intent
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.AgentBehaviour
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.util.Locale

/** Agent behaviour watch on Android: presence reading, AI lookups, and the "Is this you?" card on the Protection screen. */
class AgentWatchDeviceTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val norwegian get() = Locale.getDefault().language in listOf("nb", "no", "nn")
    private fun t(en: String, no: String) = if (norwegian) no else en
    private val agent = "com.example.devtest.agent"

    @Before fun clean() { AgentWatch.enabled = true; AgentWatch.clearForTest() }
    @After fun cleanUp() { AgentWatch.clearForTest(); AgentGateway.firewall.setPaused(agent, false) }

    @Test fun aiLookupsAreRatedByWhetherThePersonIsUsingThePhone() {
        val present = AgentWatch.personPresent(context)
        repeat(3) { AgentWatch.onAiLookup(context, "OpenAI"); Thread.sleep(50) }
        val s = AgentWatch.sessions.value.single { it.actor() == "OpenAI" }
        assertEquals("debounced", 1, s.events())
        // One lookup is never enough for "while locked"; in use it is the person's own AI use.
        assertEquals(AgentBehaviour.Mode.HUMAN, s.mode())
        assertEquals(if (present) 0 else 1, s.whileAway())
    }

    @Test fun autonomousAgentShowsIsThisYouUntilConfirmed() {
        repeat(8) { AgentWatch.onGatewayCall(context, agent, true) }
        assertTrue("paused", AgentGateway.firewall.paused(agent))
        assertTrue(AgentWatch.needsAnswer.value.any { it.actor() == agent })
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            compose.waitUntil(5_000) { compose.onAllNodesWithText(t("Is this you? AI activity looked like it happened without you.", "Er dette deg? KI-aktivitet så ut til å skje uten deg.")).fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText(t("Protection", "Beskyttelse")).performClick()
            compose.onNodeWithText(t("AI agent activity", "KI-agentaktivitet")).performScrollTo()
            compose.onNodeWithText(t("Yes, that was me", "Ja, det var meg")).performScrollTo().performClick()
            compose.waitUntil(5_000) { AgentWatch.needsAnswer.value.isEmpty() }
            assertTrue("unpaused after confirming", !AgentGateway.firewall.paused(agent))
            compose.onNodeWithText(t("you confirmed", "du bekreftet"), substring = true).performScrollTo()
        }
    }
}
