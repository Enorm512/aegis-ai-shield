package com.aegis.app

import android.content.Intent
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.aegis.core.ResultSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.util.Locale

/**
 * Run on an Android device/emulator; no network or external APK is required. These tests have been COMPILED but
 * never executed (no device was available when they were written).
 */
class DashboardSmokeTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val norwegian get() = Locale.getDefault().language in listOf("nb", "no", "nn")
    private fun t(en: String, no: String) = if (norwegian) no else en
    private fun intent() = Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java)
    private fun waitFor(text: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithText(text, ignoreCase = true).fetchSemanticsNodes().isNotEmpty() }
    }
    private fun openCheck() { compose.onNodeWithText(t("Check", "Sjekk")).performClick() }
    /** The Check screen's own button. "Check" alone also matches the bottom-bar tab of the same name. */
    private fun checkButton() = compose.onNode(hasText(t("Check", "Sjekk")) and SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))

    @Test fun homeRendersWithStatusAndNavigation() {
        ActivityScenario.launch<MainActivity>(intent()).use {
            compose.onNodeWithText("AEGIS").assertIsDisplayed()
            compose.onNodeWithText(t("Nothing needs your attention", "Ingenting krever oppmerksomheten din")).assertIsDisplayed()
            for (label in listOf(t("Home", "Hjem"), t("Check", "Sjekk"), t("Protection", "Beskyttelse"), t("More", "Mer"))) compose.onNodeWithText(label).assertIsDisplayed()
        }
    }

    @Test fun benignUrlShowsQualifiedResult() {
        ActivityScenario.launch<MainActivity>(intent()).use {
            openCheck()
            compose.onNode(hasSetTextAction()).performTextInput("https://example.com")
            checkButton().performClick()
            waitFor(t("No known warning signs", "Ingen kjente faresignaler"))
            compose.onNodeWithText(t("Nothing matched the rules and lists on this device.", "Ingenting traff reglene og listene på denne enheten."), substring = true).assertExists()
        }
    }

    @Test fun malformedLinkShowsUnclearNotSafe() {
        ActivityScenario.launch<MainActivity>(intent()).use {
            openCheck()
            compose.onNode(hasSetTextAction()).performTextInput("https://")
            compose.onNodeWithText(t("Link", "Lenke")).performClick()
            checkButton().performClick()
            waitFor(t("Couldn't assess this link", "Kunne ikke vurdere lenken"))
        }
    }

    @Test fun sharedTextIsCheckedAutomaticallyAndExplainsWhatToDo() {
        val share = intent().setAction(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, "Please send your password immediately")
        ActivityScenario.launch<MainActivity>(share).use {
            waitFor(t("Strong signs of a scam", "Sterke tegn på svindel"))
            compose.onNodeWithText(t("What to do", "Hva bør du gjøre")).assertExists()
        }
    }

    @Test fun shareDuringAnalysisDiscardsPreviousResult() {
        ActivityScenario.launch<MainActivity>(intent()).use { scenario ->
            lateinit var model: AegisViewModel
            scenario.onActivity { activity ->
                model = ViewModelProvider(activity)[AegisViewModel::class.java]
                model.input("https://example.com")
                model.analyze()
                // Same main-thread turn: delivery predates publication from the worker.
                model.shared("New shared message")
            }
            compose.waitUntil(5_000) { !model.state.value.busy && model.state.value.result != null }
            assertEquals("New shared message", model.state.value.input)
            assertEquals(ResultSummary.Subject.MESSAGE, model.state.value.result?.summary?.subject)
        }
    }

    @Test fun languageAndThemeControlsWork() {
        ActivityScenario.launch<MainActivity>(intent()).use {
            compose.onNodeWithText(t("More", "Mer")).performClick()
            compose.onAllNodes(isToggleable())[0].assertIsOn().performClick().assertIsOff()
            compose.onNodeWithText(if (norwegian) "English" else "Norsk").performClick()
            compose.onNodeWithText(if (norwegian) "Appearance and language" else "Utseende og språk").assertExists()
        }
    }

    @Test fun waitingAgentRequestShowsBannerAndCanBeDenied() {
        ActivityScenario.launch<MainActivity>(intent()).use {
            AgentGateway.addApproval(ApprovalItem("a".repeat(32), "com.example.assistant", "INSTALL_APP", "store.example.org", "Install calculator", listOf("INSTALL_APP"), System.currentTimeMillis()))
            waitFor(t("An AI agent is waiting for your decision", "En KI-agent venter på avgjørelsen din"))
            // Both the top banner and the Home attention item offer "Review"; either opens the same review dialog.
            compose.onAllNodesWithText(t("Review", "Se på")).onFirst().performClick()
            compose.onNodeWithText(t("Deny", "Nekt")).assertIsDisplayed().performClick()
            compose.waitUntil(5_000) { compose.onAllNodesWithText(t("An AI agent is waiting for your decision", "En KI-agent venter på avgjørelsen din")).fetchSemanticsNodes().isEmpty() }
            assertTrue(AgentGateway.approvals.value.isEmpty())
        }
    }
}
