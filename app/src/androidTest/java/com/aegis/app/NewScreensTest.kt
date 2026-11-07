package com.aegis.app

import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.AgentFirewall
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Opens the real agent limit and approval screens, checks what they say, and leaves screenshots in
 * /data/local/tmp/aegis-shots (shell-owned, so they outlast the app being uninstalled; CI pulls them).
 */
class NewScreensTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val context get() = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val self get() = context.packageName
    private val payments = setOf(AgentFirewall.ActionType.FINANCIAL_TRANSACTION)

    private fun shell(command: String) {
        ParcelFileDescriptor.AutoCloseInputStream(InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }
    private fun shot(name: String) {
        compose.waitForIdle()
        Thread.sleep(600) // dialogs animate in
        shell("mkdir -p /data/local/tmp/aegis-shots")
        shell("screencap -p /data/local/tmp/aegis-shots/$name.png")
    }
    private fun waitFor(text: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithText(text, substring = true).fetchSemanticsNodes().isNotEmpty() }
    }
    private fun openProtection() {
        compose.onNodeWithText("Protection").performClick()
        waitFor("Stop one kind of action")
    }
    private fun ask(): String {
        val r = AgentFirewall.Request(self, AgentFirewall.ActionType.READ_SENSITIVE, "", "Read my messages", "", AgentFirewall.Provenance.USER_DIRECT, -1, null)
        val d = AgentGateway.firewall.evaluate(r)
        AgentGateway.addApproval(ApprovalItem(d.approvalId(), self, "READ_SENSITIVE", "", "Read my messages", d.reasons(), System.currentTimeMillis(),
            chain = listOf("SEND_DATA|api.example.com|ALLOWED|0")))
        return d.approvalId()
    }

    @Before fun setUp() {
        AgentGateway.load(context)
        cleanUp()
        AgentGateway.approvePairing(context, PairRequest(self, AgentGateway.signerDigest(context.packageManager, self)!!))
    }

    @After fun cleanUp() {
        AgentGateway.screenLockSet = { false }
        if (AgentGateway.stopped.value.isNotEmpty()) AgentGateway.setStopped(context, AgentGateway.stopped.value, false)
        AgentGateway.approvals.value.forEach { AgentGateway.resolve(context, it.id, false) }
        if (AgentGateway.paired.value.containsKey(self)) AgentGateway.unpair(context, self)
    }

    private fun launch(block: () -> Unit) = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use { block() }

    @Test fun stopsCardAndItsConfirmation() = launch {
        openProtection()
        compose.onNodeWithText("Payments").performScrollTo().performClick()
        waitFor("Stopped")
        compose.onNodeWithText("Stop one kind of action").performScrollTo()
        shot("1-stops-card")
        compose.onNodeWithText("Payments").performScrollTo().performClick()
        waitFor("Allow this again?")
        compose.onAllNodesWithText("Payments").assertCountEquals(2) // the card's row and the dialog naming it
        shot("2-allow-again-dialog")
        compose.onNodeWithText("Keep it stopped").performClick()
        compose.onNodeWithText("Stopped").assertExists()
    }

    @Test fun readOnlyRowAndItsConfirmation() = launch {
        openProtection()
        compose.onNodeWithText("Read only").performScrollTo().performClick()
        compose.waitUntil(5_000) { self in AgentGateway.readOnly.value }
        shot("3-read-only-on")
        compose.onNodeWithText("Read only").performScrollTo().performClick()
        waitFor("Turn off read only?")
        shot("4-read-only-off-dialog")
        compose.onNodeWithText("Keep it on").performClick()
        compose.onNodeWithText("Turn off read only?").assertDoesNotExist()
    }

    @Test fun approvalDialogSaysWhatTheCheckWillBe() = launch {
        AgentGateway.screenLockSet = { true }
        ask()
        openProtection()
        compose.onNodeWithText("Review 1 waiting request(s)").performScrollTo().performClick()
        waitFor("Approving needs your fingerprint, face or screen PIN.")
        compose.onNodeWithText("$self wants to: read private data").assertExists()
        compose.onNodeWithText("What this agent did just before, in order:").assertExists()
        shot("5-approval-with-screen-lock")
        compose.onNodeWithText("Decide later").performScrollTo().performClick()
    }

    @Test fun approvalDialogWarnsWithoutAScreenLock() = launch {
        ask()
        openProtection()
        compose.onNodeWithText("Review 1 waiting request(s)").performScrollTo().performClick()
        waitFor("This phone has no screen lock")
        shot("6-approval-no-screen-lock")
        compose.onNodeWithText("Decide later").performScrollTo().performClick()
    }

    @Test fun aboutShowsTheAuthorAndInstalledVersion() = launch {
        compose.onNodeWithText("More").performClick()
        val version = context.packageManager.getPackageInfo(context.packageName, 0).versionName
        compose.onNodeWithText("Made by Espen Normann. Open source under the Apache License 2.0.").performScrollTo()
        compose.onNodeWithText("Version $version", substring = true).assertExists()
        shot("7-about")
    }
}
