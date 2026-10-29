package com.aegis.app

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.agentsdk.AegisProtocol
import com.aegis.agentsdk.ApprovalToken
import com.aegis.core.AgentFirewall
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * The agent gateway over its real Messenger interface on Android: pairing, policy verdicts, approvals, signed tokens
 * (Android Keystore key), the capability broker, the kill switch and the encrypted log store.
 *
 * Limitation: the test runs inside Aegis' own process, so the "agent" is Aegis itself (same UID, same certificate) and
 * the calls do not cross a process boundary. Caller identification, certificate pinning and every policy path are the
 * production code; cross-process binder delivery is not covered here.
 */
class AgentGatewayDeviceTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val self get() = context.packageName
    private val trustedHost = "api.example.com"

    /** Minimal Messenger client, the same wire format as the SDK's AegisClient. */
    private class Client(context: Context) : AutoCloseable {
        private val replies = LinkedBlockingQueue<Pair<Int, Bundle>>()
        private val thread = HandlerThread("test-gateway-replies").apply { start() }
        val replyTo = Messenger(object : Handler(thread.looper) {
            override fun handleMessage(msg: Message) { replies.add(msg.what to Bundle(msg.data ?: Bundle())) }
        })
        private val bound = LinkedBlockingQueue<Messenger>()
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder) { bound.add(Messenger(binder)) }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        private val app = context.applicationContext
        val service: Messenger

        init {
            assertTrue(app.bindService(Intent(app, AgentGatewayService::class.java), connection, Context.BIND_AUTO_CREATE))
            service = bound.poll(10, TimeUnit.SECONDS) ?: error("gateway did not bind")
        }

        /** Sends one request and waits for the reply that echoes its requestId. */
        fun call(what: Int, data: Bundle): Bundle {
            val id = UUID.randomUUID().toString()
            data.putString(AegisProtocol.KEY_REQUEST_ID, id)
            service.send(Message.obtain(null, what).also { it.data = data; it.replyTo = replyTo })
            return awaitWhere { it.getString(AegisProtocol.KEY_REQUEST_ID) == id }.second
        }

        fun awaitWhere(timeoutMs: Long = 10_000, match: (Bundle) -> Boolean): Pair<Int, Bundle> {
            val end = System.currentTimeMillis() + timeoutMs
            while (true) {
                val left = end - System.currentTimeMillis()
                val r = replies.poll(left.coerceAtLeast(0), TimeUnit.MILLISECONDS) ?: error("no reply within $timeoutMs ms")
                if (match(r.second)) return r
            }
        }

        override fun close() { runCatching { app.unbindService(connection) }; thread.quitSafely() }
    }

    private fun request(type: String, destination: String, payload: String, provenance: String = "USER_DIRECT") = Bundle().apply {
        putString(AegisProtocol.KEY_TYPE, type); putString(AegisProtocol.KEY_DESTINATION, destination)
        putString(AegisProtocol.KEY_SUMMARY, "device test"); putString(AegisProtocol.KEY_PAYLOAD, payload)
        putString(AegisProtocol.KEY_PROVENANCE, provenance)
    }

    private fun Bundle.verdict() = getString(AegisProtocol.KEY_VERDICT)
    private fun Bundle.reasons() = getStringArray(AegisProtocol.KEY_REASONS)?.toList() ?: emptyList()

    /** The person's approval of the pairing, as the pairing dialog does it. */
    private fun pairSelf() {
        val cert = AgentGateway.signerDigest(context.packageManager, self)
        assertNotNull("own signing certificate readable", cert)
        AgentGateway.approvePairing(context, PairRequest(self, cert!!))
        assertEquals(AgentGateway.Status.PAIRED, AgentGateway.status(self, cert))
    }

    private fun events(): List<AgentFirewall.Event> = (AgentGateway.firewall.auditLog() + AgentGateway.firewall.securityLog()).map { it.event() }

    private fun waitUntil(timeoutMs: Long = 10_000, what: String, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (!condition()) { if (System.currentTimeMillis() > end) fail("timed out waiting for $what"); Thread.sleep(50) }
    }

    @Before fun clean() {
        AgentGateway.load(context)
        cleanUp()
        // These tests make many quick calls, which the behaviour watch would rightly rate as automated; it has its own test below.
        AgentWatch.enabled = false
    }

    @After fun cleanUp() {
        if (AgentGateway.lockdown.value) AgentGateway.releaseKillSwitch(context)
        AgentGateway.approvals.value.forEach { AgentGateway.resolve(context, it.id, false) }
        AgentGateway.pairings.value.forEach { AgentGateway.rejectPairing(context, it) }
        if (AgentGateway.paired.value.containsKey(self)) AgentGateway.unpair(context, self)
        AgentGateway.removeTrusted(context, trustedHost)
        AgentGateway.removeTrusted(context, "example.com")
        AgentWatch.clearForTest()
        AgentWatch.enabled = true
    }

    /** Behaviour watch through the real gateway: calls at machine pace pause the agent, "yes, that was me" lets it continue. */
    @Test fun machinePacedAgentIsAskedIsThisYou() {
        AgentWatch.enabled = true
        AgentWatch.clearForTest()
        pairSelf()
        assertTrue(AgentGateway.addTrusted(context, trustedHost))
        Client(context).use { c ->
            // Eight calls far less than 4 s apart: the machine-pace rule.
            val verdicts = (1..8).map { c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://$trustedHost/v1", "note $it")) }
            assertEquals("first calls allowed", AegisProtocol.VERDICT_ALLOW, verdicts.first().verdict())
            val last = verdicts.last()
            assertEquals(last.reasons().toString(), AegisProtocol.VERDICT_ASK_USER, last.verdict())
            assertTrue("asks Is this you?", "IS_THIS_YOU" in last.reasons())
            val session = AgentWatch.needsAnswer.value.single { it.actor() == self }
            assertTrue(session.reasons().contains("MACHINE_PACE") || session.reasons().contains("WHILE_LOCKED"))
            AgentWatch.confirm(context, session)
            assertTrue(AgentWatch.needsAnswer.value.none { it.actor() == self })
            assertEquals("confirmed session runs again", AegisProtocol.VERDICT_ALLOW, c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://$trustedHost/v1", "after")).verdict())
        }
    }

    @Test fun unpairedCallerIsRefusedAndAskedToPair() {
        Client(context).use { c ->
            val r = c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://$trustedHost/v1", "hello"))
            assertEquals(AegisProtocol.VERDICT_NOT_PAIRED, r.verdict())
            assertEquals(listOf("PAIRING_REQUIRED"), r.reasons())
            assertTrue("pairing request raised", AgentGateway.pairings.value.any { it.packageName == self })
            // Approving that request (what the pairing dialog does) makes the same caller a paired agent.
            AgentGateway.approvePairing(context, AgentGateway.pairings.value.first { it.packageName == self })
            AgentGateway.addTrusted(context, trustedHost)
            assertEquals(AegisProtocol.VERDICT_ALLOW, c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://$trustedHost/v1", "hello")).verdict())
        }
    }

    @Test fun allowedCallCarriesATokenTheServerAccepts() {
        pairSelf()
        assertTrue(AgentGateway.addTrusted(context, trustedHost))
        val dest = "https://$trustedHost/v1/notes"
        val body = "shopping list: milk"
        Client(context).use { c ->
            val r = c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", dest, body))
            assertEquals(r.reasons().toString(), AegisProtocol.VERDICT_ALLOW, r.verdict())
            val token = r.getString(AegisProtocol.KEY_TOKEN)
            assertNotNull("ALLOW with a destination host carries a token", token)
            val key = ApprovalSigner.publicKey()
            assertNotNull("Keystore signing key available", key)
            val verifier = ApprovalToken.Verifier(listOf(key!!), ApprovalToken.MemoryReplayCache(100), 30)
            val now = System.currentTimeMillis() / 1000
            fun expect(b: String, aud: String = trustedHost) = ApprovalToken.Expect(aud, b.toByteArray(Charsets.UTF_8), dest, setOf(self), setOf("SEND_DATA"))
            // Failing checks first: a refused token is not recorded as used.
            assertEquals("BODY_MISMATCH", verifier.verify(token, expect("something else"), now).reason())
            assertEquals("WRONG_AUDIENCE", verifier.verify(token, expect(body, "evil.example.net"), now).reason())
            assertEquals("EXPIRED", verifier.verify(token, expect(body), now + ApprovalSigner.LIFETIME_SECONDS + 60).reason())
            val ok = verifier.verify(token, expect(body), now)
            assertTrue(ok.reason(), ok.ok())
            assertEquals(ApprovalToken.GRANT_POLICY_ALLOW, ok.claims().grant())
            assertEquals("REPLAYED", verifier.verify(token, expect(body), now).reason())
            assertTrue(AgentFirewall.Event.TOKEN_ISSUED in events())
        }
    }

    @Test fun riskyActionIsRefusedForAnAgentWithoutRiskyGrant() {
        pairSelf()
        Client(context).use { c ->
            val r = c.call(AegisProtocol.MSG_EVALUATE, request("INSTALL_APP", "https://store.example.org/app.apk", ""))
            assertEquals(AegisProtocol.VERDICT_DENY, r.verdict())
            assertEquals(listOf("ACTION_NOT_PERMITTED_FOR_AGENT"), r.reasons())
        }
    }

    @Test fun askedCallNeedsTheApprovalAndRedeemsOnce() {
        pairSelf()
        val dest = "https://notes.example.net/upload"
        val req = { request("SEND_DATA", dest, "meeting notes") }
        Client(context).use { c ->
            val r = c.call(AegisProtocol.MSG_EVALUATE, req())
            assertEquals(AegisProtocol.VERDICT_ASK_USER, r.verdict())
            val id = r.getString(AegisProtocol.KEY_APPROVAL_ID)!!
            assertTrue("shown to the person", AgentGateway.approvals.value.any { it.id == id && it.destinationHost == "notes.example.net" })
            val redeem = { b: Bundle -> b.apply { putString(AegisProtocol.KEY_APPROVAL_ID, id) } }
            assertFalse("not before the person answers", c.call(AegisProtocol.MSG_REDEEM, redeem(req())).getBoolean(AegisProtocol.KEY_GRANTED))
            AgentGateway.resolve(context, id, true)
            // Bound to the exact request: a different payload is refused.
            assertFalse(c.call(AegisProtocol.MSG_REDEEM, redeem(request("SEND_DATA", dest, "all my contacts"))).getBoolean(AegisProtocol.KEY_GRANTED))
            val granted = c.call(AegisProtocol.MSG_REDEEM, redeem(req()))
            assertTrue(granted.getBoolean(AegisProtocol.KEY_GRANTED))
            val token = granted.getString(AegisProtocol.KEY_TOKEN)
            assertNotNull(token)
            val v = ApprovalToken.Verifier(listOf(ApprovalSigner.publicKey()!!), ApprovalToken.MemoryReplayCache(10), 30)
                .verify(token, ApprovalToken.Expect("notes.example.net", "meeting notes".toByteArray(), dest, null, null), System.currentTimeMillis() / 1000)
            assertTrue(v.reason(), v.ok())
            assertEquals(ApprovalToken.GRANT_USER_APPROVED, v.claims().grant())
            assertFalse("single use", c.call(AegisProtocol.MSG_REDEEM, redeem(req())).getBoolean(AegisProtocol.KEY_GRANTED))
            assertTrue(events().containsAll(listOf(AgentFirewall.Event.USER_APPROVED, AgentFirewall.Event.REDEEMED, AgentFirewall.Event.REDEEM_REFUSED)))
        }
    }

    @Test fun brokerAllowReturnsOneShotLauncherAndAskWaitsForThePerson() {
        pairSelf()
        AgentGateway.addTrusted(context, "example.com")
        // Foreground, so the launcher may start Aegis' broker activity.
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            Client(context).use { c ->
                val open = c.call(AegisProtocol.MSG_BROKER, Bundle().apply {
                    putString(AegisProtocol.KEY_BROKER_ACTION, AegisProtocol.BROKER_OPEN_URL); putString(AegisProtocol.KEY_VALUE, "https://example.com/")
                    putString(AegisProtocol.KEY_SUMMARY, "open the page"); putString(AegisProtocol.KEY_PROVENANCE, "USER_DIRECT")
                })
                assertEquals(open.reasons().toString(), AegisProtocol.VERDICT_ALLOW, open.verdict())
                @Suppress("DEPRECATION") val launch = open.getParcelable<PendingIntent>(AegisProtocol.KEY_LAUNCH)
                assertNotNull(launch)
                val before = events().count { it == AgentFirewall.Event.BROKER_PERFORMED || it == AgentFirewall.Event.BROKER_FAILED }
                launch!!.send()
                // Performed when the image has a browser, NO_APP_TO_HANDLE otherwise; either way the ticket was used and logged.
                waitUntil(what = "broker outcome logged") { events().count { it == AgentFirewall.Event.BROKER_PERFORMED || it == AgentFirewall.Event.BROKER_FAILED } > before }
                try { launch.send(); fail("one-shot launcher was usable twice") } catch (_: PendingIntent.CanceledException) { }

                // Plain URLs are refused before policy.
                val http = c.call(AegisProtocol.MSG_BROKER, Bundle().apply {
                    putString(AegisProtocol.KEY_BROKER_ACTION, AegisProtocol.BROKER_OPEN_URL); putString(AegisProtocol.KEY_VALUE, "http://example.com/")
                    putString(AegisProtocol.KEY_PROVENANCE, "USER_DIRECT")
                })
                assertEquals(AegisProtocol.VERDICT_DENY, http.verdict())

                // Sharing text has no trusted destination, so the person decides; denying reports back to the agent.
                val share = c.call(AegisProtocol.MSG_BROKER, Bundle().apply {
                    putString(AegisProtocol.KEY_BROKER_ACTION, AegisProtocol.BROKER_SHARE_TEXT); putString(AegisProtocol.KEY_VALUE, "see you at 6")
                    putString(AegisProtocol.KEY_SUMMARY, "share the time"); putString(AegisProtocol.KEY_PROVENANCE, "USER_DIRECT")
                })
                assertEquals(AegisProtocol.VERDICT_ASK_USER, share.verdict())
                val id = share.getString(AegisProtocol.KEY_APPROVAL_ID)!!
                assertEquals("SHARE_TEXT", AgentGateway.approvals.value.single { it.id == id }.broker)
                // The agent cannot redeem a brokered approval for its own use.
                assertFalse(c.call(AegisProtocol.MSG_REDEEM, request("SEND_DATA", "", "see you at 6").apply { putString(AegisProtocol.KEY_APPROVAL_ID, id) })
                    .getBoolean(AegisProtocol.KEY_GRANTED))
                AgentGateway.resolve(context, id, false)
                val done = c.awaitWhere { it.getString(AegisProtocol.KEY_APPROVAL_ID) == id && it.containsKey(AegisProtocol.KEY_PERFORMED) }
                assertEquals(AegisProtocol.MSG_BROKER_DONE, done.first)
                assertFalse(done.second.getBoolean(AegisProtocol.KEY_PERFORMED))
                assertEquals("DENIED_BY_USER", done.second.getString(AegisProtocol.KEY_REASON))
            }
        }
    }

    @Test fun killSwitchRefusesEverythingAndRemovesAgents() {
        pairSelf()
        AgentGateway.addTrusted(context, trustedHost)
        Client(context).use { c ->
            val waiting = c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://other.example.net/x", "notes"))
            assertEquals(AegisProtocol.VERDICT_ASK_USER, waiting.verdict())
            val id = waiting.getString(AegisProtocol.KEY_APPROVAL_ID)!!
            AgentGateway.resolve(context, id, true) // approved but not yet used

            val removed = AgentGateway.killSwitch(context)
            assertTrue(self in removed)
            assertTrue(AgentGateway.paired.value.isEmpty())
            assertTrue(AgentGateway.approvals.value.isEmpty())
            assertTrue("lockdown survives a restart", context.getSharedPreferences("agent_state", Context.MODE_PRIVATE).getBoolean("lockdown", false))

            val r = c.call(AegisProtocol.MSG_EVALUATE, request("SEND_DATA", "https://$trustedHost/v1", "hello"))
            assertEquals(AegisProtocol.VERDICT_DENY, r.verdict())
            assertEquals(listOf("KILL_SWITCH_ON"), r.reasons())
            assertNull("no token while locked", r.getString(AegisProtocol.KEY_TOKEN))
            assertFalse("approved-but-unused approval cancelled",
                c.call(AegisProtocol.MSG_REDEEM, request("SEND_DATA", "https://other.example.net/x", "notes").apply { putString(AegisProtocol.KEY_APPROVAL_ID, id) })
                    .getBoolean(AegisProtocol.KEY_GRANTED))
            assertTrue("no pairing request while locked", AgentGateway.pairings.value.isEmpty())

            AgentGateway.releaseKillSwitch(context)
            assertFalse(AgentGateway.lockdown.value)
            val cert = AgentGateway.signerDigest(context.packageManager, self)!!
            assertEquals("removed agents must pair again", AgentGateway.Status.UNPAIRED, AgentGateway.status(self, cert))
            assertTrue(events().containsAll(listOf(AgentFirewall.Event.KILL_SWITCH_ON, AgentFirewall.Event.KILL_SWITCH_OFF)))
        }
    }

    @Test fun auditLogIsSavedEncryptedAndChained() {
        pairSelf() // a security event, saved straight away
        val saved = SealedStore.read(context, "agent_security")
        assertTrue("security log readable back", saved is SealedStore.Read.Ok)
        assertTrue((saved as SealedStore.Read.Ok).text.contains(self))
        val raw = File(File(context.filesDir, "sealed"), "agent_security").readBytes()
        assertFalse("not stored in plain text", String(raw, Charsets.ISO_8859_1).contains(self))
        assertTrue(AgentGateway.firewall.verifySecurityLog())
    }

    @Test fun sealedStoreRejectsTamperingAndSwappedFiles() {
        val a = "devtest_a"; val b = "devtest_b"
        try {
            SealedStore.delete(context, a); SealedStore.delete(context, b)
            assertEquals(SealedStore.Read.Missing, SealedStore.read(context, a))
            assertTrue(SealedStore.write(context, a, "secret ✓ text"))
            assertEquals(SealedStore.Read.Ok("secret ✓ text"), SealedStore.read(context, a))
            val dir = File(context.filesDir, "sealed")
            val bytes = File(dir, a).readBytes()
            // The same ciphertext under another name fails: the file name is bound as associated data.
            File(dir, b).writeBytes(bytes)
            assertEquals(SealedStore.Read.Unreadable, SealedStore.read(context, b))
            // One flipped bit fails authentication.
            bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
            File(dir, a).writeBytes(bytes)
            assertEquals(SealedStore.Read.Unreadable, SealedStore.read(context, a))
        } finally { SealedStore.delete(context, a); SealedStore.delete(context, b) }
    }
}
