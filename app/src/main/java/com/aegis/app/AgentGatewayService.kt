package com.aegis.app

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import com.aegis.agentsdk.AegisProtocol
import com.aegis.agentsdk.ApprovalToken
import com.aegis.core.AgentFirewall
import com.aegis.core.AgentFirewall.ActionType
import com.aegis.core.AgentFirewall.Provenance
import com.aegis.core.AgentFirewall.Verdict
import com.aegis.core.Analysis
import com.aegis.core.CapabilityBroker
import com.aegis.core.Correlator
import com.aegis.core.ThreatChecks

/**
 * Messenger interface for AI assistants that choose to ask Aegis before a consequential action. The message formats
 * are documented in the agent SDK's AegisProtocol (shared constants), summarised here:
 *
 * MSG_EVALUATE: "type", "destination", "summary", "payload", "provenance", "currency", "amountMinor" -> MSG_RESULT
 *               "verdict" (ALLOW | ASK_USER | DENY | NOT_PAIRED), "reasons", "approvalId".
 * MSG_REDEEM:   the same fields plus "approvalId", after the person approved -> MSG_REDEEMED "granted".
 *               ALLOW results and granted redemptions carry a signed approval "token" when the call has a destination
 *               host: the agent forwards it to that server, which checks it (agent SDK ApprovalToken.Verifier).
 * MSG_BROKER:   "brokerAction" (OPEN_URL | SHARE_TEXT), "value", "summary", "provenance" -> MSG_BROKER_RESULT "verdict",
 *               "reasons", "approvalId", and for ALLOW a one-shot "launch" PendingIntent. For ASK_USER Aegis later
 *               performs the action itself when the person approves, and sends MSG_BROKER_DONE "approvalId", "performed", "reason".
 * Every reply echoes the caller's "requestId". While the kill switch is on, every request gets DENY / KILL_SWITCH_ON.
 *
 * Only paired apps are served; the caller is identified from the system-supplied sending UID and its signing
 * certificate must match the one pinned when the person paired it. This cannot see or restrain assistants that never call it.
 * Preview: never exercised on a device.
 */
class AgentGatewayService : Service() {
    private lateinit var thread: HandlerThread
    private lateinit var messenger: Messenger

    override fun onCreate() {
        super.onCreate()
        thread = HandlerThread("aegis-agent-gateway").also { it.start() }
        AgentGateway.load(this)
        messenger = Messenger(object : Handler(thread.looper) {
            override fun handleMessage(msg: Message) { handle(msg) }
        })
    }

    override fun onBind(intent: Intent?): IBinder = messenger.binder
    override fun onDestroy() { thread.quitSafely(); super.onDestroy() }

    private fun reply(to: Messenger?, what: Int, data: Bundle, requestId: String) {
        if (to == null) return
        data.putString(AegisProtocol.KEY_REQUEST_ID, requestId)
        try { to.send(Message.obtain(null, what).also { it.data = data }) } catch (_: RemoteException) { }
    }

    private fun result(verdict: String, reasons: List<String>, approvalId: String? = null) = Bundle().apply {
        putString(AegisProtocol.KEY_VERDICT, verdict); putStringArray(AegisProtocol.KEY_REASONS, reasons.toTypedArray()); putString(AegisProtocol.KEY_APPROVAL_ID, approvalId ?: "")
    }

    private fun handle(msg: Message) {
        if (msg.what != MSG_EVALUATE && msg.what != MSG_REDEEM && msg.what != MSG_BROKER) return
        // Per-UID budget before any lookup or crypto: an app that floods the gateway is dropped silently instead of costing work.
        if (!withinBudget(msg.sendingUid)) return
        try { serve(msg) } finally { AgentGateway.persistSoon(this) }
    }

    private val budget = HashMap<Int, ArrayDeque<Long>>()

    /** At most [MAX_MESSAGES_PER_MINUTE] messages per calling UID per minute. Runs on the single gateway thread. */
    private fun withinBudget(uid: Int): Boolean {
        val now = android.os.SystemClock.elapsedRealtime()
        if (budget.size > 256) budget.clear()
        val q = budget.getOrPut(uid) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > 60_000) q.removeFirst()
        if (q.size >= MAX_MESSAGES_PER_MINUTE) return false
        q.addLast(now)
        return true
    }

    private fun serve(msg: Message) {
        val to = msg.replyTo
        val d = msg.data ?: Bundle()
        val requestId = runCatching { d.getString(AegisProtocol.KEY_REQUEST_ID, "") }.getOrDefault("").take(64)
        val resultWhat = when (msg.what) { MSG_EVALUATE -> MSG_RESULT; MSG_REDEEM -> MSG_REDEEMED; else -> MSG_BROKER_RESULT }
        fun refuse(vararg reasons: String) =
            if (msg.what == MSG_REDEEM) reply(to, MSG_REDEEMED, Bundle().apply { putBoolean(AegisProtocol.KEY_GRANTED, false) }, requestId)
            else reply(to, resultWhat, result("DENY", reasons.toList()), requestId)

        // Kill switch: refuse before identifying the caller, so no pairing request can be raised either. The firewall would refuse too.
        if (AgentGateway.lockdown.value) return refuse("KILL_SWITCH_ON")
        val pkgs = packageManager.getPackagesForUid(msg.sendingUid)
        val pkg = pkgs?.singleOrNull() ?: return refuse("UNIDENTIFIED_CALLER")
        val cert = AgentGateway.signerDigest(packageManager, pkg) ?: return refuse("UNIDENTIFIED_CALLER")
        when (AgentGateway.status(pkg, cert)) {
            AgentGateway.Status.UNPAIRED -> {
                val before = AgentGateway.pairings.value.size
                AgentGateway.requestPairing(pkg, cert)
                if (AgentGateway.pairings.value.size > before) AgentNotifier.notifyWaiting(this)
                return reply(to, resultWhat, result(AegisProtocol.VERDICT_NOT_PAIRED, listOf("PAIRING_REQUIRED")), requestId)
            }
            AgentGateway.Status.SIGNATURE_CHANGED -> {
                Signals.record(this, Correlator.Kind.AGENT_SIGNATURE_CHANGED, pkg, "")
                return refuse("SIGNATURE_CHANGED")
            }
            AgentGateway.Status.PAIRED -> Unit
        }
        if (msg.what == MSG_BROKER) return broker(pkg, d, to, requestId)
        val request = try {
            AgentFirewall.Request(pkg, ActionType.valueOf(d.getString(AegisProtocol.KEY_TYPE, "")), d.getString(AegisProtocol.KEY_DESTINATION, "").take(2000), d.getString(AegisProtocol.KEY_SUMMARY, "").take(AgentFirewall.MAX_SUMMARY + 1),
                d.getString(AegisProtocol.KEY_PAYLOAD, "").take(AgentFirewall.MAX_PAYLOAD + 1), Provenance.valueOf(d.getString(AegisProtocol.KEY_PROVENANCE, "UNKNOWN")), d.getLong(AegisProtocol.KEY_AMOUNT_MINOR, -1), d.getString(AegisProtocol.KEY_CURRENCY, "").take(8))
        } catch (_: Exception) { return refuse("MALFORMED_REQUEST") }

        if (msg.what == MSG_REDEEM) {
            val granted = AgentGateway.firewall.redeem(d.getString(AegisProtocol.KEY_APPROVAL_ID, "").take(64), request)
            val token = if (granted) token(request, ApprovalToken.GRANT_USER_APPROVED) else null
            return reply(to, MSG_REDEEMED, Bundle().apply { putBoolean(AegisProtocol.KEY_GRANTED, granted); if (token != null) putString(AegisProtocol.KEY_TOKEN, token) }, requestId)
        }
        val decision = AgentGateway.firewall.evaluate(request)
        if (decision.verdict() == Verdict.DENY) decision.reasons().firstOrNull()?.let { Signals.record(this, Correlator.Kind.AGENT_REFUSED, pkg, it) }
        if (decision.verdict() == Verdict.ASK_USER && decision.approvalId() != null) {
            AgentGateway.addApproval(approvalItem(decision, pkg, request, ""))
            AgentNotifier.notifyWaiting(this)
        }
        val token = if (decision.verdict() == Verdict.ALLOW) token(request, ApprovalToken.GRANT_POLICY_ALLOW) else null
        reply(to, MSG_RESULT, result(decision.verdict().name, decision.reasons(), decision.approvalId()).apply { if (token != null) putString(AegisProtocol.KEY_TOKEN, token) }, requestId)
    }

    /** Signed approval token for a server to check, or null when the call has no destination host or no key is usable. */
    private fun token(request: AgentFirewall.Request, grant: String): String? =
        ApprovalSigner.issue(request, grant)?.also { AgentGateway.firewall.noteToken(request.agentId(), request.type(), request.destination(), grant) }

    /** Show what is actually bound to the approval: real host, amount, which kinds of sensitive data, and the content itself. */
    private fun approvalItem(decision: AgentFirewall.Decision, pkg: String, request: AgentFirewall.Request, broker: String) =
        ApprovalItem(decision.approvalId()!!, pkg, request.type().name, AgentFirewall.hostOf(request.destination()).take(100),
            AgentFirewall.displaySafe(request.summary()), decision.reasons(), System.currentTimeMillis(),
            request.amountMinor(), AgentFirewall.displaySafe(request.currency()).take(8),
            decision.dataKinds().toList(), request.payload().length,
            // Control and bidi characters made visible; commands and shared text get more room because that is what is being approved.
            AgentFirewall.previewSafe(request.payload(), if (request.type() == ActionType.EXECUTE_COMMAND || broker.isNotEmpty()) 800 else 300),
            AgentFirewall.previewSafe(request.destination(), 160), broker)

    /**
     * Capability broker: the agent asks Aegis to carry the action out. Links also go through Aegis' own link check
     * first. ALLOW returns a one-shot launcher bound to a ticket Aegis holds; ASK_USER waits for the person, after
     * which Aegis performs the action itself (see AgentGateway.resolve).
     */
    private fun broker(pkg: String, d: Bundle, to: Messenger?, requestId: String) {
        fun answer(verdict: String, reasons: List<String>, approvalId: String? = null, launch: PendingIntent? = null) =
            reply(to, MSG_BROKER_RESULT, result(verdict, reasons, approvalId).apply { if (launch != null) putParcelable(AegisProtocol.KEY_LAUNCH, launch) }, requestId)
        val action = try {
            CapabilityBroker.Action(CapabilityBroker.Kind.valueOf(d.getString(AegisProtocol.KEY_BROKER_ACTION, "")), d.getString(AegisProtocol.KEY_VALUE, "").take(CapabilityBroker.MAX_TEXT + 1))
        } catch (_: Exception) { return answer("DENY", listOf("MALFORMED_REQUEST")) }
        val provenance = runCatching { Provenance.valueOf(d.getString(AegisProtocol.KEY_PROVENANCE, "UNKNOWN")) }.getOrDefault(Provenance.UNKNOWN)
        val summary = d.getString(AegisProtocol.KEY_SUMMARY, "").take(AgentFirewall.MAX_SUMMARY + 1)
        val request = CapabilityBroker.toRequest(pkg, action, summary, provenance)
        CapabilityBroker.validate(action)?.let { reason ->
            AgentGateway.firewall.noteBroker(pkg, ActionType.SEND_DATA, "", false, reason)
            return answer("DENY", listOf(reason))
        }
        if (action.kind() == CapabilityBroker.Kind.OPEN_URL) {
            // Aegis' own link check: a link it would warn a person about is never opened on an agent's behalf.
            val v = runCatching { ThreatChecks.url(action.value(), ThreatIntel.get(this)).verdict }.getOrDefault(Analysis.Verdict.SUSPICIOUS)
            if (v == Analysis.Verdict.SUSPICIOUS || v == Analysis.Verdict.STRONG_INDICATORS || v == Analysis.Verdict.CONFIRMED_MALICIOUS) {
                AgentGateway.firewall.noteBroker(pkg, ActionType.SEND_DATA, action.value(), false, "LINK_CHECK_" + v.name)
                return answer("DENY", listOf("LINK_CHECK_" + v.name))
            }
        }
        val decision = AgentGateway.firewall.evaluateBrokered(request)
        when (decision.verdict()) {
            Verdict.ALLOW -> {
                val ticket = AgentGateway.allowTickets.newId()
                AgentGateway.allowTickets.put(ticket, pkg, action, request, 60)
                // Distinct data URI per ticket so Android never merges two launchers; immutable and one-shot, so the agent cannot alter or reuse it.
                val launch = PendingIntent.getActivity(this, 0, Intent(this, BrokerActivity::class.java).setData(Uri.parse("aegis-broker://ticket/$ticket")),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_CANCEL_CURRENT)
                answer(decision.verdict().name, decision.reasons(), null, launch)
            }
            Verdict.ASK_USER -> {
                val id = decision.approvalId()!!
                AgentGateway.askTickets.put(id, pkg, action, request, 300)
                AgentGateway.rememberBrokerReply(id, to)
                AgentGateway.addApproval(approvalItem(decision, pkg, request, action.kind().name))
                AgentNotifier.notifyWaiting(this)
                answer(decision.verdict().name, decision.reasons(), id)
            }
            else -> answer(decision.verdict().name, decision.reasons())
        }
    }

    companion object {
        const val MSG_EVALUATE = AegisProtocol.MSG_EVALUATE
        const val MSG_RESULT = AegisProtocol.MSG_RESULT
        const val MSG_REDEEM = AegisProtocol.MSG_REDEEM
        const val MSG_REDEEMED = AegisProtocol.MSG_REDEEMED
        const val MSG_BROKER = AegisProtocol.MSG_BROKER
        const val MSG_BROKER_RESULT = AegisProtocol.MSG_BROKER_RESULT
        const val MSG_BROKER_DONE = AegisProtocol.MSG_BROKER_DONE
        /** Above the firewall's own 30/min so a well-behaved agent never hits it; it bounds work for floods and unpaired callers. */
        const val MAX_MESSAGES_PER_MINUTE = 120
    }
}
