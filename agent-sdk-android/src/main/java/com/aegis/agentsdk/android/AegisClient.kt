package com.aegis.agentsdk.android

import android.app.Activity
import android.app.ActivityOptions
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import com.aegis.agentsdk.ActionSpec
import com.aegis.agentsdk.AegisProtocol
import com.aegis.agentsdk.TaintTracker
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Reference Android client for Aegis' agent gateway. Typical use in an agent's harness:
 *
 *     val tracker = TaintTracker()                 // fed by the harness, never by the model
 *     val aegis = AegisClient(context).apply { onBrokerDone = { done -> ... } }
 *     if (!aegis.connect()) ...                    // Aegis not installed
 *     val spec = ActionSpec.openUrl(url)
 *     val r = aegis.broker(spec, "Open the article you asked for", tracker.provenanceFor(spec))
 *     when (r.verdict) { ALLOW -> aegis.launch(activity, r.launch!!); ASK_USER -> wait for onBrokerDone; else -> stop }
 *
 * Prefer [broker] for actions Aegis can carry out itself: then the agent never needs to be trusted to do exactly
 * what was approved. Use [evaluate] + [redeem] only for actions Aegis cannot perform. All calls are suspend
 * functions that time out after [timeoutMillis]; replies are matched by a request id.
 * NOT YET RUN ON A DEVICE.
 */
class AegisClient(context: Context, private val timeoutMillis: Long = 10_000) {
    /** token: signed approval token for ALLOW (send it to the destination server with the call), null otherwise. */
    data class Result(val verdict: String, val reasons: List<String>, val approvalId: String?, val token: String? = null)
    /** token: signed approval token when granted and the call has a destination host. */
    data class Redeemed(val granted: Boolean, val token: String?)
    data class BrokerResult(val verdict: String, val reasons: List<String>, val approvalId: String?, val launch: PendingIntent?)
    data class BrokerDone(val approvalId: String, val performed: Boolean, val reason: String)

    private val app = context.applicationContext
    private val waiting = ConcurrentHashMap<String, CompletableDeferred<Bundle>>()
    /** What was sent for each approval, so [redeem] repeats the identical request (Aegis binds approvals to it). */
    private val sentForApproval = ConcurrentHashMap<String, Bundle>()
    @Volatile private var service: Messenger? = null
    @Volatile private var connection: ServiceConnection? = null
    @Volatile var aegisPackage: String? = null; private set

    /** Called on the main thread when Aegis has carried out (or not) a brokered action the person decided on. */
    @Volatile var onBrokerDone: ((BrokerDone) -> Unit)? = null

    private val replies = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            val data = msg.data ?: return
            if (msg.what == AegisProtocol.MSG_BROKER_DONE) {
                onBrokerDone?.invoke(BrokerDone(data.getString(AegisProtocol.KEY_APPROVAL_ID, ""), data.getBoolean(AegisProtocol.KEY_PERFORMED, false), data.getString(AegisProtocol.KEY_REASON, "")))
                return
            }
            data.getString(AegisProtocol.KEY_REQUEST_ID)?.let { waiting.remove(it)?.complete(Bundle(data)) }
        }
    })

    /** The installed Aegis package offering the gateway, release build first. Null when none is installed. */
    fun findAegis(): String? = AegisProtocol.AEGIS_PACKAGES.firstOrNull { pkg ->
        runCatching { app.packageManager.resolveService(Intent(AegisProtocol.ACTION_BIND).setPackage(pkg), 0) != null }.getOrDefault(false)
    }

    /** Binds to Aegis. Returns false when Aegis is not installed or did not answer in time. */
    suspend fun connect(): Boolean {
        if (service != null) return true
        val pkg = findAegis() ?: return false
        val ready = CompletableDeferred<Boolean>()
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) { service = binder?.let { Messenger(it) }; ready.complete(service != null) }
            override fun onServiceDisconnected(name: ComponentName?) { service = null }
            override fun onBindingDied(name: ComponentName?) { service = null; ready.complete(false) }
            override fun onNullBinding(name: ComponentName?) { ready.complete(false) }
        }
        val bound = runCatching { app.bindService(Intent(AegisProtocol.ACTION_BIND).setPackage(pkg), conn, Context.BIND_AUTO_CREATE) }.getOrDefault(false)
        if (!bound) { runCatching { app.unbindService(conn) }; return false }
        connection = conn; aegisPackage = pkg
        return withTimeoutOrNull(timeoutMillis) { ready.await() } == true
    }

    fun disconnect() {
        connection?.let { runCatching { app.unbindService(it) } }
        connection = null; service = null
        waiting.values.forEach { it.cancel() }; waiting.clear()
    }

    private suspend fun call(what: Int, data: Bundle): Bundle? {
        val s = service ?: return null
        val id = UUID.randomUUID().toString()
        data.putString(AegisProtocol.KEY_REQUEST_ID, id)
        val reply = CompletableDeferred<Bundle>()
        waiting[id] = reply
        try { s.send(Message.obtain(null, what).also { it.data = data; it.replyTo = replies }) } catch (_: RemoteException) { waiting.remove(id); service = null; return null }
        return withTimeoutOrNull(timeoutMillis) { reply.await() }.also { waiting.remove(id) }
    }

    private fun request(spec: ActionSpec, summary: String, provenance: TaintTracker.Label, amountMinor: Long, currency: String) = Bundle().apply {
        putString(AegisProtocol.KEY_TYPE, spec.kind); putString(AegisProtocol.KEY_DESTINATION, spec.destination); putString(AegisProtocol.KEY_PAYLOAD, spec.payload)
        putString(AegisProtocol.KEY_SUMMARY, summary.take(AegisProtocol.MAX_SUMMARY)); putString(AegisProtocol.KEY_PROVENANCE, provenance.name)
        putLong(AegisProtocol.KEY_AMOUNT_MINOR, amountMinor); putString(AegisProtocol.KEY_CURRENCY, currency)
    }

    private fun reasons(b: Bundle) = b.getStringArray(AegisProtocol.KEY_REASONS)?.toList() ?: emptyList()

    /** Asks whether the agent may do [spec] itself. Verdict TIMEOUT or NOT_CONNECTED when Aegis did not answer. */
    suspend fun evaluate(spec: ActionSpec, summary: String, provenance: TaintTracker.Label, amountMinor: Long = -1, currency: String = ""): Result {
        require(!spec.isBroker) { "use broker() for ${spec.kind}" }
        if (service == null) return Result("NOT_CONNECTED", emptyList(), null)
        val sent = request(spec, summary, provenance, amountMinor, currency)
        val b = call(AegisProtocol.MSG_EVALUATE, Bundle(sent)) ?: return Result("TIMEOUT", emptyList(), null)
        val approval = b.getString(AegisProtocol.KEY_APPROVAL_ID)?.takeIf { it.isNotEmpty() }
        if (approval != null) sentForApproval[approval] = sent
        return Result(b.getString(AegisProtocol.KEY_VERDICT, "DENY"), reasons(b), approval, b.getString(AegisProtocol.KEY_TOKEN)?.takeIf { it.isNotEmpty() })
    }

    /**
     * After the person approved in Aegis: granted only for the identical request, once. Poll this or retry when the
     * person returns. Send the token with the call (for example as an `Aegis-Approval` HTTP header) so the server can check it.
     */
    suspend fun redeem(approvalId: String): Redeemed {
        val sent = sentForApproval[approvalId] ?: return Redeemed(false, null)
        val b = call(AegisProtocol.MSG_REDEEM, Bundle(sent).apply { putString(AegisProtocol.KEY_APPROVAL_ID, approvalId) }) ?: return Redeemed(false, null)
        val granted = b.getBoolean(AegisProtocol.KEY_GRANTED, false)
        if (granted) sentForApproval.remove(approvalId)
        return Redeemed(granted, b.getString(AegisProtocol.KEY_TOKEN)?.takeIf { granted && it.isNotEmpty() })
    }

    /**
     * Asks Aegis to carry out [spec] itself (open a link, or open the share menu with a text). ALLOW comes with a
     * one-shot launcher to start from the agent's visible activity ([launch]); ASK_USER means the person decides in
     * Aegis, which then performs it and reports through [onBrokerDone].
     */
    suspend fun broker(spec: ActionSpec, summary: String, provenance: TaintTracker.Label): BrokerResult {
        require(spec.isBroker) { "${spec.kind} is not an action Aegis can carry out; use evaluate()" }
        if (service == null) return BrokerResult("NOT_CONNECTED", emptyList(), null, null)
        val b = call(AegisProtocol.MSG_BROKER, Bundle().apply {
            putString(AegisProtocol.KEY_BROKER_ACTION, spec.kind); putString(AegisProtocol.KEY_VALUE, spec.payload)
            putString(AegisProtocol.KEY_SUMMARY, summary.take(AegisProtocol.MAX_SUMMARY)); putString(AegisProtocol.KEY_PROVENANCE, provenance.name)
        }) ?: return BrokerResult("TIMEOUT", emptyList(), null, null)
        @Suppress("DEPRECATION") val launch = if (Build.VERSION.SDK_INT >= 33) b.getParcelable(AegisProtocol.KEY_LAUNCH, PendingIntent::class.java) else b.getParcelable(AegisProtocol.KEY_LAUNCH)
        return BrokerResult(b.getString(AegisProtocol.KEY_VERDICT, "DENY"), reasons(b), b.getString(AegisProtocol.KEY_APPROVAL_ID)?.takeIf { it.isNotEmpty() }, launch)
    }

    /**
     * Starts an allowed brokered action from the agent's visible [activity]. Aegis performs it; the launcher cannot be
     * changed and works once. On Android 14+ the agent must lend its right to start activities, which this does.
     */
    fun launch(activity: Activity, launcher: PendingIntent): Boolean = try {
        if (Build.VERSION.SDK_INT >= 34) {
            @Suppress("DEPRECATION")
            val opts = ActivityOptions.makeBasic().setPendingIntentBackgroundActivityStartMode(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
            launcher.send(activity, 0, null, null, null, null, opts.toBundle())
        } else launcher.send()
        true
    } catch (_: PendingIntent.CanceledException) { false }
}
