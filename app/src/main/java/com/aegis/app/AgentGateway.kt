package com.aegis.app

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Bundle
import android.os.Message
import android.os.Messenger
import com.aegis.agentsdk.AegisProtocol
import com.aegis.core.AgentFirewall
import com.aegis.core.CapabilityBroker
import com.aegis.core.CapabilityWatch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.time.Clock
import java.util.concurrent.ConcurrentHashMap

data class PairRequest(val packageName: String, val certSha256: String)
data class ApprovalItem(val id: String, val agent: String, val type: String, val destinationHost: String, val summary: String, val reasons: List<String>, val createdMillis: Long,
                        val amountMinor: Long = -1, val currency: String = "", val dataKinds: List<String> = emptyList(), val payloadChars: Int = 0,
                        val payloadPreview: String = "", val destinationRaw: String = "",
                        /** OPEN_URL or SHARE_TEXT when Aegis itself will carry the action out once approved; empty otherwise. */
                        val broker: String = "")

/** What the activity log screen shows. intactAtLoad = false when the saved log was damaged, edited or unreadable at start-up. */
data class AuditView(val entries: List<AgentFirewall.AuditEntry> = emptyList(), val head: String = "", val intactAtLoad: Boolean = true, val saveFailed: Boolean = false)

/** What the pairing dialog shows about the app asking to connect. label is chosen by the app itself, so it is always shown next to the package name. */
data class AgentAppInfo(val label: String, val icon: Drawable?, val installer: CapabilityWatch.Installer, val drawsOverApps: Boolean,
                        val powers: Set<CapabilityWatch.Capability>, val advice: CapabilityWatch.PairingAdvice)

/**
 * App-side state of the Agent Action Firewall: which apps may ask, and what is waiting for the person to decide.
 * Callers are identified by the Android-verified calling UID and pinned to their signing certificate. The audit log
 * and waiting approvals are kept encrypted in private storage ([SealedStore]) so they survive the app being stopped.
 * Preview: never exercised on a device.
 */
object AgentGateway {
    enum class Status { PAIRED, SIGNATURE_CHANGED, UNPAIRED }

    val firewall = AgentFirewall(Clock.systemUTC())
    private val mutablePairings = MutableStateFlow<List<PairRequest>>(emptyList())
    private val mutableApprovals = MutableStateFlow<List<ApprovalItem>>(emptyList())
    private val mutablePaired = MutableStateFlow<Map<String, String>>(emptyMap())
    private val mutableRisky = MutableStateFlow<Set<String>>(emptySet())
    val pairings = mutablePairings.asStateFlow()
    val approvals = mutableApprovals.asStateFlow()
    val paired = mutablePaired.asStateFlow()
    /** Paired apps the person explicitly allowed to ask for risky actions (commands, installs, payments, credentials, settings). */
    val riskyGranted = mutableRisky.asStateFlow()
    private val mutableTrusted = MutableStateFlow<List<String>>(emptyList())
    /** Exact destination hosts the person trusts (no sub-domains). Outbound requests to them are not asked about when nothing else is flagged. */
    val trusted = mutableTrusted.asStateFlow()
    private val mutableLockdown = MutableStateFlow(false)
    /** Kill switch: while on, every agent request is refused and no app can ask to pair. */
    val lockdown = mutableLockdown.asStateFlow()
    private val mutableAudit = MutableStateFlow(AuditView())
    /** Capability broker: allowed actions waiting for the agent's one-shot launcher, and asked actions waiting for the person. Memory only. */
    val allowTickets = CapabilityBroker.Tickets(Clock.systemUTC())
    val askTickets = CapabilityBroker.Tickets(Clock.systemUTC())
    private val brokerReplies = ConcurrentHashMap<String, Messenger>()
    val audit = mutableAudit.asStateFlow()
    private const val TRUST_PREFS = "agent_trust"
    private const val STATE_PREFS = "agent_state"
    private const val MAX_TRUSTED = 50
    private const val AUDIT_FILE = "agent_audit"
    private const val PENDING_FILE = "agent_pending"
    private val lastRequest = HashMap<String, Long>()
    @Volatile private var loaded = false
    @Volatile private var intactAtLoad = true
    private const val PREFS = "agents"
    private const val MAX_PAIRINGS = 5
    private const val RISKY_FLAG = ";risky"
    private fun actionsFor(risky: Boolean): Set<AgentFirewall.ActionType> =
        if (risky) java.util.EnumSet.allOf(AgentFirewall.ActionType::class.java) else AgentFirewall.SAFE_GRANT

    @Synchronized fun load(context: Context) {
        if (loaded) return
        val app = context.applicationContext
        val p = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        // Stored as "<certificate digest>" or "<certificate digest>;risky".
        val raw = p.all.filter { it.value is String }.mapValues { it.value as String }
        val risky = raw.filterValues { it.endsWith(RISKY_FLAG) }.keys
        raw.forEach { (pkg, v) -> firewall.registerAgent(pkg, actionsFor(v.endsWith(RISKY_FLAG))) }
        mutablePaired.value = raw.mapValues { it.value.removeSuffix(RISKY_FLAG) }
        mutableRisky.value = risky
        val t = app.getSharedPreferences(TRUST_PREFS, Context.MODE_PRIVATE).all.keys.filter { AgentFirewall.isTrustableHost(it) }.sorted()
        t.forEach { firewall.trustDestination(it) }
        mutableTrusted.value = t
        val locked = app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE).getBoolean("lockdown", false)
        firewall.restoreLockdown(locked)
        mutableLockdown.value = locked
        // The log first, so a damaged one is noted before anything new is added. An unreadable file is reported as damaged, not treated as empty.
        intactAtLoad = when (val r = SealedStore.read(app, AUDIT_FILE)) {
            SealedStore.Read.Missing -> true
            SealedStore.Read.Unreadable -> firewall.restoreAudit("unreadable")
            is SealedStore.Read.Ok -> firewall.restoreAudit(r.text)
        }
        (SealedStore.read(app, PENDING_FILE) as? SealedStore.Read.Ok)?.let { restorePending(it.text) }
        loaded = true
        persist(app)
    }

    /** Waiting approvals: the firewall's binding (hash, expiry) plus what the dialog shows. Only items the firewall still has open come back. */
    private fun restorePending(text: String) {
        val nl = text.indexOf("\n--items--\n")
        if (nl < 0) return
        firewall.restorePending(text.substring(0, nl + 1))
        val open = firewall.openApprovals().toSet()
        val items = runCatching {
            val a = JSONArray(text.substring(nl + "\n--items--\n".length))
            (0 until a.length()).map { i -> a.getJSONObject(i) }.map { o ->
                ApprovalItem(o.getString("id"), o.getString("agent"), o.getString("type"), o.getString("host"), o.getString("summary"),
                    o.getJSONArray("reasons").let { r -> (0 until r.length()).map { r.getString(it) } }, o.getLong("created"),
                    o.getLong("amount"), o.getString("currency"), o.getJSONArray("kinds").let { r -> (0 until r.length()).map { r.getString(it) } },
                    o.getInt("chars"), o.getString("preview"), o.getString("raw"), o.optString("broker", ""))
            }
        }.getOrDefault(emptyList())
        mutableApprovals.value = items.filter { it.id in open }.takeLast(20)
    }

    /** Saves the log and waiting approvals. Called after every change; cheap enough at the firewall's rate limit. */
    @Synchronized fun persist(context: Context) {
        val app = context.applicationContext
        val items = JSONArray()
        mutableApprovals.value.forEach { i ->
            items.put(JSONObject().put("id", i.id).put("agent", i.agent).put("type", i.type).put("host", i.destinationHost).put("summary", i.summary)
                .put("reasons", JSONArray(i.reasons)).put("created", i.createdMillis).put("amount", i.amountMinor).put("currency", i.currency)
                .put("kinds", JSONArray(i.dataKinds)).put("chars", i.payloadChars).put("preview", i.payloadPreview).put("raw", i.destinationRaw).put("broker", i.broker))
        }
        val ok = SealedStore.write(app, AUDIT_FILE, firewall.exportAudit()) and
            SealedStore.write(app, PENDING_FILE, firewall.exportPending() + "--items--\n" + items.toString())
        val log = firewall.auditLog()
        mutableAudit.value = AuditView(log.takeLast(200).reversed(), firewall.auditHead(), intactAtLoad, !ok)
    }

    fun exportAuditText(): String = firewall.exportAudit()

    fun signerDigest(pm: PackageManager, pkg: String): String? = try {
        @Suppress("DEPRECATION")
        val sigs = if (Build.VERSION.SDK_INT >= 28) pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
                   else pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
        if (sigs.isNullOrEmpty()) null
        else sigs.map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { b -> "%02x".format(b) } }.sorted().joinToString("+")
    } catch (_: Exception) { null }

    /** Label, icon, install source, overlay request and the powers the app already holds, for the pairing dialog. */
    fun appInfo(context: Context, pkg: String, powers: PowerState): AgentAppInfo {
        val pm = context.packageManager
        val ai = runCatching { @Suppress("DEPRECATION") pm.getApplicationInfo(pkg, 0) }.getOrNull()
        val system = ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val installerPkg = runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        }.getOrNull()
        val installer = CapabilityWatch.installerOf(installerPkg, system)
        val overlay = runCatching {
            @Suppress("DEPRECATION") pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS).requestedPermissions?.contains(Manifest.permission.SYSTEM_ALERT_WINDOW) == true
        }.getOrDefault(false)
        // Fresh scan rather than the last screen state: the app may have been granted a power a moment ago.
        val held = runCatching { CapabilityWatch.byApp(PowerWatch.scan(context), context.packageName).firstOrNull { it.packageName() == pkg }?.capabilities() }.getOrNull()
            ?: powers.apps.firstOrNull { it.packageName() == pkg }?.capabilities() ?: emptySet()
        val label = ai?.let { AgentFirewall.displaySafe(pm.getApplicationLabel(it).toString()).take(60) } ?: pkg
        return AgentAppInfo(label, ai?.let { runCatching { pm.getApplicationIcon(it) }.getOrNull() }, installer, overlay, held,
            CapabilityWatch.pairingAdvice(held, overlay, installer))
    }

    fun status(pkg: String, cert: String): Status {
        val pinned = mutablePaired.value[pkg] ?: return Status.UNPAIRED
        return if (pinned == cert) Status.PAIRED else Status.SIGNATURE_CHANGED
    }

    /** An unpaired app asked; show it to the person once. Rate-limited and capped so it cannot spam prompts. Never while the kill switch is on. */
    @Synchronized fun requestPairing(pkg: String, cert: String) {
        if (mutableLockdown.value) return
        val now = System.currentTimeMillis()
        if (now - (lastRequest[pkg] ?: 0L) < 60_000) return
        lastRequest[pkg] = now
        val list = mutablePairings.value
        if (list.any { it.packageName == pkg } || list.size >= MAX_PAIRINGS) return
        mutablePairings.value = list + PairRequest(pkg, cert)
    }

    /** By default a paired agent may only ask about data and files; [risky] must be granted by the person on purpose. */
    @Synchronized fun approvePairing(context: Context, req: PairRequest, risky: Boolean = false) {
        if (mutableLockdown.value) { rejectPairing(context, req); return }
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(req.packageName, req.certSha256 + (if (risky) RISKY_FLAG else "")).apply()
        firewall.registerAgent(req.packageName, actionsFor(risky))
        firewall.notePairing(req.packageName, AgentFirewall.Event.PAIRED, risky)
        mutableRisky.value = if (risky) mutableRisky.value + req.packageName else mutableRisky.value - req.packageName
        mutablePaired.value = mutablePaired.value + (req.packageName to req.certSha256)
        mutablePairings.value = mutablePairings.value.filterNot { it.packageName == req.packageName }
        persist(context)
    }

    /** Returns false when [raw] is not a plain host name or the list is full. */
    @Synchronized fun addTrusted(context: Context, raw: String): Boolean {
        val h = raw.trim().lowercase(java.util.Locale.ROOT).removePrefix("https://").removeSuffix("/")
        if (!AgentFirewall.isTrustableHost(h) || mutableTrusted.value.size >= MAX_TRUSTED) return false
        context.applicationContext.getSharedPreferences(TRUST_PREFS, Context.MODE_PRIVATE).edit().putBoolean(h, true).apply()
        firewall.trustDestination(h)
        mutableTrusted.value = (mutableTrusted.value + h).distinct().sorted()
        return true
    }

    @Synchronized fun removeTrusted(context: Context, host: String) {
        context.applicationContext.getSharedPreferences(TRUST_PREFS, Context.MODE_PRIVATE).edit().remove(host).apply()
        firewall.untrustDestination(host)
        mutableTrusted.value = mutableTrusted.value - host
    }

    @Synchronized fun rejectPairing(context: Context, req: PairRequest) {
        mutablePairings.value = mutablePairings.value.filterNot { it.packageName == req.packageName }
        firewall.notePairing(req.packageName, AgentFirewall.Event.PAIR_REJECTED, false)
        persist(context)
    }

    @Synchronized fun unpair(context: Context, pkg: String) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(pkg).apply()
        firewall.unregisterAgent(pkg)
        firewall.notePairing(pkg, AgentFirewall.Event.UNPAIRED, false)
        mutablePaired.value = mutablePaired.value - pkg
        mutableRisky.value = mutableRisky.value - pkg
        mutableApprovals.value.filter { it.agent == pkg && it.broker.isNotEmpty() }.forEach { askTickets.take(it.id); brokerDone(it.id, false, "AGENT_REMOVED") }
        mutableApprovals.value = mutableApprovals.value.filterNot { it.agent == pkg }
        persist(context)
    }

    /**
     * Kill switch: removes every paired agent and its grants, cancels every waiting and approved-but-unused approval,
     * drops pairing requests, and refuses everything until the person turns it off. Trusted destinations are kept
     * (they only matter for paired agents). Returns the agents that were removed.
     */
    @Synchronized fun killSwitch(context: Context): List<String> {
        val app = context.applicationContext
        app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE).edit().putBoolean("lockdown", true).commit()
        val removed = firewall.killSwitch()
        allowTickets.clear(); askTickets.clear()
        brokerReplies.keys.toList().forEach { brokerDone(it, false, "KILL_SWITCH_ON") }
        app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
        mutableLockdown.value = true
        mutablePaired.value = emptyMap()
        mutableRisky.value = emptySet()
        mutablePairings.value = emptyList()
        mutableApprovals.value = emptyList()
        AgentNotifier.clear(app)
        persist(app)
        return removed
    }

    /** Ends the lockdown. Agents removed by the kill switch stay removed and must ask to pair again. */
    @Synchronized fun releaseKillSwitch(context: Context) {
        val app = context.applicationContext
        firewall.releaseKillSwitch()
        app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE).edit().putBoolean("lockdown", false).apply()
        mutableLockdown.value = false
        persist(app)
    }

    @Synchronized fun addApproval(item: ApprovalItem) {
        val fresh = mutableApprovals.value.filter { System.currentTimeMillis() - it.createdMillis < 300_000 }
        mutableApprovals.value = (fresh + item).takeLast(20)
    }

    /** Where to report the outcome of a brokered action the person decides on later. */
    fun rememberBrokerReply(approvalId: String, to: Messenger?) { if (to != null) brokerReplies[approvalId] = to }

    private fun brokerDone(approvalId: String, performed: Boolean, reason: String) {
        val to = brokerReplies.remove(approvalId) ?: return
        runCatching { to.send(Message.obtain(null, AegisProtocol.MSG_BROKER_DONE).also { it.data = Bundle().apply {
            putString(AegisProtocol.KEY_APPROVAL_ID, approvalId); putBoolean(AegisProtocol.KEY_PERFORMED, performed); putString(AegisProtocol.KEY_REASON, reason) } }) }
    }

    /**
     * The person's answer. For a brokered action, approving makes Aegis carry it out right here, from the ticket it
     * holds (the exact content that was shown), with [context] being the visible activity; the agent only hears the outcome.
     */
    @Synchronized fun resolve(context: Context, id: String, approve: Boolean) {
        val ticket = askTickets.take(id)
        val wasBroker = ticket != null || mutableApprovals.value.any { it.id == id && it.broker.isNotEmpty() }
        val answered = firewall.resolve(id, approve)
        if (wasBroker) {
            val reason = when {
                !approve -> "DENIED_BY_USER"
                ticket == null || !answered -> "EXPIRED"
                !firewall.redeemBrokered(id, ticket.request()) -> "NOT_AVAILABLE"
                else -> BrokerExec.perform(context, ticket.action()).also { r -> firewall.noteBroker(ticket.agentId(), AgentFirewall.ActionType.SEND_DATA, ticket.request().destination(), r == null, r) }
            }
            brokerDone(id, reason == null, reason ?: "")
        }
        mutableApprovals.value = mutableApprovals.value.filterNot { it.id == id }
        persist(context)
    }
}
