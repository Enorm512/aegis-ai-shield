package com.aegis.app

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
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
                        val broker: String = "",
                        /** Earlier steps of this agent's session when a chain rule fired, as TYPE|host|OUTCOME|fromContent (1/0). */
                        val chain: List<String> = emptyList())

/** What the activity log screen shows. intactAtLoad = false when the saved log was damaged, edited or unreadable at start-up. */
data class AuditView(val entries: List<AgentFirewall.AuditEntry> = emptyList(), val head: String = "", val intactAtLoad: Boolean = true, val saveFailed: Boolean = false,
                     /** The separate security log (pairings, your answers, kill switch, damage, rate-limit hits), newest first. */
                     val security: List<AgentFirewall.AuditEntry> = emptyList())

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
    private val mutableStopped = MutableStateFlow<Set<AgentFirewall.ActionType>>(emptySet())
    /** Kinds of action the person stopped for every agent; requests of these kinds are refused until resumed. Pairings are kept. */
    val stopped = mutableStopped.asStateFlow()
    private val mutableReadOnly = MutableStateFlow<Set<String>>(emptySet())
    /** Paired agents the person limited to asking for reads; everything else they ask is refused. */
    val readOnly = mutableReadOnly.asStateFlow()
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
    private const val SECURITY_FILE = "agent_security"
    /** Revision of the firewall state last written to disk; -1 = never. Writes are skipped when nothing changed. */
    @Volatile private var savedRevision = -1L
    private const val SAVE_DELAY_MS = 2_000L
    private val saver by lazy { Handler(HandlerThread("aegis-agent-save").apply { start() }.looper) }
    @Volatile private var saveScheduled = false
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
        val state = app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE)
        val stops = state.getStringSet("stopped", emptySet()).orEmpty().mapNotNull { n -> AgentFirewall.ActionType.values().firstOrNull { it.name == n } }.toSet()
        val ro = state.getStringSet("readonly", emptySet()).orEmpty().filter { it in raw.keys }.toSet()
        firewall.restoreLimits(if (stops.isEmpty()) java.util.EnumSet.noneOf(AgentFirewall.ActionType::class.java) else java.util.EnumSet.copyOf(stops), ro)
        mutableStopped.value = stops
        mutableReadOnly.value = ro
        // Both logs first, so damage is noted before anything new is added. An unreadable file is reported as damaged, not treated as empty.
        fun text(r: SealedStore.Read): String? = when (r) { SealedStore.Read.Missing -> null; SealedStore.Read.Unreadable -> "unreadable"; is SealedStore.Read.Ok -> r.text }
        val intact = firewall.restoreLogs(text(SealedStore.read(app, AUDIT_FILE)), text(SealedStore.read(app, SECURITY_FILE)))
        intactAtLoad = intact[0] && intact[1]
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
                    o.getInt("chars"), o.getString("preview"), o.getString("raw"), o.optString("broker", ""),
                    o.optJSONArray("chain")?.let { r -> (0 until r.length()).map { r.getString(it) } } ?: emptyList())
            }
        }.getOrDefault(emptyList())
        mutableApprovals.value = items.filter { it.id in open }.takeLast(20)
    }

    /**
     * Saves both logs and the waiting approvals, but only when the firewall state changed since the last write
     * (refused, unpaired and suppressed calls change nothing, so they cost no write). Used for the person's own actions.
     */
    @Synchronized fun persist(context: Context) {
        val app = context.applicationContext
        val rev = firewall.revision()
        if (rev == savedRevision) return
        val items = JSONArray()
        mutableApprovals.value.forEach { i ->
            items.put(JSONObject().put("id", i.id).put("agent", i.agent).put("type", i.type).put("host", i.destinationHost).put("summary", i.summary)
                .put("reasons", JSONArray(i.reasons)).put("created", i.createdMillis).put("amount", i.amountMinor).put("currency", i.currency)
                .put("kinds", JSONArray(i.dataKinds)).put("chars", i.payloadChars).put("preview", i.payloadPreview).put("raw", i.destinationRaw).put("broker", i.broker).put("chain", JSONArray(i.chain)))
        }
        val auditText = firewall.exportAudit() // may first add a denial summary, which advances the revision
        val ok = SealedStore.write(app, AUDIT_FILE, auditText) and
            SealedStore.write(app, SECURITY_FILE, firewall.exportSecurityLog()) and
            SealedStore.write(app, PENDING_FILE, firewall.exportPending() + "--items--\n" + items.toString())
        if (ok) savedRevision = firewall.revision()
        val log = firewall.auditLog()
        mutableAudit.value = AuditView(log.takeLast(200).reversed(), firewall.auditHead(), intactAtLoad, !ok, firewall.securityLog().reversed())
    }

    /**
     * For the gateway's request traffic: coalesces saves to at most one per [SAVE_DELAY_MS] on a background thread,
     * and does nothing when nothing changed. A burst of requests from one app therefore costs one write, not one per call.
     */
    fun persistSoon(context: Context) {
        if (firewall.revision() == savedRevision || saveScheduled) return
        saveScheduled = true
        val app = context.applicationContext
        saver.postDelayed({ saveScheduled = false; runCatching { persist(app) } }, SAVE_DELAY_MS)
    }

    /** Both logs as one text file (each with its own header and hash chain). */
    fun exportAuditText(): String = firewall.exportAudit() + firewall.exportSecurityLog()

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
        if (pkg in mutableReadOnly.value) saveReadOnly(context, mutableReadOnly.value - pkg)
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
        saveReadOnly(app, emptySet())
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

    /**
     * Stops or resumes kinds of action for every agent. Saved before anything else, like the kill switch, so a stop
     * survives the app being stopped. Waiting approvals of those kinds are cancelled (brokered ones told why).
     */
    @Synchronized fun setStopped(context: Context, types: Set<AgentFirewall.ActionType>, on: Boolean) {
        val app = context.applicationContext
        val next = if (on) mutableStopped.value + types else mutableStopped.value - types
        app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE).edit().putStringSet("stopped", next.map { it.name }.toSet()).commit()
        firewall.setStopped(types, on)
        mutableStopped.value = next
        if (on) dropApprovals("CAPABILITY_STOPPED") { it.type in types.map { t -> t.name } }
        persist(app)
    }

    /** Read-only mode for one paired agent: it may still ask to read (you still approve), and everything else is refused. */
    @Synchronized fun setReadOnly(context: Context, pkg: String, on: Boolean) {
        if (pkg !in mutablePaired.value) return
        val app = context.applicationContext
        saveReadOnly(app, if (on) mutableReadOnly.value + pkg else mutableReadOnly.value - pkg)
        firewall.setReadOnly(pkg, on)
        if (on) dropApprovals("AGENT_READ_ONLY") { it.agent == pkg && it.type != AgentFirewall.ActionType.READ_SENSITIVE.name }
        persist(app)
    }

    private fun saveReadOnly(context: Context, next: Set<String>) {
        context.applicationContext.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE).edit().putStringSet("readonly", next).commit()
        mutableReadOnly.value = next
    }

    private fun dropApprovals(reason: String, which: (ApprovalItem) -> Boolean) {
        mutableApprovals.value.filter { which(it) && it.broker.isNotEmpty() }.forEach { askTickets.take(it.id); brokerDone(it.id, false, reason) }
        mutableApprovals.value = mutableApprovals.value.filterNot(which)
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

    /** Whether the phone has a screen lock to confirm with. Replaced in tests; a CI emulator has none and cannot answer the prompt. */
    @Volatile internal var screenLockSet: (Context) -> Boolean = { c -> c.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true }

    /** True when approving [item] must pass the phone's own fingerprint, face or PIN check. Without a screen lock there is nothing to check against. */
    fun needsScreenLock(context: Context, item: ApprovalItem) = screenLockSet(context) && AgentFirewall.needsStrongConfirmation(item.type, item.reasons, item.dataKinds)

    /**
     * The person's answer. For a brokered action, approving makes Aegis carry it out right here, from the ticket it
     * holds (the exact content that was shown), with [context] being the visible activity; the agent only hears the outcome.
     * An approval that needs the screen lock is ignored unless [confirmed] says that check passed.
     */
    @Synchronized fun resolve(context: Context, id: String, approve: Boolean, confirmed: Boolean = false) {
        if (approve && !confirmed) {
            val item = mutableApprovals.value.firstOrNull { it.id == id }
            if (if (item == null) screenLockSet(context) else needsScreenLock(context, item)) return
        }
        val ticket = askTickets.take(id)
        val wasBroker = ticket != null || mutableApprovals.value.any { it.id == id && it.broker.isNotEmpty() }
        val answered = firewall.resolve(id, approve, confirmed)
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
