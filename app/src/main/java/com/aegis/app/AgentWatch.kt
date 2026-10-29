package com.aegis.app

import android.Manifest
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import com.aegis.core.AgentBehaviour
import com.aegis.core.CapabilityWatch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant
import java.util.Locale

/**
 * App side of the agent behaviour watch ([AgentBehaviour]). Records gateway calls and AI-API lookups with whether the
 * person was using the phone (screen on and unlocked), keeps the rated sessions for the UI, pauses paired agents whose
 * session looks autonomous ("Is this you?") and notifies once per unanswered autonomous session. Memory only: nothing is
 * saved, and the history is gone when Android stops the app.
 */
object AgentWatch {
    private const val CHANNEL = "linked_warnings"
    private const val NOTIFICATION_ID = 47
    private val watch = AgentBehaviour()
    private val notified = HashSet<String>()
    private val mutable = MutableStateFlow<List<AgentBehaviour.Session>>(emptyList())
    /** Sessions of the last 24 hours, most recent first. */
    val sessions = mutable.asStateFlow()
    private val pending = MutableStateFlow<List<AgentBehaviour.Session>>(emptyList())
    /** Autonomous sessions the person has not answered yet. */
    val needsAnswer = pending.asStateFlow()

    /** Off only in device tests of the gateway's own rules, where many quick calls from the test would rightly look automated. */
    @Volatile var enabled = true

    /** Screen on and not locked: the closest a normal app can get to "the person is using the phone right now". */
    fun personPresent(context: Context): Boolean {
        val power = context.getSystemService(PowerManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        return power?.isInteractive == true && keyguard?.isKeyguardLocked == false
    }

    /** A gateway call from a paired agent. Returns whether its next action must ask the person first. */
    @Synchronized fun onGatewayCall(context: Context, pkg: String, sensitive: Boolean): Boolean {
        if (!enabled) { AgentGateway.firewall.setPaused(pkg, false); return false }
        val now = Instant.now()
        watch.record(AgentBehaviour.Event(now, AgentBehaviour.Source.GATEWAY, pkg, personPresent(context), sensitive))
        val pause = watch.shouldPause(pkg, now)
        AgentGateway.firewall.setPaused(pkg, pause)
        publish(context, now)
        return pause
    }

    /** From the DNS thread: an AI model API was looked up. Cheap; the work is a few list operations. */
    @Synchronized fun onAiLookup(context: Context, service: String) {
        if (!enabled) return
        val now = Instant.now()
        watch.record(AgentBehaviour.Event(now, AgentBehaviour.Source.AI_LOOKUP, service, personPresent(context), false))
        publish(context, now)
    }

    /** "Yes, that was me": the session stays listed but no longer pauses the agent or asks again. */
    @Synchronized fun confirm(context: Context, s: AgentBehaviour.Session) {
        watch.acknowledge(s)
        if (s.source() == AgentBehaviour.Source.GATEWAY) AgentGateway.firewall.setPaused(s.actor(), false)
        publish(context, Instant.now())
        if (pending.value.isEmpty()) context.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
    }

    @Synchronized fun refresh(context: Context) = publish(context, Instant.now())

    fun acknowledged(s: AgentBehaviour.Session) = watch.acknowledged(s)

    @Synchronized fun clearForTest() { watch.clear(); notified.clear(); mutable.value = emptyList(); pending.value = emptyList() }

    /**
     * Apps that could be behind AI traffic Android does not attribute: those holding screen control (Accessibility) or
     * notification access, which is what an agent needs to act in other apps. Suspects only.
     */
    fun candidates(): List<String> = PowerWatch.state.value.apps
        .filter { !it.preinstalled() && (CapabilityWatch.Capability.ACCESSIBILITY in it.capabilities() || CapabilityWatch.Capability.NOTIFICATION_ACCESS in it.capabilities()) }
        .map { it.packageName() }.filter { it != PowerWatch.UNKNOWN }

    private fun publish(context: Context, now: Instant) {
        mutable.value = watch.sessions(now)
        val open = watch.needsAnswer(now)
        pending.value = open
        val fresh = open.filter { it.key() !in notified }
        if (fresh.isNotEmpty()) {
            notified.addAll(fresh.map { it.key() }); if (notified.size > 500) notified.clear()
            runCatching { notify(context, fresh.first()) }
        }
    }

    private fun notify(context: Context, s: AgentBehaviour.Session) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Sammenhengende varsler" else "Linked warnings", NotificationManager.IMPORTANCE_HIGH))
        val open = PendingIntent.getActivity(context, 5, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        // Generic text: the notification shade is visible on the lock screen, so no app or service name is shown there.
        val text = if (s.source() == AgentBehaviour.Source.GATEWAY)
            (if (no) "En KI-agent ser ut til å handle på egen hånd. Neste handling venter på deg. Var dette deg?" else "An AI agent seems to be acting on its own. Its next action waits for you. Was this you?")
            else (if (no) "En KI-tjeneste ble brukt mens telefonen var låst. Var dette deg?" else "An AI service was used while your phone was locked. Was this you?")
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "Er dette deg?" else "Is this you?").setContentText(text).setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true).build()
        try { nm.notify(NOTIFICATION_ID, n) } catch (_: SecurityException) { }
    }

    fun modeLabel(m: AgentBehaviour.Mode, no: Boolean) = when (m) {
        AgentBehaviour.Mode.HUMAN -> if (no) "Deg" else "You"
        AgentBehaviour.Mode.ASSISTED -> if (no) "Med deg" else "With you"
        AgentBehaviour.Mode.AUTONOMOUS -> if (no) "På egen hånd" else "On its own"
    }

    fun reasonText(code: String, no: Boolean) = when (code) {
        "WHILE_LOCKED" -> if (no) "Brukt mens telefonen var låst eller skjermen av." else "Used while the phone was locked or the screen was off."
        "MACHINE_PACE" -> if (no) "Mange handlinger med bare noen sekunder imellom, raskere enn en person." else "Many actions only seconds apart, faster than a person."
        "STEADY_RHYTHM" -> if (no) "Handlinger i et jevnt, maskinaktig tempo." else "Actions at an even, machine-like rhythm."
        "AGENT_WHILE_IN_USE" -> if (no) "Agenten handlet mens du brukte telefonen." else "The agent acted while you were using the phone."
        "AI_USE_WHILE_IN_USE" -> if (no) "KI-tjenesten ble brukt mens du brukte telefonen." else "The AI service was used while you were using the phone."
        else -> code
    }
}
