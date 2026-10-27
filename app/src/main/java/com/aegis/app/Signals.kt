package com.aegis.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.aegis.core.CapabilityWatch
import com.aegis.core.Correlator
import com.aegis.core.DnsFilter
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant
import java.util.Locale

/**
 * App side of cross-module correlation: every watch reports coarse signals here, they are kept encrypted for 7 days
 * ([SealedStore]) and linked into incidents ([Correlator]). A new HIGH incident gets one notification with generic
 * text. The person dismisses incidents; nothing is ever done to an app automatically.
 */
object Signals {
    private const val FILE = "correlation_signals"
    private const val PREFS = "correlation"
    private const val CHANNEL = "linked_warnings"
    private const val NOTIFICATION_ID = 46
    private val correlator = Correlator()
    @Volatile private var loaded = false
    private val mutable = MutableStateFlow<List<Correlator.Incident>>(emptyList())
    /** Incidents not yet dismissed, most serious first. */
    val incidents = mutable.asStateFlow()

    @Synchronized private fun load(context: Context) {
        if (loaded) return
        (SealedStore.read(context, FILE) as? SealedStore.Read.Ok)?.let { correlator.restore(it.text) }
        loaded = true
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun record(context: Context, kind: Correlator.Kind, pkg: String?, detail: String, time: Instant = Instant.now()) = record(context, listOf(Correlator.Signal(time, kind, pkg, detail)))

    /** Adds signals, saves when any was new, and re-evaluates. Never throws into the caller's watch. */
    @Synchronized fun record(context: Context, signals: List<Correlator.Signal>) {
        runCatching {
            load(context)
            var added = false
            for (s in signals) if (correlator.add(s)) added = true
            if (added) SealedStore.write(context, FILE, correlator.serialize())
            evaluate(context)
        }
    }

    /** Re-evaluates with the current power holders and notifies once per new HIGH incident. */
    @Synchronized fun evaluate(context: Context) {
        load(context)
        val holders = PowerWatch.state.value.apps.map { it.packageName() }.toSet()
        val dismissed = prefs(context).getLong("dismissed_until", 0)
        val list = correlator.incidents(Instant.now(), holders).filter { it.last().epochSecond > dismissed }
        mutable.value = list
        val notified = prefs(context).getStringSet("notified", emptySet()) ?: emptySet()
        val fresh = list.filter { it.risk() == CapabilityWatch.Risk.HIGH && it.key() !in notified }
        if (fresh.isNotEmpty()) {
            prefs(context).edit().putStringSet("notified", (notified + fresh.map { it.key() }).toList().takeLast(100).toSet()).apply()
            runCatching { notify(context) }
        }
    }

    /** The person has looked: current incidents are hidden until a newer signal links into one. */
    @Synchronized fun dismiss(context: Context) {
        prefs(context).edit().putLong("dismissed_until", Instant.now().epochSecond).apply()
        context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        mutable.value = emptyList()
    }

    /** Threat-database matches from the DNS filter's recent events (which keep only blocked and warned names). */
    fun recordDnsEvents(context: Context) {
        val recent = Protection.proxy?.recentEvents() ?: return
        record(context, recent.filter { it.reason() == DnsFilter.Reason.THREAT_DB }
            .map { Correlator.Signal(it.time(), Correlator.Kind.THREAT_LOOKUP, null, it.category()?.name ?: "") })
    }

    private fun notify(context: Context) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Sammenhengende varsler" else "Linked warnings", NotificationManager.IMPORTANCE_HIGH))
        val open = PendingIntent.getActivity(context, 4, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "Flere varsler henger sammen" else "Several warnings fit together")
            .setContentText(if (no) "Aegis så endringer som til sammen ligner et angrep. Åpne Aegis for å se hva." else "Aegis saw changes that together look like an attack. Open Aegis to see what.")
            .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true).build()
        try { nm.notify(NOTIFICATION_ID, n) } catch (_: SecurityException) { }
    }

    fun ruleText(rule: Correlator.Rule, no: Boolean): String = when (rule) {
        Correlator.Rule.NEW_APP_GAINED_POWER -> if (no) "En ny eller utbyttet app fikk skjermstyring, varseltilgang eller administratorrett kort tid etter at den kom." else "A new or replaced app got screen control, notification access or admin rights soon after it arrived."
        Correlator.Rule.DECOY_READ_AFTER_CHANGE -> if (no) "Lokkedataene dine ble brukt etter at en app fikk ny makt eller ble endret. Appen(e) under er mistenkt, ikke bevist." else "Your decoy data was used after an app got new power or changed. The app(s) below are suspects, not proven."
        Correlator.Rule.DECOY_AND_THREAT_LOOKUP -> if (no) "Lokkedataene dine ble brukt, og telefonen slo opp en kjent farlig adresse innen samme time." else "Your decoy data was used, and the phone looked up a known dangerous address within the same hour."
        Correlator.Rule.THREAT_LOOKUP_AFTER_CHANGE -> if (no) "Telefonen slo opp en kjent farlig adresse kort tid etter at en app fikk ny makt eller ble endret. Android sier ikke hvilken app som slo opp." else "The phone looked up a known dangerous address soon after an app got new power or changed. Android does not say which app made the lookup."
        Correlator.Rule.AGENT_PROBING -> if (no) "En KI-agent forsøkte gjentatte ganger risikable handlinger, eller spurte med en annen signeringsnøkkel enn den du godkjente." else "An AI agent repeatedly tried risky actions, or asked with a different signing key than the one you approved."
    }
}
