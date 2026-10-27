package com.aegis.app

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import androidx.core.app.NotificationManagerCompat
import com.aegis.core.AppWatch
import com.aegis.core.CapabilityWatch
import com.aegis.core.CapabilityWatch.Capability
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale

/** What the screens show: holders by app, their labels, and grants that are new since the person last reviewed. */
data class PowerState(
    val loaded: Boolean = false,
    val apps: List<CapabilityWatch.AppSummary> = emptyList(),
    val labels: Map<String, String> = emptyMap(),
    val alerts: List<CapabilityWatch.Change> = emptyList(),
    val firstLook: Boolean = false,
    /** New, replaced or re-sourced apps since the last review (MEDIUM and HIGH only), most worrying first. */
    val appChanges: List<AppWatch.Change> = emptyList(),
)

/**
 * "Who can control or read this phone". Reads which apps hold Accessibility, notification access, device admin,
 * default SMS, keyboard and VPN, using public Android APIs and no extra permission. The first look becomes the
 * baseline; later grants are alerts until the person marks them reviewed. Aegis never revokes anything: it links
 * to the system page where the person can.
 *
 * NOT YET RUN ON A DEVICE: which holders are visible under Android's package-visibility rules (see the <queries>
 * block in the manifest) must be checked on real phones. The diff and risk logic is host-tested (CapabilityTests).
 */
object PowerWatch {
    private const val PREFS = "power_watch"
    private const val BASELINE = "baseline"
    private const val APP_BASELINE = "app_baseline"
    private const val SIGNALLED = "signalled"
    private const val NOTIFIED = "notified"
    private const val CHANNEL = "power_changes"
    private const val NOTIFICATION_ID = 43
    private val mutable = MutableStateFlow(PowerState())
    val state = mutable.asStateFlow()

    fun scan(context: Context): CapabilityWatch.Snapshot {
        val c = context.applicationContext
        val pm = c.packageManager
        val cr = c.contentResolver
        val out = ArrayList<CapabilityWatch.Holder>()
        fun add(cap: Capability, pkg: String?) { if (pkg != null && CapabilityWatch.validPackage(pkg)) out += CapabilityWatch.Holder(cap, pkg, preinstalled(pm, pkg)) }

        // Accessibility: the secure setting lists enabled services even for apps Aegis cannot see; the manager is a cross-check.
        runCatching { CapabilityWatch.packagesFromComponentList(Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)) }.getOrNull()?.forEach { add(Capability.ACCESSIBILITY, it) }
        runCatching { c.getSystemService(AccessibilityManager::class.java).getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).mapNotNull { it.resolveInfo?.serviceInfo?.packageName } }.getOrNull()?.forEach { add(Capability.ACCESSIBILITY, it) }
        runCatching { NotificationManagerCompat.getEnabledListenerPackages(c) }.getOrNull()?.forEach { add(Capability.NOTIFICATION_ACCESS, it) }
        runCatching { c.getSystemService(DevicePolicyManager::class.java).activeAdmins?.map { it.packageName } }.getOrNull()?.forEach { add(Capability.DEVICE_ADMIN, it) }
        runCatching { Telephony.Sms.getDefaultSmsPackage(c) }.getOrNull()?.let { add(Capability.DEFAULT_SMS, it) }
        runCatching { CapabilityWatch.packagesFromComponentList(Settings.Secure.getString(cr, Settings.Secure.ENABLED_INPUT_METHODS)) }.getOrNull()?.forEach { add(Capability.INPUT_METHOD, it) }
        runCatching { c.getSystemService(InputMethodManager::class.java).enabledInputMethodList.map { it.packageName } }.getOrNull()?.forEach { add(Capability.INPUT_METHOD, it) }
        // A VPN other than Aegis' own: Android does not tell other apps which app owns it, so it is recorded as "unknown".
        if (!Protection.running.value) {
            val vpn = runCatching {
                val cm = c.getSystemService(ConnectivityManager::class.java)
                cm.activeNetwork?.let { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } == true
            }.getOrDefault(false)
            if (vpn) add(Capability.VPN, UNKNOWN)
        }
        return CapabilityWatch.Snapshot(out)
    }

    const val UNKNOWN = "unknown"

    /**
     * Installed apps Android lets Aegis see (no QUERY_ALL_PACKAGES), with version, signing certificates and install source.
     * Under package visibility that is mainly apps offering the high-power services in the manifest's queries.
     */
    fun scanApps(context: Context): AppWatch.Snapshot {
        val pm = context.applicationContext.packageManager
        @Suppress("DEPRECATION")
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val infos = runCatching { @Suppress("DEPRECATION") pm.getInstalledPackages(flags) }.getOrDefault(emptyList())
        return AppWatch.Snapshot(infos.mapNotNull { pi ->
            runCatching {
                val system = pi.applicationInfo?.let { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 } ?: false
                val installer = runCatching {
                    if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pi.packageName).installingPackageName else @Suppress("DEPRECATION") pm.getInstallerPackageName(pi.packageName)
                }.getOrNull()
                @Suppress("DEPRECATION")
                val sigs = if (Build.VERSION.SDK_INT >= 28) pi.signingInfo?.apkContentsSigners else pi.signatures
                val signer = sigs.orEmpty().map { s -> java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) } }.sorted().take(8).joinToString("+")
                @Suppress("DEPRECATION")
                val version = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
                AppWatch.App(pi.packageName, version, signer, CapabilityWatch.installerOf(installer, system))
            }.getOrNull()
        })
    }

    private fun preinstalled(pm: PackageManager, pkg: String): Boolean = try {
        @Suppress("DEPRECATION") val ai = pm.getApplicationInfo(pkg, 0)
        (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
    } catch (_: Exception) { false } // not visible or not installed: treat as not preinstalled (the cautious side)

    fun label(context: Context, pkg: String): String = try {
        @Suppress("DEPRECATION") context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0)).toString().take(60)
    } catch (_: Exception) { pkg }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Scans, compares with the reviewed baseline and publishes the result. The very first scan becomes the baseline. */
    @Synchronized fun refresh(context: Context) {
        val now = scan(context)
        val p = prefs(context)
        val baseline = CapabilityWatch.Snapshot.parse(p.getString(BASELINE, null))
        val first = baseline == null
        if (first) p.edit().putString(BASELINE, now.serialize()).apply()
        val alerts = CapabilityWatch.alerts(CapabilityWatch.diff(baseline, now), context.packageName)
        // Only removals since the baseline: nothing to warn about, so move the baseline forward quietly.
        if (!first && alerts.isEmpty() && CapabilityWatch.diff(baseline, now).isNotEmpty()) p.edit().putString(BASELINE, now.serialize()).apply()
        val apps = CapabilityWatch.byApp(now, context.packageName)
        val appChanges = appChanges(context, now)
        val labelled = apps.map { it.packageName() } + appChanges.map { it.packageName() }
        mutable.value = PowerState(true, apps, labelled.distinct().associateWith { if (it == UNKNOWN) "" else label(context, it) }, alerts, first, appChanges)
        signal(context, alerts, appChanges)
        Signals.recordDnsEvents(context)
    }

    /** Reports each new grant and risky app change to the correlator once (until the person marks them reviewed). */
    private fun signal(context: Context, grants: List<CapabilityWatch.Change>, apps: List<AppWatch.Change>) {
        val p = prefs(context)
        val done = p.getStringSet(SIGNALLED, emptySet()) ?: emptySet()
        val out = ArrayList<Pair<String, com.aegis.core.Correlator.Signal>>()
        val now = java.time.Instant.now()
        grants.filter { it.holder().packageName() != UNKNOWN }.forEach {
            out += ("G " + it.holder().capability().name + " " + it.holder().packageName()) to com.aegis.core.Correlator.Signal(now, com.aegis.core.Correlator.Kind.POWER_GRANTED, it.holder().packageName(), it.holder().capability().name)
        }
        apps.forEach { out += ("A " + it.kind().name + " " + it.packageName()) to com.aegis.core.Correlator.Signal(now, com.aegis.core.Correlator.Kind.APP_RISKY_CHANGE, it.packageName(), it.kind().name) }
        val fresh = out.filter { it.first !in done }
        if (fresh.isNotEmpty()) p.edit().putStringSet(SIGNALLED, done + fresh.map { it.first }).apply()
        Signals.record(context, fresh.map { it.second })
    }

    /** App changes worth showing; the first look becomes the baseline, and a baseline with only routine changes moves forward quietly. */
    private fun appChanges(context: Context, holders: CapabilityWatch.Snapshot): List<AppWatch.Change> {
        val p = prefs(context)
        val now = scanApps(context)
        val baseline = AppWatch.Snapshot.parse(p.getString(APP_BASELINE, null))
        if (baseline == null) { p.edit().putString(APP_BASELINE, now.serialize()).apply(); return emptyList() }
        val all = AppWatch.diff(baseline, now, holders.holders().map { it.packageName() }.toSet(), context.packageName)
        val alerts = AppWatch.alerts(all)
        if (alerts.isEmpty() && all.isNotEmpty()) p.edit().putString(APP_BASELINE, now.serialize()).apply()
        return alerts
    }

    /** The person has seen the current holders and app changes: they become the new baseline. */
    @Synchronized fun markReviewed(context: Context) {
        prefs(context).edit().putString(BASELINE, scan(context).serialize()).putString(APP_BASELINE, scanApps(context).serialize()).remove(NOTIFIED).remove(SIGNALLED).apply()
        context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        refresh(context)
    }

    /** Called periodically while DNS protection runs: notifies once per new grant, with generic text only. */
    @Synchronized fun backgroundCheck(context: Context) {
        val p = prefs(context)
        val baseline = CapabilityWatch.Snapshot.parse(p.getString(BASELINE, null)) ?: return
        val holders = scan(context)
        val alerts = CapabilityWatch.alerts(CapabilityWatch.diff(baseline, holders), context.packageName)
        val apps = AppWatch.Snapshot.parse(p.getString(APP_BASELINE, null))
            ?.let { AppWatch.alerts(AppWatch.diff(it, scanApps(context), holders.holders().map { h -> h.packageName() }.toSet(), context.packageName)) }.orEmpty()
        val notified = p.getStringSet(NOTIFIED, emptySet()) ?: emptySet()
        signal(context, alerts, apps)
        Signals.recordDnsEvents(context)
        val keys = alerts.map { it.holder().capability().name + " " + it.holder().packageName() } + apps.map { "APP " + it.kind().name + " " + it.packageName() }
        val fresh = keys.filterNot { it in notified }
        if (fresh.isEmpty()) return
        p.edit().putStringSet(NOTIFIED, notified + fresh).apply()
        notify(context, keys.size)
    }

    private fun notify(context: Context, count: Int) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Endringer i app-tilganger" else "App power changes", NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(context, 3, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "Endringer i apper med makt over telefonen" else "Changes to apps with power over your phone")
            .setContentText(if (no) "$count endring(er), for eksempel ny skjermstyring eller en app byttet ut av en annen utvikler. Åpne Aegis for å se hvem." else "$count change(s), such as new screen control or an app replaced by a different developer. Open Aegis to see which app.")
            .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true).build()
        try { nm.notify(NOTIFICATION_ID, n) } catch (_: SecurityException) { }
    }

    /** The system page where the person can switch the capability off. Falls back to the main settings page. */
    fun openSettings(context: Context, cap: Capability) {
        val action = when (cap) {
            Capability.ACCESSIBILITY -> Settings.ACTION_ACCESSIBILITY_SETTINGS
            Capability.NOTIFICATION_ACCESS -> Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS
            Capability.DEVICE_ADMIN -> Settings.ACTION_SECURITY_SETTINGS // the device-admin list lives under security on most phones; no public direct action
            Capability.DEFAULT_SMS -> Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS
            Capability.INPUT_METHOD -> Settings.ACTION_INPUT_METHOD_SETTINGS
            Capability.VPN -> Settings.ACTION_VPN_SETTINGS
        }
        start(context, Intent(action))
    }

    fun openAppDetails(context: Context, pkg: String) {
        if (pkg == UNKNOWN || !CapabilityWatch.validPackage(pkg)) return start(context, Intent(Settings.ACTION_VPN_SETTINGS))
        start(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null)))
    }

    private fun start(context: Context, intent: Intent) {
        try { context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        catch (_: ActivityNotFoundException) { runCatching { context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } }
        catch (_: SecurityException) { runCatching { context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } }
    }

    fun capabilityName(cap: Capability, no: Boolean): String = when (cap) {
        Capability.ACCESSIBILITY -> if (no) "Kan lese skjermen og trykke for deg" else "Can read the screen and tap for you"
        Capability.NOTIFICATION_ACCESS -> if (no) "Leser alle varsler (også engangskoder)" else "Reads all notifications (including one-time codes)"
        Capability.DEVICE_ADMIN -> if (no) "Enhetsadministrator (kan låse eller slette telefonen)" else "Device admin (can lock or wipe the phone)"
        Capability.DEFAULT_SMS -> if (no) "Standard SMS-app (mottar alle SMS)" else "Default SMS app (receives every SMS)"
        Capability.INPUT_METHOD -> if (no) "Tastatur (ser alt du skriver)" else "Keyboard (sees everything you type)"
        Capability.VPN -> if (no) "VPN (kan se eller omdirigere nettrafikk)" else "VPN (can see or redirect network traffic)"
    }

    fun appChangeTitle(kind: AppWatch.Kind, no: Boolean): String = when (kind) {
        AppWatch.Kind.INSTALLED -> if (no) "Ny app" else "New app"
        AppWatch.Kind.UPDATED -> if (no) "Oppdatert" else "Updated"
        AppWatch.Kind.SIGNER_CHANGED -> if (no) "Byttet ut: signert av en annen utvikler" else "Replaced: signed by a different developer"
        AppWatch.Kind.INSTALLER_CHANGED -> if (no) "Installert fra en ny kilde" else "Installed from a new source"
        AppWatch.Kind.REMOVED -> if (no) "Fjernet" else "Removed"
    }

    fun appReasonText(code: String, no: Boolean): String? = when (code) {
        "HOLDS_POWERS" -> if (no) "Har tilganger som kan styre eller lese telefonen." else "Holds powers that can control or read the phone."
        "SIDELOADED" -> if (no) "Installert fra en fil, ikke fra en appbutikk." else "Installed from a file, not from an app store."
        "INSTALLED_BY_OTHER_APP" -> if (no) "Installert av en annen app." else "Installed by another app."
        "INSTALL_SOURCE_UNKNOWN" -> if (no) "Android oppgir ikke hvor den kom fra." else "Android does not say where it came from."
        "SIGNER_CHANGED" -> if (no) "Samme navn, men en annen signeringsnøkkel: den gamle appen ble fjernet og erstattet. Dette er det vanlige mønsteret for en forfalsket app." else "Same name, different signing key: the old app was removed and replaced. This is the usual pattern of a counterfeit app."
        "SOURCE_CHANGED" -> if (no) "Kom tidligere fra en annen kilde." else "Previously came from a different source."
        "DOWNGRADED" -> if (no) "Byttet til en eldre versjon." else "Changed to an older version."
        else -> null
    }

    fun reasonText(code: String, no: Boolean): String? = when (code) {
        "READ_AND_ACT" -> if (no) "Kan både lese engangskoder og trykke for deg: det sterkeste mønsteret for en useriøs agent eller skadevare." else "Can both read one-time codes and tap for you: the strongest pattern for a rogue agent or malware."
        "NOT_PREINSTALLED" -> if (no) "Installert av deg eller en annen app, ikke levert med telefonen." else "Installed by you or another app, not shipped with the phone."
        else -> null
    }
}
