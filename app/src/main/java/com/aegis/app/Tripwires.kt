package com.aegis.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import com.aegis.core.CanaryTokens
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress
import java.security.SecureRandom
import java.util.Locale

/** One time a decoy's link was looked up. test = caused by the person's own "Test" button. */
data class Trip(val tokenId: String, val kind: CanaryTokens.Kind, val timeMillis: Long, val test: Boolean)
data class TripwireState(val tokens: List<CanaryTokens.Token> = emptyList(), val trips: List<Trip> = emptyList(), val testResult: String? = null, val testRunning: Boolean = false)

/**
 * Canary-token tripwires. Decoys are handed to the person's own apps through standard intents (Contacts' insert screen,
 * the share sheet, the document picker), so Aegis needs no contacts or storage permission and never writes into other
 * apps itself. Detection happens in the DNS filter while DNS protection runs. NOT YET RUN ON A DEVICE.
 */
object Tripwires {
    private const val PREFS = "tripwires"
    private const val CHANNEL = "tripwire_alerts"
    private const val NOTIFICATION_ID = 44
    private const val MAX_TRIPS = 50
    private val random = SecureRandom()
    private val registry = CanaryTokens.Registry(CanaryTokens.DEFAULT_ZONE)
    @Volatile private var loaded = false
    @Volatile private var testing: String? = null
    @Volatile private var testDeadline = 0L
    private val mutable = MutableStateFlow(TripwireState())
    val state = mutable.asStateFlow()

    private fun prefs(c: Context) = c.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized fun load(context: Context): CanaryTokens.Registry {
        if (!loaded) {
            registry.load(prefs(context).getString("tokens", null))
            mutable.value = mutable.value.copy(tokens = registry.tokens(), trips = parseTrips(prefs(context).getString("trips", "") ?: ""))
            loaded = true
        }
        return registry
    }

    private fun parseTrips(s: String): List<Trip> = s.lines().mapNotNull { l ->
        val f = l.split(" ")
        if (f.size != 4) null else runCatching { Trip(f[0], CanaryTokens.Kind.valueOf(f[1]), f[2].toLong(), f[3] == "1") }.getOrNull()
    }.takeLast(MAX_TRIPS)

    private fun save(context: Context) {
        val s = mutable.value
        prefs(context).edit().putString("tokens", registry.serialize())
            .putString("trips", s.trips.takeLast(MAX_TRIPS).joinToString("\n") { "${it.tokenId} ${it.kind.name} ${it.timeMillis} ${if (it.test) 1 else 0}" }).apply()
    }

    private fun plant(context: Context, kind: CanaryTokens.Kind): CanaryTokens.Token {
        load(context)
        val t = registry.plant(kind, random, System.currentTimeMillis())
        mutable.value = mutable.value.copy(tokens = registry.tokens())
        save(context)
        return t
    }

    fun canPlant() = registry.tokens().size < CanaryTokens.MAX_TOKENS

    /** Opens the Contacts app's own "new contact" screen pre-filled with a decoy; the person taps Save there. */
    fun plantContact(context: Context, no: Boolean): Boolean {
        val t = plant(context, CanaryTokens.Kind.CONTACT)
        val website = ContentValues().apply {
            put(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE)
            put(ContactsContract.CommonDataKinds.Website.URL, t.url(registry.zone()))
        }
        val i = Intent(ContactsContract.Intents.Insert.ACTION).setType(ContactsContract.RawContacts.CONTENT_TYPE)
            .putExtra(ContactsContract.Intents.Insert.NAME, CanaryTokens.contactName(t))
            .putExtra(ContactsContract.Intents.Insert.EMAIL, CanaryTokens.contactName(t).lowercase(Locale.ROOT).replace(' ', '.') + "@" + t.host(registry.zone()))
            .putExtra(ContactsContract.Intents.Insert.NOTES, if (no) "Bank: se nettside" else "Bank: see website")
            .putParcelableArrayListExtra(ContactsContract.Intents.Insert.DATA, arrayListOf(website))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try { context.startActivity(i); true } catch (_: Exception) { remove(context, t.id()); false }
    }

    /** Opens the share sheet with a decoy "login backup" note; the person picks their notes app and saves it there. */
    fun plantNote(context: Context, no: Boolean): Boolean {
        val t = plant(context, CanaryTokens.Kind.NOTE)
        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, if (no) "Innlogging backup" else "Login backup")
            .putExtra(Intent.EXTRA_TEXT, CanaryTokens.noteText(t, registry.zone(), no))
        return try { context.startActivity(Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); true } catch (_: Exception) { remove(context, t.id()); false }
    }

    /** Writes a decoy file to the place the person chose in the system file picker. */
    fun plantFile(context: Context, uri: Uri, no: Boolean): Boolean {
        val t = plant(context, CanaryTokens.Kind.FILE)
        return try {
            context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(CanaryTokens.fileText(t, registry.zone(), no).toByteArray(Charsets.UTF_8)) }
            true
        } catch (_: Exception) { remove(context, t.id()); false }
    }

    fun remove(context: Context, id: String) {
        load(context)
        registry.remove(id)
        mutable.value = mutable.value.copy(tokens = registry.tokens())
        save(context)
    }

    fun clearTrips(context: Context) {
        mutable.value = mutable.value.copy(trips = emptyList(), testResult = null)
        save(context)
        context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
    }

    /** Called by the DNS filter on its packet thread. Records the trip and, unless it is the person's own test, alerts. */
    fun onTripped(context: Context, token: CanaryTokens.Token, @Suppress("UNUSED_PARAMETER") name: String) {
        val now = System.currentTimeMillis()
        val isTest = testing == token.id() && now < testDeadline
        synchronized(this) {
            mutable.value = mutable.value.copy(trips = (mutable.value.trips + Trip(token.id(), token.kind(), now, isTest)).takeLast(MAX_TRIPS),
                testResult = if (isTest) "ok" else mutable.value.testResult)
            save(context)
        }
        if (!isTest) {
            runCatching { alert(context, token.kind()) }
            Signals.record(context, com.aegis.core.Correlator.Kind.TRIPWIRE, null, token.kind().name)
        }
    }

    /**
     * Looks the decoy's name up from Aegis itself. With DNS protection on, the filter sees it and the test passes;
     * otherwise the lookup goes to the network's resolver and simply fails (".invalid" never exists).
     */
    fun selfTest(context: Context, token: CanaryTokens.Token) {
        testing = token.id(); testDeadline = System.currentTimeMillis() + 10_000
        mutable.value = mutable.value.copy(testResult = null, testRunning = true)
        Thread({
            runCatching { InetAddress.getByName(token.host(registry.zone())) }
            Thread.sleep(3000)
            val passed = mutable.value.testResult == "ok"
            testing = null
            mutable.value = mutable.value.copy(testRunning = false, testResult = if (passed) "ok" else if (Protection.running.value) "missed" else "off")
        }, "aegis-tripwire-test").apply { isDaemon = true; start() }
    }

    private fun alert(context: Context, kind: CanaryTokens.Kind) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Snubletråd utløst" else "Tripwire alerts", NotificationManager.IMPORTANCE_HIGH))
        val what = when (kind) {
            CanaryTokens.Kind.CONTACT -> if (no) "lokke-kontakten" else "the decoy contact"
            CanaryTokens.Kind.NOTE -> if (no) "lokke-notatet" else "the decoy note"
            CanaryTokens.Kind.FILE -> if (no) "lokke-filen" else "the decoy file"
        }
        val open = PendingIntent.getActivity(context, 4, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "Snubletråd utløst" else "Tripwire triggered")
            .setContentText(if (no) "Noe på telefonen prøvde å åpne lenken i $what. Åpne Aegis." else "Something on this phone tried to open the link in $what. Open Aegis.")
            .setContentIntent(open).setAutoCancel(true).build()
        try { nm.notify(NOTIFICATION_ID, n) } catch (_: SecurityException) { }
    }
}
