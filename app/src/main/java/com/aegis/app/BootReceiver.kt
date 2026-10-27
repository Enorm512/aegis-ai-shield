package com.aegis.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import java.util.Locale

/**
 * Turns DNS protection back on after the phone restarts or Aegis is updated, if the person had it on. Not exported:
 * only the system delivers these two broadcasts. Does nothing else at boot (no scans, no network).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        Protection.restoreAfterRestart(context)
    }
}

/** Tells the person protection could not come back by itself, so they are not left believing it is on. */
object RestartNotice {
    private const val CHANNEL = "protection_alerts"
    private const val ID = 45

    fun needsConsent(context: Context) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Beskyttelse av" else "Protection off", NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(context, 3, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "DNS-beskyttelse er av" else "DNS protection is off")
            .setContentText(if (no) "Den kunne ikke slås på igjen etter omstart. Åpne Aegis for å slå den på." else "It could not turn back on after the restart. Open Aegis to turn it on.")
            .setContentIntent(open).setAutoCancel(true).build()
        try { nm.notify(ID, n) } catch (_: SecurityException) { }
    }
}
