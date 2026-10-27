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
import java.util.Locale

/** Tells the person that an AI agent is waiting. Generic text only: nothing the agent supplied is placed in a notification. */
object AgentNotifier {
    private const val CHANNEL = "agent_requests"
    private const val ID = 42

    fun notifyWaiting(context: Context) {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Forespørsler fra KI-agenter" else "AI agent requests", NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(context, 2, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "En KI-agent venter på deg" else "An AI agent is waiting for you")
            .setContentText(if (no) "Åpne Aegis for å godkjenne eller nekte. Forespørselen utløper om 5 minutter." else "Open Aegis to approve or deny. The request expires in 5 minutes.")
            .setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true).setTimeoutAfter(300_000).build()
        try { nm.notify(ID, n) } catch (_: SecurityException) { }
    }

    fun clear(context: Context) { context.getSystemService(NotificationManager::class.java).cancel(ID) }
}
