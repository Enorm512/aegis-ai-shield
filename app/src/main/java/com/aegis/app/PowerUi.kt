package com.aegis.app

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aegis.core.CapabilityWatch
import com.aegis.core.ResultSummary.Level

/** Colour for a holder's risk; the text label always carries the meaning. */
private fun riskLevel(r: CapabilityWatch.Risk) = when (r) {
    CapabilityWatch.Risk.HIGH -> Level.STRONG
    CapabilityWatch.Risk.MEDIUM -> Level.SUSPICIOUS
    CapabilityWatch.Risk.LOW -> Level.UNCLEAR
}

private fun riskLabel(r: CapabilityWatch.Risk, tx: Tx) = when (r) {
    CapabilityWatch.Risk.HIGH -> tx.t("High power", "Stor makt")
    CapabilityWatch.Risk.MEDIUM -> tx.t("Some power", "Noe makt")
    CapabilityWatch.Risk.LOW -> tx.t("Expected", "Forventet")
}

fun displayName(p: PowerState, pkg: String, tx: Tx): String =
    if (pkg == PowerWatch.UNKNOWN) tx.t("A VPN app (Android does not say which)", "En VPN-app (Android oppgir ikke hvilken)")
    else p.labels[pkg]?.takeIf { it.isNotBlank() && it != pkg }?.let { "$it ($pkg)" } ?: pkg

/** "Who can control or read this phone": new grants first, then every holder by risk, each with a link to the system page. */
@Composable
fun PowersCard(p: PowerState, tx: Tx, dark: Boolean, context: Context) {
    val warnStyle = levelStyle(Level.SUSPICIOUS, dark)
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("Who can control or read this phone", "Hvem kan styre eller lese telefonen"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_lock)
                Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
            }
            Text(tx.t("Apps with these powers could act like an AI agent on your phone: read your screen, tap buttons, read codes, or see what you type. Most are legitimate. Check that you recognise every app with high power.",
                "Apper med disse tilgangene kan oppføre seg som en KI-agent på telefonen: lese skjermen, trykke på knapper, lese koder eller se hva du skriver. De fleste er lovlige. Sjekk at du kjenner igjen alle apper med stor makt."),
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (!p.loaded) { Text(tx.t("Checking…", "Sjekker…"), style = MaterialTheme.typography.bodySmall); return@Column }

            if (p.alerts.isNotEmpty()) {
                Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = warnStyle.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(tx.t("New since you last looked", "Nytt siden sist du så"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        p.alerts.take(10).forEach { c ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(displayName(p, c.holder().packageName(), tx), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                    Text(PowerWatch.capabilityName(c.holder().capability(), tx.no), style = MaterialTheme.typography.bodySmall)
                                }
                                TextButton(onClick = { PowerWatch.openSettings(context, c.holder().capability()) }) { Text(tx.t("Settings", "Innstillinger")) }
                            }
                        }
                        Text(tx.t("If you did not turn this on yourself, switch it off in Settings and consider removing the app.", "Hvis du ikke slo dette på selv, slå det av i Innstillinger og vurder å fjerne appen."), style = MaterialTheme.typography.bodySmall)
                        Button(onClick = { PowerWatch.markReviewed(context) }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("I recognise these", "Jeg kjenner igjen disse")) }
                    }
                }
            } else if (p.firstLook) Text(tx.t("First check: this list is your starting point. Aegis will point out any app that gets new power from now on.", "Første sjekk: denne listen er utgangspunktet. Aegis sier fra om apper som får ny makt fra nå av."), style = MaterialTheme.typography.bodySmall)

            if (p.apps.isEmpty()) Text(tx.t("No app holds these powers, as far as Android lets Aegis see.", "Ingen apper har disse tilgangene, så langt Android lar Aegis se."), style = MaterialTheme.typography.bodySmall)
            p.apps.take(30).forEach { a ->
                val accent = levelStyle(riskLevel(a.risk()), dark).accent
                HorizontalDivider()
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(displayName(p, a.packageName(), tx), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Pill(riskLabel(a.risk(), tx), accent)
                    }
                    a.capabilities().forEach { cap -> Text("• " + PowerWatch.capabilityName(cap, tx.no), style = MaterialTheme.typography.bodySmall) }
                    a.reasons().mapNotNull { PowerWatch.reasonText(it, tx.no) }.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { PowerWatch.openSettings(context, a.capabilities().first()) }) { Text(tx.t("Manage", "Administrer")) }
                        if (a.packageName() != PowerWatch.UNKNOWN) TextButton(onClick = { PowerWatch.openAppDetails(context, a.packageName()) }) { Text(tx.t("App info", "Appinfo")) }
                    }
                }
            }
            if (p.apps.size > 30) Text(tx.t("Showing the 30 most powerful of ${p.apps.size} apps.", "Viser de 30 med mest makt av ${p.apps.size} apper."), style = MaterialTheme.typography.labelSmall)
            Text(tx.t("Aegis cannot switch these off for you. Android may hide some apps from Aegis, so also look in Settings. Checked when you open Aegis, and every 30 minutes while DNS protection is on.",
                "Aegis kan ikke slå av disse for deg. Android kan skjule noen apper for Aegis, så se også i Innstillinger. Sjekkes når du åpner Aegis, og hvert 30. minutt mens DNS-beskyttelsen er på."),
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
