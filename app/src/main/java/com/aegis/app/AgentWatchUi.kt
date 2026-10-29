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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.core.AgentBehaviour
import com.aegis.core.ResultSummary.Level
import java.time.Duration
import java.time.Instant

private fun modeLevel(m: AgentBehaviour.Mode) = when (m) {
    AgentBehaviour.Mode.AUTONOMOUS -> Level.SUSPICIOUS
    AgentBehaviour.Mode.ASSISTED -> Level.UNCLEAR
    AgentBehaviour.Mode.HUMAN -> Level.CLEAR
}

private fun ago(t: Instant, tx: Tx): String {
    val m = Duration.between(t, Instant.now()).toMinutes()
    return when {
        m < 1 -> tx.t("just now", "akkurat nå")
        m < 60 -> tx.t("$m min ago", "for $m min siden")
        else -> tx.t("${m / 60} h ago", "for ${m / 60} t siden")
    }
}

/**
 * "AI agent activity": sessions rated by the behaviour watch, with "Is this you?" for those that look autonomous.
 * Hidden when Aegis has seen no agent activity (no paired agent called and no AI API lookup with DNS protection on).
 */
@Composable
fun AgentActivityCard(p: PowerState, tx: Tx, dark: Boolean, context: Context, onUnpair: (String) -> Unit) {
    val sessions by AgentWatch.sessions.collectAsStateWithLifecycle()
    val open by AgentWatch.needsAnswer.collectAsStateWithLifecycle()
    if (sessions.isEmpty()) return
    val warn = levelStyle(Level.SUSPICIOUS, dark)
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("AI agent activity", "KI-agentaktivitet"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_agent)
                Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
            }
            Text(tx.t("Whether AI agents seem to act with you or on their own, from calls by connected agents and, while DNS protection is on, lookups of AI services. A rating is a reason to look, not proof.",
                "Om KI-agenter ser ut til å handle sammen med deg eller på egen hånd, ut fra kall fra tilkoblede agenter og, mens DNS-beskyttelsen er på, oppslag av KI-tjenester. En vurdering er grunn til å se etter, ikke bevis."),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            open.forEach { s ->
                Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = warn.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(tx.t("Is this you?", "Er dette deg?"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        val gateway = s.source() == AgentBehaviour.Source.GATEWAY
                        Text(if (gateway) displayName(p, s.actor(), tx) + tx.t(" seems to be acting on its own. Until you answer, each of its actions waits for your approval.", " ser ut til å handle på egen hånd. Til du svarer, venter hver handling på godkjenningen din.")
                            else tx.t("${s.actor()} was used while your phone was locked (${s.events()} lookups). Android does not say which app did it.", "${s.actor()} ble brukt mens telefonen var låst (${s.events()} oppslag). Android sier ikke hvilken app som gjorde det."),
                            style = MaterialTheme.typography.bodyMedium)
                        s.reasons().forEach { Text("• " + AgentWatch.reasonText(it, tx.no), style = MaterialTheme.typography.bodySmall) }
                        if (!gateway) {
                            val suspects = AgentWatch.candidates()
                            if (suspects.isEmpty()) Text(tx.t("No app outside the phone's own has screen control or notification access, so this may be an ordinary app working in the background.", "Ingen app utenom telefonens egne har skjermstyring eller varseltilgang, så dette kan være en vanlig app som jobber i bakgrunnen."), style = MaterialTheme.typography.bodySmall)
                            else {
                                Text(tx.t("Apps that could act on your phone this way:", "Apper som kan handle på telefonen på denne måten:"), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                                suspects.take(5).forEach { pkg ->
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(displayName(p, pkg, tx), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                                        TextButton(onClick = { PowerWatch.openAppDetails(context, pkg) }) { Text(tx.t("App info", "Appinfo")) }
                                    }
                                }
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { AgentWatch.confirm(context, s) }, Modifier.weight(1f).heightIn(min = 48.dp)) { Text(tx.t("Yes, that was me", "Ja, det var meg")) }
                            if (gateway) OutlinedButton(onClick = { onUnpair(s.actor()) }, Modifier.weight(1f).heightIn(min = 48.dp)) { Text(tx.t("No, remove it", "Nei, fjern den")) }
                        }
                    }
                }
            }
            sessions.take(6).forEach { s ->
                HorizontalDivider()
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(if (s.source() == AgentBehaviour.Source.GATEWAY) displayName(p, s.actor(), tx) else s.actor() + tx.t(" (AI service)", " (KI-tjeneste)"), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Text(tx.t("${s.events()} event(s) · ${ago(s.end(), tx)}", "${s.events()} hendelse(r) · ${ago(s.end(), tx)}") + if (AgentWatch.acknowledged(s)) tx.t(" · you confirmed", " · du bekreftet") else "",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Pill(AgentWatch.modeLabel(s.mode(), tx.no), levelStyle(modeLevel(s.mode()), dark).accent)
                }
            }
            Text(tx.t("Kept in memory for 24 hours, never saved or sent. Agents that never call Aegis and use their own encrypted DNS are not seen.", "Holdes i minnet i 24 timer, lagres eller sendes aldri. Agenter som aldri kaller Aegis og bruker egen kryptert DNS, sees ikke."),
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
