package com.aegis.app

import android.content.Context
import android.text.format.DateFormat
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aegis.core.CanaryTokens
import com.aegis.core.ResultSummary.Level

private fun kindName(k: CanaryTokens.Kind, tx: Tx) = when (k) {
    CanaryTokens.Kind.CONTACT -> tx.t("Decoy contact", "Lokke-kontakt")
    CanaryTokens.Kind.NOTE -> tx.t("Decoy note", "Lokke-notat")
    CanaryTokens.Kind.FILE -> tx.t("Decoy file", "Lokke-fil")
}

private fun whenText(context: Context, millis: Long) =
    DateFormat.getMediumDateFormat(context).format(millis) + " " + DateFormat.getTimeFormat(context).format(millis)

/** Tripwires: plant decoys, see which fired, test that detection works. */
@Composable
fun TripwireCard(t: TripwireState, running: Boolean, tx: Tx, dark: Boolean, context: Context) {
    val strong = levelStyle(Level.STRONG, dark)
    var failed by remember { mutableStateOf(false) }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri -> if (uri != null) failed = !Tripwires.plantFile(context, uri, tx.no) }
    val realTrips = t.trips.filter { !it.test }
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("Tripwires", "Snubletråder"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_alert)
                Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
            }
            Text(tx.t("A tripwire is a decoy (a contact, a note or a file) with a link that leads nowhere. You have no reason to open it, so if anything on this phone opens that link, something has been reading your data and acting on it, such as a rogue AI agent or spyware.",
                "En snubletråd er et lokkemiddel (en kontakt, et notat eller en fil) med en lenke som ikke fører noe sted. Du har ingen grunn til å åpne den, så hvis noe på telefonen åpner lenken, har noe lest dataene dine og handlet på dem, for eksempel en useriøs KI-agent eller spionprogram."),
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (!running) Text(tx.t("Tripwires are only watched while DNS protection is on.", "Snubletråder overvåkes bare mens DNS-beskyttelsen er på."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)

            if (realTrips.isNotEmpty()) {
                Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = strong.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(tx.t("A tripwire was triggered", "En snubletråd er utløst"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        realTrips.takeLast(5).reversed().forEach { tr -> Text("• " + kindName(tr.kind, tx) + " · " + whenText(context, tr.timeMillis), style = MaterialTheme.typography.bodySmall) }
                        Text(tx.t("Something on this phone read a decoy and tried to use it. Check \"Who can control or read this phone\" above, remove apps you do not trust, and change passwords for any real accounts stored in the same app.",
                            "Noe på telefonen leste et lokkemiddel og prøvde å bruke det. Sjekk «Hvem kan styre eller lese telefonen» over, fjern apper du ikke stoler på, og bytt passord for ekte kontoer som er lagret i samme app."), style = MaterialTheme.typography.bodySmall)
                        Text(tx.t("Exception: if you opened the decoy link yourself, this was you.", "Unntak: hvis du åpnet lokkelenken selv, var det deg."), style = MaterialTheme.typography.labelSmall)
                        OutlinedButton(onClick = { Tripwires.clearTrips(context) }) { Text(tx.t("Clear", "Tøm")) }
                    }
                }
            }

            Text(tx.t("Plant a decoy", "Legg ut et lokkemiddel"), style = MaterialTheme.typography.titleSmall)
            val can = Tripwires.canPlant()
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = can, onClick = { failed = !Tripwires.plantContact(context, tx.no) }, modifier = Modifier.weight(1f)) { Text(tx.t("Contact", "Kontakt")) }
                OutlinedButton(enabled = can, onClick = { failed = !Tripwires.plantNote(context, tx.no) }, modifier = Modifier.weight(1f)) { Text(tx.t("Note", "Notat")) }
                OutlinedButton(enabled = can, onClick = { filePicker.launch(if (tx.no) "kontoer.txt" else "accounts.txt") }, modifier = Modifier.weight(1f)) { Text(tx.t("File", "Fil")) }
            }
            Text(tx.t("Contact opens your Contacts app with the decoy filled in; tap Save there. Note opens the share menu; save it in your notes app. File asks where to save it. Do not open the decoy's link yourself.",
                "Kontakt åpner Kontakter-appen med lokkemiddelet fylt ut; trykk Lagre der. Notat åpner delemenyen; lagre det i notatappen. Fil spør hvor den skal lagres. Ikke åpne lenken i lokkemiddelet selv."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (failed) Text(tx.t("That did not work on this phone (no app to receive it, or the save failed).", "Det virket ikke på denne telefonen (ingen app kunne ta imot det, eller lagringen feilet)."), style = MaterialTheme.typography.bodySmall, color = strong.accent)

            if (t.tokens.isNotEmpty()) {
                HorizontalDivider()
                Text(tx.t("Your decoys", "Dine lokkemidler"), style = MaterialTheme.typography.titleSmall)
                t.tokens.forEach { tok ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(kindName(tok.kind(), tx) + if (tok.kind() == CanaryTokens.Kind.CONTACT) " · " + CanaryTokens.contactName(tok) else "", style = MaterialTheme.typography.bodyMedium)
                            Text(tx.t("Added ", "Lagt til ") + whenText(context, tok.createdMillis()), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(enabled = !t.testRunning, onClick = { Tripwires.selfTest(context, tok) }) { Text(tx.t("Test", "Test")) }
                        TextButton(onClick = { Tripwires.remove(context, tok.id()) }) { Text(tx.t("Remove", "Fjern")) }
                    }
                }
                when (t.testResult) {
                    "ok" -> Text(tx.t("Test passed: Aegis saw the lookup and answered it locally.", "Testen besto: Aegis så oppslaget og besvarte det lokalt."), style = MaterialTheme.typography.bodySmall)
                    "off" -> Text(tx.t("Test not seen: turn on DNS protection first.", "Testen ble ikke sett: slå på DNS-beskyttelsen først."), style = MaterialTheme.typography.bodySmall)
                    "missed" -> Text(tx.t("Test not seen although protection is on. The phone may use its own encrypted DNS; tripwires may not work here.", "Testen ble ikke sett selv om beskyttelsen er på. Telefonen bruker kanskje egen kryptert DNS; snubletråder virker kanskje ikke her."), style = MaterialTheme.typography.bodySmall, color = strong.accent)
                    else -> if (t.testRunning) Text(tx.t("Testing…", "Tester…"), style = MaterialTheme.typography.bodySmall)
                }
                Text(tx.t("Removing a decoy here stops watching it; delete the contact, note or file in its own app too.", "Fjerner du et lokkemiddel her, overvåkes det ikke lenger; slett kontakten, notatet eller filen i appen den ligger i også."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(tx.t("Only actions taken on this phone through its normal DNS are seen. Data copied off the phone and used elsewhere, or apps with their own encrypted DNS, are not detected.",
                "Bare handlinger på denne telefonen via vanlig DNS blir sett. Data som kopieres ut og brukes et annet sted, eller apper med egen kryptert DNS, oppdages ikke."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
