package com.aegis.app

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Build
import android.text.format.DateFormat
import android.view.View
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aegis.core.AgentFirewall
import com.aegis.core.AgentFirewall.Event
import com.aegis.core.CapabilityWatch
import com.aegis.core.CapabilityWatch.Capability
import com.aegis.core.ResultSummary.Level

/**
 * On Android 14+ marks the surrounding window's views as accessibility-data-sensitive: only services that declare
 * themselves accessibility tools (such as TalkBack) can read or operate them, so an ordinary app with Accessibility
 * access cannot read or tap Aegis' approval and kill-switch controls. Gesture injection at screen coordinates is not
 * blocked by this; see KNOWN_LIMITATIONS.md.
 */
@Composable
fun GuardFromAccessibilityApps() {
    val view = LocalView.current
    DisposableEffect(view) {
        if (Build.VERSION.SDK_INT >= 34) runCatching { view.rootView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES) }
        onDispose { }
    }
}

private fun Drawable.toSmallBitmap(px: Int): Bitmap {
    val b = Bitmap.createBitmap(px, px, Bitmap.Config.ARGB_8888)
    val c = Canvas(b)
    setBounds(0, 0, px, px); draw(c)
    return b
}

private fun installerText(i: CapabilityWatch.Installer, tx: Tx) = when (i) {
    CapabilityWatch.Installer.STORE -> tx.t("Installed from an app store", "Installert fra en appbutikk")
    CapabilityWatch.Installer.PREINSTALLED -> tx.t("Came with the phone", "Fulgte med telefonen")
    CapabilityWatch.Installer.SIDELOADED -> tx.t("Installed from a file (sideloaded), not from an app store", "Installert fra en fil (sidelastet), ikke fra en appbutikk")
    CapabilityWatch.Installer.OTHER_APP -> tx.t("Installed by another app, not by a known app store", "Installert av en annen app, ikke av en kjent appbutikk")
    CapabilityWatch.Installer.UNKNOWN -> tx.t("Install source unknown", "Ukjent installasjonskilde")
}

private fun pairingReason(code: String, tx: Tx): String? = when (code) {
    "CAN_APPROVE_ITSELF" -> tx.t("It can read Aegis' screen and tap for you, so it could approve its own requests.", "Den kan lese Aegis-skjermen og trykke for deg, så den kan godkjenne sine egne forespørsler.")
    "DRAWS_OVER_APPS" -> tx.t("It asks to draw over other apps, so it can cover or imitate dialogs.", "Den ber om å tegne over andre apper, så den kan dekke over eller etterligne dialoger.")
    "READ_AND_ACT" -> PowerWatch.reasonText(code, tx.no)
    else -> null
}

/**
 * Returns a function that runs an action after the phone's own fingerprint, face or PIN check, which needs no
 * permission and runs in system UI that another app cannot tap through. The action is told whether the check ran:
 * without a screen lock there is nothing to check against, so it runs with false. A failed or cancelled check runs nothing.
 */
@Composable
fun rememberLockGate(tx: Tx, onFailed: () -> Unit = {}): (((Boolean) -> Unit)) -> Unit {
    val context = LocalContext.current
    var waiting by remember { mutableStateOf<((Boolean) -> Unit)?>(null) }
    val check = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val action = waiting; waiting = null
        if (r.resultCode == Activity.RESULT_OK && action != null) action(true) else onFailed()
    }
    return { action ->
        if (!AgentGateway.screenLockSet(context)) action(false)
        else {
            // Fixed text: nothing an agent wrote appears in the system prompt.
            @Suppress("DEPRECATION") val intent = context.getSystemService(KeyguardManager::class.java)?.createConfirmDeviceCredentialIntent(tx.t("Confirm in Aegis", "Bekreft i Aegis"), tx.t("Confirm that it is you.", "Bekreft at det er deg."))
            if (intent != null) { waiting = action; check.launch(intent) } else onFailed()
        }
    }
}

/**
 * Shows the oldest waiting pairing or approval. The safe choice (Deny / Reject) is the prominent button; approving
 * needs the quieter, outlined one. The dialog is pinned to the request it opened with: if a newer one jumps the queue
 * it closes instead of letting a tap land on something the person has not read. Pairing shows who is asking (label,
 * icon, install source) and the powers the app already holds; an app that could tap Aegis' buttons itself needs an
 * extra, deliberate confirmation. Sensitive approvals and risky connections also pass the phone's screen-lock check.
 */
@Composable
fun AgentReviewDialog(pairings: List<PairRequest>, approvals: List<ApprovalItem>, powers: PowerState, tx: Tx, dark: Boolean, onDismiss: () -> Unit, onPair: (PairRequest, Boolean, Boolean, Boolean) -> Unit, onResolve: (String, Boolean, Boolean) -> Unit) {
    val context = LocalContext.current
    val pair = pairings.firstOrNull()
    val item = if (pair == null) approvals.firstOrNull() else null
    if (pair == null && item == null) { LaunchedEffect(Unit) { onDismiss() }; return }
    val currentKey = if (pair != null) "pair:" + pair.packageName else "ask:" + item!!.id
    val shownKey = remember { currentKey }
    if (currentKey != shownKey) { LaunchedEffect(currentKey) { onDismiss() }; return }
    var risky by remember { mutableStateOf(false) }
    var understood by remember { mutableStateOf(false) }
    val info = remember(pair?.packageName) { pair?.let { runCatching { AgentGateway.appInfo(context, it.packageName, powers) }.getOrNull() } }
    val advice = info?.advice
    // Without the app info (not visible to Aegis), assume the worst: ask for the deliberate confirmation too.
    val needsConfirm = pair != null && (advice == null || advice.needsExtraConfirm())
    val agentCanTap = item != null && powers.apps.any { it.packageName() == item.agent && Capability.ACCESSIBILITY in it.capabilities() }
    val sensitive = item != null && AgentFirewall.needsStrongConfirmation(item.type, item.reasons, item.dataKinds)
    val needsLock = item != null && AgentGateway.needsScreenLock(context, item)
    var lockFailed by remember { mutableStateOf(false) }
    val lockGate = rememberLockGate(tx) { lockFailed = true }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Ico(R.drawable.ic_agent, tint = MaterialTheme.colorScheme.primary, size = 28.dp) },
        title = { Text(if (pair != null) tx.t("An app wants to connect as an AI agent", "En app vil koble til som KI-agent") else tx.t("An AI agent asks for permission", "En KI-agent ber om tillatelse")) },
        text = {
            GuardFromAccessibilityApps()
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (pair != null) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        info?.icon?.let { d -> val bmp = remember(d) { runCatching { d.toSmallBitmap(96).asImageBitmap() }.getOrNull() }; if (bmp != null) Image(bmp, contentDescription = null, modifier = Modifier.size(40.dp)) }
                        Column {
                            Text(info?.label ?: pair.packageName, fontWeight = FontWeight.SemiBold)
                            Text(pair.packageName, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    Text(tx.t("The name and icon are chosen by the app itself. The package name above is what Android uses.", "Navnet og ikonet velger appen selv. Pakkenavnet over er det Android bruker."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (info != null) {
                        Text(installerText(info.installer, tx), style = MaterialTheme.typography.bodySmall)
                        val lvl = when (info.advice.risk()) { CapabilityWatch.Risk.HIGH -> Level.STRONG; CapabilityWatch.Risk.MEDIUM -> Level.SUSPICIOUS; else -> Level.CLEAR }
                        Pill(when (info.advice.risk()) { CapabilityWatch.Risk.HIGH -> tx.t("High risk", "Høy risiko"); CapabilityWatch.Risk.MEDIUM -> tx.t("Some risk", "Noe risiko"); else -> tx.t("No extra powers found", "Ingen ekstra tilganger funnet") },
                            levelStyle(lvl, dark).accent)
                        if (info.powers.isNotEmpty()) {
                            Text(tx.t("This app can already:", "Denne appen kan allerede:"), style = MaterialTheme.typography.labelMedium)
                            info.powers.sorted().forEach { Text("• " + PowerWatch.capabilityName(it, tx.no), style = MaterialTheme.typography.bodySmall) }
                        }
                        info.advice.reasons().mapNotNull { pairingReason(it, tx) }.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                    } else Text(tx.t("Aegis could not read details about this app.", "Aegis fikk ikke lest detaljer om denne appen."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Text(tx.t("Only allow apps you recognise. Its signing certificate will be remembered, and a changed certificate is refused later. By default it may only ask about sending data and files.", "Tillat bare apper du kjenner igjen. Signeringssertifikatet huskes, og et endret sertifikat nektes senere. Som standard kan den bare spørre om å sende data og filer."), style = MaterialTheme.typography.bodySmall)
                    Row(Modifier.toggleable(value = risky, role = Role.Checkbox, onValueChange = { risky = it }).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Checkbox(checked = risky, onCheckedChange = null)
                        Text(tx.t("Also let it ask for risky actions: run commands, install apps, pay, use saved credentials, change settings (you still approve each one)", "La den også spørre om risikable handlinger: kjøre kommandoer, installere apper, betale, bruke lagret legitimasjon, endre innstillinger (du godkjenner fortsatt hver for seg)"), style = MaterialTheme.typography.bodySmall)
                    }
                    if (lockFailed) Text(tx.t("Not allowed: the screen-lock check was not completed.", "Ikke tillatt: skjermlåssjekken ble ikke fullført."), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    if (needsConfirm) Row(Modifier.toggleable(value = understood, role = Role.Checkbox, onValueChange = { understood = it }).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Checkbox(checked = understood, onCheckedChange = null)
                        Text(tx.t("I know this app has strong powers over my phone, and I still want to connect it.", "Jeg vet at denne appen har sterk makt over telefonen min, og jeg vil likevel koble den til."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    }
                } else if (item != null) {
                    Text(tx.t("${item.agent} wants to: ${actionText(item.type, tx)}", "${item.agent} vil: ${actionText(item.type, tx)}"), fontWeight = FontWeight.SemiBold)
                    if (agentCanTap) Text(tx.t("Warning: this agent can also tap on your screen. Approve only if you are the one tapping now.", "Advarsel: denne agenten kan også trykke på skjermen. Godkjenn bare hvis det er du som trykker nå."), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    if (item.broker == "OPEN_URL") Text(tx.t("Aegis will open this link itself, exactly as shown below. The agent cannot change it.", "Aegis åpner denne lenken selv, nøyaktig som vist under. Agenten kan ikke endre den."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    if (item.broker == "SHARE_TEXT") Text(tx.t("Aegis will open the share menu with exactly the text below; you choose the app. The agent cannot change it.", "Aegis åpner delemenyen med nøyaktig teksten under; du velger appen. Agenten kan ikke endre den."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    if (item.destinationHost.isNotEmpty()) Text(tx.t("Destination: ", "Mål: ") + item.destinationHost)
                    else if (item.type != "READ_SENSITIVE" && item.broker != "SHARE_TEXT") Text(tx.t("Destination could not be determined.", "Målet kunne ikke fastslås."), color = MaterialTheme.colorScheme.error)
                    if (item.destinationRaw.isNotEmpty() && item.destinationRaw != item.destinationHost) Text(tx.t("As written: ", "Slik det står: ") + item.destinationRaw, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    if (item.amountMinor >= 0) Text(tx.t("Amount (smallest currency unit): ${item.amountMinor} ${item.currency}", "Beløp (minste valutaenhet): ${item.amountMinor} ${item.currency}"), fontWeight = FontWeight.SemiBold)
                    if (item.dataKinds.isNotEmpty()) Text(tx.t("Data contains: ", "Dataene inneholder: ") + item.dataKinds.joinToString(), color = MaterialTheme.colorScheme.error)
                    if (item.payloadPreview.isNotEmpty()) {
                        Text(if (item.type == "EXECUTE_COMMAND") tx.t("The command it wants to run:", "Kommandoen den vil kjøre:") else tx.t("What would be sent (${item.payloadChars} characters in total):", "Dette ville blitt sendt (${item.payloadChars} tegn totalt):"), style = MaterialTheme.typography.labelMedium)
                        Text(item.payloadPreview, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxWidth().heightIn(max = 180.dp).verticalScroll(rememberScrollState()).background(MaterialTheme.colorScheme.surfaceContainerHighest, RoundedCornerShape(8.dp)).padding(8.dp))
                        Text(tx.t("Hidden or control characters are shown as <U+…>.", "Skjulte tegn og kontrolltegn vises som <U+…>."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(tx.t("The agent says: ", "Agenten sier: ") + "\"${item.summary}\"", style = MaterialTheme.typography.bodySmall)
                    item.reasons.forEach { Text("• " + agentReason(it, tx.no), style = MaterialTheme.typography.bodySmall) }
                    if (item.chain.isNotEmpty()) {
                        Text(tx.t("What this agent did just before, in order:", "Hva agenten gjorde rett før, i rekkefølge:"), style = MaterialTheme.typography.labelMedium)
                        item.chain.forEach { Text(chainStepText(it, tx), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
                    }
                    if (lockFailed) Text(tx.t("Not approved: the screen-lock check was not completed.", "Ikke godkjent: skjermlåssjekken ble ikke fullført."), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    if (needsLock) Text(tx.t("Approving needs your fingerprint, face or screen PIN.", "Godkjenning krever fingeravtrykk, ansikt eller skjermkode."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    else if (sensitive) Text(tx.t("This phone has no screen lock, so Aegis cannot check that it is you approving. Set one up in Android's settings.", "Denne telefonen har ingen skjermlås, så Aegis kan ikke sjekke at det er du som godkjenner. Sett opp en i Androids innstillinger."), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    Text(tx.t("This request expires after 5 minutes.", "Forespørselen utløper etter 5 minutter."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(onClick = onDismiss) { Text(tx.t("Decide later", "Avgjør senere")) }
            }
        },
        confirmButton = {
            OutlinedButton(enabled = !needsConfirm || understood, onClick = {
                lockFailed = false
                if (pair != null && risky) lockGate { c -> onPair(pair, true, true, c) }
                else if (pair != null) onPair(pair, true, false, false)
                else if (item != null && needsLock) lockGate { c -> onResolve(item.id, true, c) }
                else if (item != null) onResolve(item.id, true, false)
            }) {
                Text(if (pair != null) tx.t("Allow", "Tillat") else when (item?.broker) { "OPEN_URL" -> tx.t("Approve and open", "Godkjenn og åpne"); "SHARE_TEXT" -> tx.t("Approve and share", "Godkjenn og del"); else -> tx.t("Approve once", "Godkjenn én gang") })
            }
        },
        dismissButton = {
            Button(onClick = { if (pair != null) onPair(pair, false, false, false) else if (item != null) onResolve(item.id, false, false) }) {
                Text(if (pair != null) tx.t("Reject", "Avvis") else tx.t("Deny", "Nekt"))
            }
        },
    )
}

/**
 * Emergency stop for AI agents. Off: one button that disconnects every agent. On: says so, lists the apps that can
 * still read or control the phone without asking Aegis (Accessibility, notification access) with links to the
 * system pages, and lets the person end the lockdown.
 */
@Composable
fun KillSwitchCard(lockdown: Boolean, pairedCount: Int, powers: PowerState, tx: Tx, dark: Boolean, context: Context) {
    val strong = levelStyle(Level.STRONG, dark)
    var confirmOn by remember { mutableStateOf(false) }
    var confirmOff by remember { mutableStateOf(false) }
    var removed by remember { mutableStateOf<Int?>(null) }
    val lockGate = rememberLockGate(tx)
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = if (lockdown) strong.container.compositeOver(MaterialTheme.colorScheme.surfaceContainer) else MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionTitle(tx.t("Emergency stop for AI agents", "Nødstopp for KI-agenter"), icon = R.drawable.ic_power)
            if (!lockdown) {
                Text(tx.t("If an assistant behaves strangely, stop them all at once: every connected agent is disconnected, its extra permissions are removed, waiting and already-approved requests are cancelled, and every new request is refused until you turn this off.",
                    "Hvis en assistent oppfører seg rart, stopp alle på én gang: alle tilkoblede agenter kobles fra, ekstra tillatelser fjernes, ventende og allerede godkjente forespørsler avbrytes, og alle nye forespørsler nektes til du slår dette av."),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = { confirmOn = true }, Modifier.fillMaxWidth().heightIn(min = 52.dp), colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)) {
                    IconLabel(R.drawable.ic_power, tx.t("Stop all AI agents", "Stopp alle KI-agenter"))
                }
            } else {
                Text(tx.t("Emergency stop is ON. Every AI agent request is refused, and no app can ask to connect.", "Nødstopp er PÅ. Alle forespørsler fra KI-agenter nektes, og ingen app kan be om å koble til."), fontWeight = FontWeight.SemiBold)
                removed?.let { Text(tx.t("$it agent(s) were disconnected.", "$it agent(er) ble koblet fra."), style = MaterialTheme.typography.bodySmall) }
                val strongHolders = powers.apps.filter { a -> a.capabilities().any { it == Capability.ACCESSIBILITY || it == Capability.NOTIFICATION_ACCESS } && a.packageName() != PowerWatch.UNKNOWN }
                if (strongHolders.isNotEmpty()) {
                    Text(tx.t("These apps can still read or control the phone without asking Aegis. Switch off any you do not trust in Android's settings:", "Disse appene kan fortsatt lese eller styre telefonen uten å spørre Aegis. Slå av dem du ikke stoler på i Androids innstillinger:"), style = MaterialTheme.typography.bodySmall)
                    strongHolders.forEach { a ->
                        Column {
                            Text(powers.labels[a.packageName()]?.takeIf { it.isNotEmpty() } ?: a.packageName(), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (Capability.ACCESSIBILITY in a.capabilities()) OutlinedButton(onClick = { PowerWatch.openSettings(context, Capability.ACCESSIBILITY) }) { Text(tx.t("Accessibility", "Tilgjengelighet")) }
                                if (Capability.NOTIFICATION_ACCESS in a.capabilities()) OutlinedButton(onClick = { PowerWatch.openSettings(context, Capability.NOTIFICATION_ACCESS) }) { Text(tx.t("Notification access", "Varseltilgang")) }
                            }
                        }
                    }
                } else Text(tx.t("No app with Accessibility or notification access was found.", "Fant ingen app med tilgjengelighet eller varseltilgang."), style = MaterialTheme.typography.bodySmall)
                Text(tx.t("Aegis cannot switch these off for you; Android only lets you do that yourself.", "Aegis kan ikke slå av disse for deg; Android lar bare deg gjøre det selv."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = { confirmOff = true }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("Turn off emergency stop", "Slå av nødstopp")) }
            }
        }
    }
    if (confirmOn) AlertDialog(onDismissRequest = { confirmOn = false },
        title = { Text(tx.t("Stop all AI agents?", "Stoppe alle KI-agenter?")) },
        text = { GuardFromAccessibilityApps(); Text(tx.t("$pairedCount connected agent(s) will be disconnected and must ask to connect again later. Your trusted destinations are kept.", "$pairedCount tilkoblet(e) agent(er) kobles fra og må be om å koble til på nytt senere. Betrodde mottakere beholdes.")) },
        confirmButton = { Button(onClick = { removed = AgentGateway.killSwitch(context).size; confirmOn = false; runCatching { PowerWatch.refresh(context) } },
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)) { Text(tx.t("Stop all", "Stopp alle")) } },
        dismissButton = { TextButton(onClick = { confirmOn = false }) { Text(tx.t("Cancel", "Avbryt")) } })
    if (confirmOff) AlertDialog(onDismissRequest = { confirmOff = false },
        title = { Text(tx.t("Turn off emergency stop?", "Slå av nødstopp?")) },
        text = { GuardFromAccessibilityApps(); Text(tx.t("Agents can then ask to connect again, and you decide each one. Agents that were disconnected stay disconnected.", "Agenter kan da be om å koble til igjen, og du bestemmer for hver. Agenter som ble koblet fra forblir frakoblet.")) },
        confirmButton = { OutlinedButton(onClick = { lockGate { c -> AgentGateway.releaseKillSwitch(context, c); removed = null; confirmOff = false } }) { Text(tx.t("Turn off", "Slå av")) } },
        dismissButton = { Button(onClick = { confirmOff = false }) { Text(tx.t("Keep it on", "Behold den på")) } })
}

/** One emergency stop per kind of action, for every agent at once. The groups match what the person would recognise. */
private val stopGroups: List<Pair<Set<AgentFirewall.ActionType>, Pair<String, String>>> = listOf(
    setOf(AgentFirewall.ActionType.SEND_DATA, AgentFirewall.ActionType.SHARE_FILE, AgentFirewall.ActionType.MESSAGE_AGENT) to ("Sending data, files or messages" to "Sende data, filer eller meldinger"),
    setOf(AgentFirewall.ActionType.READ_SENSITIVE) to ("Reading private data" to "Lese private data"),
    setOf(AgentFirewall.ActionType.FINANCIAL_TRANSACTION) to ("Payments" to "Betalinger"),
    setOf(AgentFirewall.ActionType.INSTALL_APP) to ("Installing apps" to "Installere apper"),
    setOf(AgentFirewall.ActionType.EXECUTE_COMMAND) to ("Running commands" to "Kjøre kommandoer"),
    setOf(AgentFirewall.ActionType.USE_CREDENTIAL) to ("Using saved passwords and keys" to "Bruke lagrede passord og nøkler"),
    setOf(AgentFirewall.ActionType.MODIFY_SETTINGS) to ("Changing settings" to "Endre innstillinger"))

/**
 * Stops for single kinds of action. Stopping takes one tap and refuses that kind for every agent while keeping them
 * connected; allowing it again is confirmed, like ending the full emergency stop.
 */
@Composable
fun CapabilityStopsCard(stopped: Set<AgentFirewall.ActionType>, tx: Tx, context: Context) {
    var confirmResume by remember { mutableStateOf<Set<AgentFirewall.ActionType>?>(null) }
    val lockGate = rememberLockGate(tx)
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            SectionTitle(tx.t("Stop one kind of action", "Stopp én type handling"), icon = R.drawable.ic_lock)
            Text(tx.t("Switch one on to refuse that kind of request from every AI agent, without disconnecting them. Waiting requests of that kind are cancelled.",
                "Slå på en bryter for å nekte den typen forespørsel fra alle KI-agenter, uten å koble dem fra. Ventende forespørsler av den typen avbrytes."),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            stopGroups.forEach { (types, label) ->
                val on = types.all { it in stopped }
                Row(Modifier.fillMaxWidth().toggleable(value = on, role = Role.Switch, onValueChange = { want ->
                    if (want) AgentGateway.setStopped(context, types, true) else confirmResume = types
                }).heightIn(min = 52.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(tx.t(label.first, label.second), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = if (on) FontWeight.SemiBold else FontWeight.Normal)
                    if (on) Text(tx.t("Stopped", "Stoppet"), Modifier.padding(end = 8.dp), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error)
                    Switch(checked = on, onCheckedChange = null)
                }
            }
        }
    }
    confirmResume?.let { types ->
        AlertDialog(onDismissRequest = { confirmResume = null },
            title = { Text(tx.t("Allow this again?", "Tillate dette igjen?")) },
            text = {
                GuardFromAccessibilityApps()
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    stopGroups.firstOrNull { it.first == types }?.let { (_, label) -> Text(tx.t(label.first, label.second), fontWeight = FontWeight.SemiBold) }
                    Text(tx.t("Connected agents can then ask for this again. Aegis still checks each request and asks you when it should.", "Tilkoblede agenter kan da be om dette igjen. Aegis sjekker fortsatt hver forespørsel og spør deg når den skal."))
                }
            },
            confirmButton = { OutlinedButton(onClick = { lockGate { c -> AgentGateway.setStopped(context, types, false, c); confirmResume = null } }) { Text(tx.t("Allow again", "Tillat igjen")) } },
            dismissButton = { Button(onClick = { confirmResume = null }) { Text(tx.t("Keep it stopped", "Behold stoppet")) } })
    }
}

/** Read-only switch for one connected agent. Turning it on takes one tap; turning it off is confirmed. */
@Composable
fun ReadOnlyRow(pkg: String, on: Boolean, tx: Tx, context: Context) {
    var confirmOff by remember { mutableStateOf(false) }
    val lockGate = rememberLockGate(tx)
    Row(Modifier.fillMaxWidth().toggleable(value = on, role = Role.Switch, onValueChange = { want -> if (want) AgentGateway.setReadOnly(context, pkg, true) else confirmOff = true }).heightIn(min = 48.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(tx.t("Read only", "Bare lesing"), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
            Text(tx.t("May only ask to read; sending, paying, installing and the rest are refused.", "Kan bare be om å lese; sending, betaling, installering og resten nektes."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = on, onCheckedChange = null)
    }
    if (confirmOff) AlertDialog(onDismissRequest = { confirmOff = false },
        title = { Text(tx.t("Turn off read only?", "Slå av bare lesing?")) },
        text = { GuardFromAccessibilityApps(); Text(tx.t("$pkg can then ask for everything it was allowed when it connected. Aegis still checks each request.", "$pkg kan da be om alt den fikk lov til da den koblet til. Aegis sjekker fortsatt hver forespørsel.")) },
        confirmButton = { OutlinedButton(onClick = { lockGate { c -> AgentGateway.setReadOnly(context, pkg, false, c); confirmOff = false } }) { Text(tx.t("Turn off", "Slå av")) } },
        dismissButton = { Button(onClick = { confirmOff = false }) { Text(tx.t("Keep it on", "Behold den på")) } })
}

/** An action type in everyday words, fitting after "wants to". */
internal fun actionText(type: String, tx: Tx): String = when (type) {
    "SEND_DATA" -> tx.t("send data", "sende data")
    "SHARE_FILE" -> tx.t("share a file", "dele en fil")
    "MESSAGE_AGENT" -> tx.t("message another agent", "sende melding til en annen agent")
    "READ_SENSITIVE" -> tx.t("read private data", "lese private data")
    "EXECUTE_COMMAND" -> tx.t("run a command", "kjøre en kommando")
    "INSTALL_APP" -> tx.t("install an app", "installere en app")
    "FINANCIAL_TRANSACTION" -> tx.t("make a payment", "betale")
    "USE_CREDENTIAL" -> tx.t("use a saved password or key", "bruke et lagret passord eller en nøkkel")
    "MODIFY_SETTINGS" -> tx.t("change settings", "endre innstillinger")
    else -> type.lowercase().replace('_', ' ')
}

private fun eventText(e: AgentFirewall.AuditEntry, tx: Tx): String {
    val what = e.type()?.name?.let { actionText(it, tx) } ?: ""
    val to = if (e.destinationHost().isNotEmpty()) " → " + e.destinationHost() else ""
    return when (e.event()) {
        Event.DECISION -> when (e.verdict()) {
            AgentFirewall.Verdict.ALLOW -> tx.t("Allowed", "Tillatt")
            AgentFirewall.Verdict.ASK_USER -> tx.t("Asked you", "Spurte deg")
            else -> tx.t("Refused", "Nektet")
        } + ": $what$to"
        Event.USER_APPROVED -> tx.t("You approved", "Du godkjente") + ": $what$to"
        Event.USER_DENIED -> tx.t("You denied", "Du nektet") + ": $what$to"
        Event.REDEEMED -> tx.t("Approval used", "Godkjenning brukt") + ": $what$to"
        Event.REDEEM_REFUSED -> tx.t("Approval refused", "Godkjenning avvist") + ": $what$to"
        Event.PAIRED -> tx.t("Connected", "Koblet til")
        Event.PAIR_REJECTED -> tx.t("Connection rejected", "Tilkobling avvist")
        Event.UNPAIRED -> tx.t("Removed", "Fjernet")
        Event.KILL_SWITCH_ON -> tx.t("Emergency stop turned on", "Nødstopp slått på")
        Event.KILL_SWITCH_OFF -> tx.t("Emergency stop turned off", "Nødstopp slått av")
        Event.DENIALS_SUMMARISED -> tx.t("More refusals, not listed one by one", "Flere avslag, ikke listet enkeltvis") + " (" + e.reasons().joinToString().removePrefix("NOT_LOGGED_") + ")"
        Event.RATE_LIMIT_HIT -> tx.t("Sent too many requests and was slowed down", "Sendte for mange forespørsler og ble bremset")
        Event.TOKEN_ISSUED -> tx.t("Signed a token for the server", "Signerte et bevis for tjeneren") + ": $what$to"
        Event.BROKER_PERFORMED -> tx.t("Aegis carried out", "Aegis utførte") + ": $what$to"
        Event.BROKER_FAILED -> tx.t("Aegis did not carry out", "Aegis utførte ikke") + ": $what$to"
        Event.LOG_DAMAGED -> tx.t("Saved log was damaged or changed; started a new one", "Lagret logg var skadet eller endret; startet en ny")
        Event.CAPABILITY_STOPPED -> tx.t("You stopped for all agents", "Du stoppet for alle agenter") + ": " + e.reasons().joinToString { actionText(it, tx) }
        Event.CAPABILITY_RESUMED -> tx.t("You allowed again for all agents", "Du tillot igjen for alle agenter") + ": " + e.reasons().joinToString { actionText(it, tx) }
        Event.READ_ONLY_ON -> tx.t("Set to read only", "Satt til bare lesing")
        Event.READ_ONLY_OFF -> tx.t("Read only turned off", "Bare lesing slått av")
    }
}

/**
 * Approval tokens for servers: shows this phone's signing-key fingerprint, exports the public key for a backend to
 * enrol, and replaces the key (which invalidates every token until servers enrol the new one).
 */
@Composable
fun ServerTokenCard(tx: Tx, dark: Boolean, context: Context) {
    val strong = levelStyle(Level.STRONG, dark)
    val kid by ApprovalSigner.keyId.collectAsState()
    var message by remember { mutableStateOf<String?>(null) }
    var confirmReplace by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { runCatching { ApprovalSigner.refresh() } }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-pem-file")) { uri ->
        if (uri != null) message = runCatching {
            val pem = ApprovalSigner.pem() ?: error("no key")
            context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(pem.toByteArray(Charsets.US_ASCII)) }
        }.fold({ tx.t("Public key saved. Give it to the server's administrator.", "Offentlig nøkkel lagret. Gi den til administratoren av tjeneren.") }, { tx.t("Could not save the key.", "Kunne ikke lagre nøkkelen.") })
    }
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("Proof for servers", "Bevis for tjenere"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_lock); Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
            }
            Text(tx.t("When Aegis allows an agent's call, or you approve it, Aegis signs a short-lived proof (valid 2 minutes, usable once) for that exact call. A server that has this phone's public key can refuse any agent call that comes without one. The private key never leaves this phone's secure key storage.",
                "Når Aegis tillater et kall fra en agent, eller du godkjenner det, signerer Aegis et kortvarig bevis (gyldig i 2 minutter, kan brukes én gang) for akkurat det kallet. En tjener som har telefonens offentlige nøkkel, kan avvise alle agentkall som kommer uten bevis. Den private nøkkelen forlater aldri telefonens sikre nøkkellager."),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(tx.t("Key fingerprint: ", "Nøkkelens fingeravtrykk: ") + (kid?.chunked(4)?.joinToString(" ") ?: tx.t("no key yet (made on first use)", "ingen nøkkel ennå (lages ved første bruk)")),
                fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall)
            OutlinedButton(onClick = { exporter.launch("aegis-phone-key.pem") }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("Export public key", "Eksporter offentlig nøkkel")) }
            TextButton(onClick = { confirmReplace = true }) { Text(tx.t("Replace key", "Bytt nøkkel")) }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            Text(tx.t("Check the fingerprint with the server's administrator when you hand over the key. The phone's clock must be right for proofs to be accepted.", "Sjekk fingeravtrykket med administratoren av tjeneren når du gir fra deg nøkkelen. Telefonens klokke må gå riktig for at bevisene skal godtas."),
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    if (confirmReplace) AlertDialog(onDismissRequest = { confirmReplace = false },
        title = { Text(tx.t("Replace this phone's key?", "Bytte telefonens nøkkel?")) },
        text = { GuardFromAccessibilityApps(); Text(tx.t("All servers that trust the current key will refuse this phone's proofs until they get the new public key. Do this if you think the old key was misused.", "Alle tjenere som stoler på dagens nøkkel, vil avvise telefonens bevis til de får den nye offentlige nøkkelen. Gjør dette hvis du tror den gamle nøkkelen er misbrukt.")) },
        confirmButton = { OutlinedButton(onClick = { confirmReplace = false; message = if (ApprovalSigner.replace()) tx.t("New key made. Export it to your servers.", "Ny nøkkel laget. Eksporter den til tjenerne dine.") else tx.t("Could not make a new key on this phone.", "Kunne ikke lage ny nøkkel på denne telefonen.") }) { Text(tx.t("Replace", "Bytt")) } },
        dismissButton = { Button(onClick = { confirmReplace = false }) { Text(tx.t("Cancel", "Avbryt")) } })
}

/** The tamper-evident record of what agents asked and what was decided, kept across restarts, with export. */
@Composable
fun AgentLogCard(audit: AuditView, tx: Tx, dark: Boolean, context: Context) {
    val strong = levelStyle(Level.STRONG, dark)
    var showAll by remember { mutableStateOf(false) }
    var exportFailed by remember { mutableStateOf(false) }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) exportFailed = runCatching { context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(AgentGateway.exportAuditText().toByteArray(Charsets.UTF_8)) } }.isFailure
    }
    Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            SectionTitle(tx.t("Agent activity log", "Aktivitetslogg for agenter"), icon = R.drawable.ic_lock)
            Text(tx.t("Every request, your answers, connections and emergency stops. Kept encrypted on this phone and linked so that a changed or removed entry shows.", "Alle forespørsler, svarene dine, tilkoblinger og nødstopp. Lagres kryptert på telefonen og lenket slik at en endret eller fjernet oppføring synes."),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (!audit.intactAtLoad) Text(tx.t("The saved log was damaged, changed or could not be read when Aegis started. A new log was started; entries from before cannot be trusted.", "Den lagrede loggen var skadet, endret eller uleselig da Aegis startet. En ny logg ble startet; tidligere oppføringer kan ikke stoles på."),
                color = strong.accent, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
            if (audit.saveFailed) Text(tx.t("The log could not be saved on this phone; it is kept only until Aegis stops.", "Loggen kunne ikke lagres på telefonen; den beholdes bare til Aegis stopper."), color = strong.accent, style = MaterialTheme.typography.bodySmall)
            if (audit.entries.isEmpty()) Text(tx.t("Nothing yet.", "Ingenting ennå."), style = MaterialTheme.typography.bodySmall)
            audit.entries.take(if (showAll) 50 else 8).forEach { e ->
                Column {
                    Text(eventText(e, tx), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    val t = e.time().toEpochMilli()
                    Text(DateFormat.getMediumDateFormat(context).format(t) + " " + DateFormat.getTimeFormat(context).format(t) + (if (e.agentId().isNotEmpty()) " · " + e.agentId() else "")
                        + (if (e.event() == Event.DECISION && e.verdict() == AgentFirewall.Verdict.DENY) " · " + e.reasons().joinToString { agentReason(it, tx.no) } else ""),
                        style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (audit.entries.size > 8) TextButton(onClick = { showAll = !showAll }) { Text(if (showAll) tx.t("Show fewer", "Vis færre") else tx.t("Show more", "Vis flere")) }
            if (audit.security.isNotEmpty()) {
                Text(tx.t("Security events (kept separately; request traffic cannot push these out)", "Sikkerhetshendelser (lagres separat; forespørsler kan ikke skyve dem ut)"), style = MaterialTheme.typography.titleSmall)
                audit.security.take(if (showAll) 50 else 5).forEach { e ->
                    val t = e.time().toEpochMilli()
                    Text(eventText(e, tx) + " · " + DateFormat.getMediumDateFormat(context).format(t) + " " + DateFormat.getTimeFormat(context).format(t) + (if (e.agentId().isNotEmpty()) " · " + e.agentId() else ""), style = MaterialTheme.typography.labelSmall)
                }
            }
            if (audit.head.length >= 16) Text(tx.t("Log fingerprint: ", "Loggens fingeravtrykk: ") + audit.head.take(16).chunked(4).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall)
            Text(tx.t("Write the fingerprint down or export the log now and then: if someone with access to the phone rewrote the whole log, an older copy would not match.", "Skriv ned fingeravtrykket eller eksporter loggen av og til: hvis noen med tilgang til telefonen skrev om hele loggen, ville en eldre kopi ikke stemme."),
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedButton(onClick = { exporter.launch("aegis-agent-log.txt") }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("Export log", "Eksporter logg")) }
            if (exportFailed) Text(tx.t("Export failed.", "Eksporten feilet."), color = strong.accent, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** One earlier step of the session, from ApprovalItem.chain (TYPE|host|OUTCOME|fromContent). */
internal fun chainStepText(encoded: String, tx: Tx): String {
    val f = encoded.split('|')
    if (f.size != 4) return "• ?"
    val outcome = when (f[2]) {
        "ALLOWED" -> tx.t("allowed", "tillatt")
        "APPROVED" -> tx.t("you approved", "du godkjente")
        "ASKED" -> tx.t("asked, not carried out", "spurt, ikke utført")
        else -> tx.t("refused", "nektet")
    }
    return "• " + actionText(f[0], tx) + (if (f[1].isNotEmpty()) " → " + f[1] else "") + " · " + outcome +
        if (f[3] == "1") tx.t(" · from outside content", " · fra innhold utenfra") else ""
}
