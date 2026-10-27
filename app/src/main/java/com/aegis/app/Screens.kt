package com.aegis.app

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.core.InputKind
import com.aegis.core.ResultSummary.Level
import kotlinx.coroutines.delay

private fun isDebuggable(context: Context) = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

// ---------------------------------------------------------------------------------------------------------------
// Root: bottom navigation, global agent banner, dialogs
// ---------------------------------------------------------------------------------------------------------------

@Composable
fun AegisApp(s: UiState, vm: AegisViewModel, context: Context) {
    val tx = Tx(s.norwegian)
    val colors = appColors(s.dark)
    val hostView = LocalView.current
    val reduceMotion = remember { try { Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f } catch (_: Exception) { false } }
    var lastWaiting by remember { mutableIntStateOf(1) }
    SideEffect {
        (context as? Activity)?.window?.let { w -> WindowCompat.getInsetsController(w, hostView).apply { isAppearanceLightStatusBars = !s.dark; isAppearanceLightNavigationBars = !s.dark } }
    }
    LaunchedEffect(Unit) { vm.refreshIntel(); Protection.load(context); AgentGateway.load(context); Tripwires.load(context) }
    val pairings by AgentGateway.pairings.collectAsStateWithLifecycle()
    val approvals by AgentGateway.approvals.collectAsStateWithLifecycle()
    val pairedAgents by AgentGateway.paired.collectAsStateWithLifecycle()
    val trustedHosts by AgentGateway.trusted.collectAsStateWithLifecycle()
    val powers by PowerWatch.state.collectAsStateWithLifecycle()
    val tripwires by Tripwires.state.collectAsStateWithLifecycle()
    // Re-check app powers whenever Aegis comes to the front, e.g. after the person changed something in Settings.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { runCatching { PowerWatch.refresh(context) } }
    val running by Protection.running.collectAsStateWithLifecycle()
    val watching = running && (s.screen == Screens.HOME || s.screen == Screens.PROTECT)
    val stats = produceState(ProtectionStats(), running, watching) {
        if (!running) value = ProtectionStats()
        else if (watching) while (true) { value = Protection.snapshot(); delay(1000) }
    }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(vm::inspect) }
    val bundlePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(vm::importBundle) }
    val pickApk = { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "application/zip")) }

    var showDisclosure by remember { mutableStateOf(false) }
    var reviewOpen by remember { mutableStateOf(false) }
    var unpairTarget by remember { mutableStateOf<String?>(null) }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r -> if (r.resultCode == Activity.RESULT_OK) AegisVpnService.start(context) }
    fun beginProtection() { val intent = VpnService.prepare(context); if (intent != null) consent.launch(intent) else AegisVpnService.start(context) }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { beginProtection() }
    val waiting = pairings.size + approvals.size
    if (waiting > 0) lastWaiting = waiting

    CompositionLocalProvider(LocalReduceMotion provides reduceMotion) { MaterialTheme(colorScheme = colors) {
        BackHandler(enabled = s.screen != Screens.HOME) { vm.go(Screens.HOME) }
        if (showDisclosure) AlertDialog(
            onDismissRequest = { showDisclosure = false },
            title = { Text(tx.t("Before you turn on DNS protection", "Før du slår på DNS-beskyttelse")) },
            text = {
                Text(tx.t("Aegis will use Android's VPN feature for one purpose: to check the website names (DNS lookups) your apps ask for. Names on the threat database or your block list are refused. All other names are passed on to your network's DNS server. If your phone uses encrypted Private DNS in Automatic mode, those passed-on lookups are sent as ordinary, unencrypted DNS.\n\nOther traffic does not go through Aegis, nothing is decrypted, no certificate is installed, and Aegis does not send lookups to the developer or any other server. Android will now show its own VPN request. You can stop at any time here or in Android's VPN settings.",
                    "Aegis bruker Androids VPN-funksjon til ett formål: å sjekke nettstedsnavnene (DNS-oppslag) appene dine ber om. Navn i trusseldatabasen eller blokkeringslisten din nektes. Alle andre navn sendes videre til nettverkets DNS-tjener. Bruker telefonen din kryptert privat DNS i automatisk modus, sendes de videresendte oppslagene som vanlig, ukryptert DNS.\n\nAnnen trafikk går ikke gjennom Aegis, ingenting dekrypteres, ingen sertifikater installeres, og Aegis sender ikke oppslag til utvikleren eller andre tjenere. Android viser nå sin egen VPN-forespørsel. Du kan stoppe når som helst her eller i Androids VPN-innstillinger."))
            },
            confirmButton = {
                TextButton(onClick = {
                    showDisclosure = false
                    if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS) else beginProtection()
                }) { Text(tx.t("Continue", "Fortsett")) }
            },
            dismissButton = { TextButton(onClick = { showDisclosure = false }) { Text(tx.t("Cancel", "Avbryt")) } },
        )
        if (reviewOpen && waiting > 0) AgentReviewDialog(pairings, approvals, powers, tx, s.dark, onDismiss = { reviewOpen = false },
            onPair = { req, allow, risky -> if (allow) AgentGateway.approvePairing(context, req, risky) else AgentGateway.rejectPairing(context, req) },
            onResolve = { id, ok -> AgentGateway.resolve(context, id, ok) })
        else if (reviewOpen) LaunchedEffect(Unit) { reviewOpen = false }
        unpairTarget?.let { pkg ->
            ConfirmDialog(tx.t("Remove this AI agent?", "Fjerne denne KI-agenten?"), pkg + "\n\n" + tx.t("It will have to ask for permission again.", "Den må be om tillatelse på nytt."),
                tx.t("Remove", "Fjern"), tx.t("Cancel", "Avbryt"), onConfirm = { AgentGateway.unpair(context, pkg); unpairTarget = null }, onDismiss = { unpairTarget = null })
        }

        Scaffold(containerColor = colors.background, bottomBar = {
            NavigationBar(containerColor = colors.surfaceContainer) {
                val items = listOf(Screens.HOME to tx.t("Home", "Hjem"), Screens.CHECK to tx.t("Check", "Sjekk"), Screens.PROTECT to tx.t("Protection", "Beskyttelse"), Screens.MORE to tx.t("More", "Mer"))
                items.forEach { (id, label) ->
                    NavigationBarItem(selected = s.screen == id, onClick = { if (!s.busy) vm.go(id) }, icon = { Ico(when (id) { Screens.HOME -> R.drawable.ic_home; Screens.CHECK -> R.drawable.ic_check; Screens.PROTECT -> R.drawable.ic_shield; else -> R.drawable.ic_more }, Modifier.clearAndSetSemantics { }) }, label = { Text(label, maxLines = 1) })
                }
            }
        }) { pad ->
            Column(Modifier.padding(pad).fillMaxSize()) {
                if (s.intel.loaded && s.intel.anchorsPresent && isDebuggable(context)) TestBuildBanner(tx)
                AnimatedVisibility(waiting > 0, enter = if (reduceMotion) EnterTransition.None else slideInVertically(tween(260)) { -it / 2 } + expandVertically(tween(260)) + fadeIn(tween(260)),
                    exit = if (reduceMotion) ExitTransition.None else shrinkVertically(tween(200)) + fadeOut(tween(200))) {
                    AgentBanner(if (waiting > 0) waiting else lastWaiting, s.dark, tx) { reviewOpen = true }
                }
                Box(Modifier.weight(1f)) {
                    AnimatedContent(targetState = s.screen, label = "screen", transitionSpec = {
                        if (reduceMotion) EnterTransition.None togetherWith ExitTransition.None
                        else { val dir = if (targetState > initialState) 1 else -1
                            (fadeIn(tween(240, delayMillis = 60)) + slideInHorizontally(tween(260)) { it / 14 * dir }) togetherWith fadeOut(tween(120)) }
                    }) { screen ->
                        when (screen) {
                            Screens.HOME -> HomeScreen(s, vm, tx, stats, running, pairings.size + approvals.size, pairedAgents.size, powers, tripwires, pickApk) { reviewOpen = true }
                            Screens.CHECK -> CheckScreen(s, vm, tx, context, pickApk)
                            Screens.PROTECT -> ProtectScreen(s, tx, stats, running, pairedAgents.keys.sorted(), trustedHosts, powers, tripwires, waiting, onStart = { showDisclosure = true }, onReview = { reviewOpen = true }, onUnpair = { unpairTarget = it }, context = context)
                            else -> MoreScreen(s, vm, tx, context) { bundlePicker.launch(arrayOf("*/*")) }
                        }
                    }
                }
            }
        }
    } }
}

// ---------------------------------------------------------------------------------------------------------------
// Home: what needs attention, quick actions, one line per feature
// ---------------------------------------------------------------------------------------------------------------

private class Attention(val text: String, val action: String, val go: () -> Unit)

@Composable
private fun HomeScreen(s: UiState, vm: AegisViewModel, tx: Tx, stats: State<ProtectionStats>, running: Boolean, waiting: Int, paired: Int, powers: PowerState, tripwires: TripwireState, pickApk: () -> Unit, onReview: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val calm = levelStyle(Level.CLEAR, s.dark).accent
    val warn = levelStyle(Level.SUSPICIOUS, s.dark).accent
    val off = MaterialTheme.colorScheme.outline
    val lockdown by AgentGateway.lockdown.collectAsStateWithLifecycle()
    val audit by AgentGateway.audit.collectAsStateWithLifecycle()
    val items = buildList {
        if (lockdown) add(Attention(tx.t("Emergency stop for AI agents is on: every agent request is refused.", "Nødstopp for KI-agenter er på: alle forespørsler fra agenter nektes."), tx.t("View", "Vis")) { vm.go(Screens.PROTECT) })
        if (!audit.intactAtLoad) add(Attention(tx.t("The saved AI agent log was damaged or changed.", "Den lagrede KI-agentloggen var skadet eller endret."), tx.t("View", "Vis")) { vm.go(Screens.PROTECT) })
        if (waiting > 0) add(Attention(if (waiting == 1) tx.t("An AI agent is waiting for your decision.", "En KI-agent venter på avgjørelsen din.") else tx.t("$waiting AI agent requests are waiting for your decision.", "$waiting forespørsler fra KI-agenter venter på deg."), tx.t("Review", "Se på"), onReview))
        if (tripwires.trips.any { !it.test }) add(Attention(tx.t("A tripwire was triggered: something tried to use your decoy data.", "En snubletråd er utløst: noe prøvde å bruke lokkedataene dine."), tx.t("View", "Vis")) { vm.go(Screens.PROTECT) })
        if (powers.alerts.isNotEmpty()) add(Attention(if (powers.alerts.size == 1) tx.t("An app got new power over your phone (for example screen control).", "En app har fått ny makt over telefonen (for eksempel skjermstyring).") else tx.t("${powers.alerts.size} new app powers over your phone.", "${powers.alerts.size} nye app-tilganger over telefonen."), tx.t("Review", "Se på")) { vm.go(Screens.PROTECT) })
        if (s.intel.loaded && s.intel.loadWarning) add(Attention(tx.t("The saved threat database failed its check and is not being used.", "Den lagrede trusseldatabasen besto ikke kontrollen og brukes ikke."), tx.t("Open", "Åpne")) { vm.go(Screens.MORE) })
        else if (s.intel.loaded && s.intel.stale) add(Attention(tx.t("The threat database has expired. It still works but may miss recent threats.", "Trusseldatabasen er utløpt. Den virker fortsatt, men kan overse nye trusler."), tx.t("Open", "Åpne")) { vm.go(Screens.MORE) })
        s.result?.takeIf { it.error == null && it.summary.level.compareTo(Level.SUSPICIOUS) >= 0 }?.let { r ->
            add(Attention(tx.t("Your last check: ", "Din siste sjekk: ") + headline(r, tx.no), tx.t("View", "Vis")) { vm.go(Screens.CHECK) })
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            AegisMark(56.dp)
            Column {
                Text("AEGIS", Modifier.semantics { }, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, letterSpacing = 3.sp)
                Text(tx.t("Pause. Check. Decide.", "Stopp. Sjekk. Vurder."), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
            }
        }
        val style = levelStyle(if (items.isEmpty()) Level.CLEAR else Level.SUSPICIOUS, s.dark)
        Card(Modifier.animateContentSize(), shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = style.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    GlyphBadge(style, 40.dp)
                    Text(if (items.isEmpty()) tx.t("Nothing needs your attention", "Ingenting krever oppmerksomheten din") else if (items.size == 1) tx.t("1 thing needs your attention", "1 ting krever oppmerksomheten din") else tx.t("${items.size} things need your attention", "${items.size} ting krever oppmerksomheten din"),
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = Modifier.semantics { })
                }
                if (items.isEmpty()) Text(tx.t("Aegis checks what you give it, and DNS lookups if you turn on DNS protection. It does not scan your phone in the background.", "Aegis sjekker det du gir den, og DNS-oppslag hvis du slår på DNS-beskyttelse. Den skanner ikke telefonen i bakgrunnen."), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                items.forEach { a ->
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(a.text, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        OutlinedButton(onClick = a.go) { Text(a.action) }
                    }
                }
            }
        }
        SectionTitle(tx.t("Check something", "Sjekk noe"))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { vm.go(Screens.CHECK) }, Modifier.weight(1f).heightIn(min = 52.dp)) { IconLabel(R.drawable.ic_link, tx.t("Link or message", "Lenke eller melding"), 2) }
            OutlinedButton(onClick = { pickApk() }, Modifier.weight(1f).heightIn(min = 52.dp)) { IconLabel(R.drawable.ic_file, tx.t("APK file", "APK-fil"), 2) }
        }
        SectionTitle(tx.t("Status", "Status"))
        val st = stats.value
        StatusRow(R.drawable.ic_globe, tx.t("DNS protection", "DNS-beskyttelse"), if (running) tx.t("On · ${st.queries} lookups checked · ${st.blocked} blocked", "På · ${st.queries} oppslag sjekket · ${st.blocked} blokkert") else tx.t("Off · optional, you start it", "Av · valgfri, du starter den selv"), if (running) calm else off) { vm.go(Screens.PROTECT) }
        val i = s.intel
        StatusRow(R.drawable.ic_database, tx.t("Threat database", "Trusseldatabase"), when {
            !i.loaded -> tx.t("Checking…", "Sjekker…")
            i.sequence == 0L -> tx.t("None installed · known-threat lookups unavailable", "Ingen installert · oppslag mot kjente trusler utilgjengelig")
            else -> tx.t("Version ${i.sequence} · ${i.indicators} entries", "Versjon ${i.sequence} · ${i.indicators} oppføringer")
        }, if (!i.loaded || i.sequence == 0L) off else if (i.stale || i.loadWarning) warn else calm) { vm.go(Screens.MORE) }
        val high = powers.apps.count { it.risk() == com.aegis.core.CapabilityWatch.Risk.HIGH }
        StatusRow(R.drawable.ic_lock, tx.t("App powers", "App-tilganger"), when {
            !powers.loaded -> tx.t("Checking…", "Sjekker…")
            powers.alerts.isNotEmpty() -> tx.t("${powers.alerts.size} new since you last looked", "${powers.alerts.size} nye siden sist")
            high > 0 -> tx.t("$high app(s) with high power · ${powers.apps.size} in total", "$high app(er) med stor makt · ${powers.apps.size} totalt")
            else -> tx.t("${powers.apps.size} app(s) with special access · none with high power", "${powers.apps.size} app(er) med spesialtilgang · ingen med stor makt")
        }, if (powers.alerts.isNotEmpty() || high > 0) warn else if (powers.loaded) calm else off) { vm.go(Screens.PROTECT) }
        StatusRow(R.drawable.ic_agent, tx.t("AI agent guard", "KI-agentvakt"), if (paired == 0) tx.t("No apps connected", "Ingen apper koblet til") else tx.t("$paired app(s) connected · $waiting waiting", "$paired app(er) koblet til · $waiting venter"), if (waiting > 0) warn else if (paired > 0) calm else off) { vm.go(Screens.PROTECT) }
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        StatusRow(R.drawable.ic_phone, tx.t("This phone", "Denne telefonen"), tx.t("Screen lock ${if (keyguard.isDeviceSecure) "on" else "OFF"} · security patch ${Build.VERSION.SECURITY_PATCH.ifBlank { "unknown" }}", "Skjermlås ${if (keyguard.isDeviceSecure) "på" else "AV"} · sikkerhetsoppdatering ${Build.VERSION.SECURITY_PATCH.ifBlank { "ukjent" }}"), if (keyguard.isDeviceSecure) calm else warn) { vm.go(Screens.MORE) }
        StatusRow(R.drawable.ic_sparkle, tx.t("Experimental text classifier", "Eksperimentell tekstklassifiserer"), if (s.aiEnabled) tx.t("On for messages", "På for meldinger") else tx.t("Off", "Av"), if (s.aiEnabled) calm else off) { vm.go(Screens.MORE) }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Check: one box for links and messages, plus APK review, one result card
// ---------------------------------------------------------------------------------------------------------------

@Composable
private fun CheckScreen(s: UiState, vm: AegisViewModel, tx: Tx, context: Context, pickApk: () -> Unit) {
    val effective = s.kindOverride ?: InputKind.detect(s.input)
    val bring = remember { BringIntoViewRequester() }
    LaunchedEffect(s.result) { if (s.result != null) { delay(80); bring.bringIntoView() } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        ScreenTitle(tx.t("Check something", "Sjekk noe"))
        OutlinedTextField(value = s.input, onValueChange = vm::input, enabled = !s.busy, modifier = Modifier.fillMaxWidth(), minLines = 4, maxLines = 8, shape = RoundedCornerShape(18.dp),
            label = { Text(tx.t("Paste a link or a message", "Lim inn en lenke eller melding")) },
            supportingText = { Text("${s.input.length} / $MAX_TEXT · " + tx.t("Stays on this phone, not saved", "Blir på denne telefonen, lagres ikke")) })
        if (s.inputTooLong) Text(tx.t("The text was longer than $MAX_TEXT characters and was shortened. Use a smaller excerpt.", "Teksten var lengre enn $MAX_TEXT tegn og ble forkortet. Bruk et mindre utdrag."), color = MaterialTheme.colorScheme.error)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                val clip = context.getSystemService(ClipboardManager::class.java).primaryClip
                val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                if (!text.isNullOrBlank()) vm.input(text)
            }, enabled = !s.busy) { IconLabel(R.drawable.ic_paste, tx.t("Paste", "Lim inn")) }
            if (s.input.isNotBlank()) {
                FilterChip(selected = effective == InputKind.Kind.LINK, onClick = { vm.setKind(InputKind.Kind.LINK) }, enabled = !s.busy, leadingIcon = { Ico(R.drawable.ic_link, size = 18.dp) }, label = { Text(tx.t("Link", "Lenke")) })
                FilterChip(selected = effective == InputKind.Kind.MESSAGE, onClick = { vm.setKind(InputKind.Kind.MESSAGE) }, enabled = !s.busy, leadingIcon = { Ico(R.drawable.ic_message, size = 18.dp) }, label = { Text(tx.t("Message", "Melding")) })
                if (s.kindOverride == null) Text(tx.t("detected", "oppdaget"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = vm::analyze, enabled = s.input.isNotBlank() && !s.busy && !s.inputTooLong, modifier = Modifier.weight(1f).heightIn(min = 52.dp)) { IconLabel(R.drawable.ic_check, tx.t("Check", "Sjekk")) }
            OutlinedButton(onClick = vm::clear, enabled = !s.busy && (s.input.isNotEmpty() || s.result != null), modifier = Modifier.heightIn(min = 52.dp)) { Text(tx.t("Clear", "Tøm")) }
        }
        Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("Review an APK file", "Gjennomgå en APK-fil"), icon = R.drawable.ic_file)
                Text(tx.t("Looks inside an Android installation file you choose: its fingerprint, what it asks for, and risky combinations. Nothing is installed or run, and nothing leaves your phone. Up to 100 MiB.", "Ser inni en Android-installasjonsfil du velger: fingeravtrykk, hva den ber om og risikable kombinasjoner. Ingenting installeres eller kjøres, og ingenting forlater telefonen. Opptil 100 MiB."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = pickApk, enabled = !s.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { IconLabel(R.drawable.ic_file, tx.t("Choose APK file", "Velg APK-fil")) }
            }
        }
        if (s.busy) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(tx.t("Checking on this phone…", "Sjekker på denne telefonen…"), Modifier.semantics { })
        }
        s.result?.let { ResultCard(it, s.dark, tx, Modifier.fillMaxWidth().bringIntoViewRequester(bring)) }
        if (s.result == null && !s.busy) Text(tx.t("Results give evidence, not guarantees. \"No known warning signs\" never means safe.", "Resultatene gir indikasjoner, ikke garantier. «Ingen kjente faresignaler» betyr aldri trygt."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Protection: DNS protection and AI agents
// ---------------------------------------------------------------------------------------------------------------

@Composable
private fun Expander(title: String, content: @Composable ColumnScope.() -> Unit) {
    var open by rememberSaveable { mutableStateOf(false) }
    Column {
        TextButton(onClick = { open = !open }, contentPadding = PaddingValues(horizontal = 4.dp)) { Text((if (open) "▾ " else "▸ ") + title) }
        if (open) Column(verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
    }
}

@Composable
private fun ProtectScreen(s: UiState, tx: Tx, stats: State<ProtectionStats>, running: Boolean, paired: List<String>, trustedHosts: List<String>, powers: PowerState, tripwires: TripwireState, waiting: Int, onStart: () -> Unit, onReview: () -> Unit, onUnpair: (String) -> Unit, context: Context) {
    val st = stats.value
    val calm = levelStyle(Level.CLEAR, s.dark).accent
    var listVersion by remember { mutableIntStateOf(0) }
    var domain by rememberSaveable { mutableStateOf("") }
    var domainError by remember { mutableStateOf(false) }
    val allowed = remember(listVersion) { Protection.lists.allowed().toList() }
    val blocked = remember(listVersion) { Protection.lists.blocked().toList() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        ScreenTitle(tx.t("Protection", "Beskyttelse"))
        PowersCard(powers, tx, s.dark, context)
        TripwireCard(tripwires, running, tx, s.dark, context)
        val lockdown by AgentGateway.lockdown.collectAsStateWithLifecycle()
        val audit by AgentGateway.audit.collectAsStateWithLifecycle()
        KillSwitchCard(lockdown, paired.size, powers, tx, s.dark, context)
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SectionTitle(tx.t("DNS protection", "DNS-beskyttelse"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_globe); Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                    BreathingIcon(R.drawable.ic_power, running, calm)
                    Text(if (running) tx.t("On", "På") else tx.t("Off", "Av"), style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = if (running) calm else MaterialTheme.colorScheme.onSurface)
                }
                Text(tx.t("Refuses websites that are on your threat database or block list. Only website-name lookups are checked; other traffic is not touched.", "Nekter nettsteder som står i trusseldatabasen eller blokkeringslisten din. Bare oppslag av nettstedsnavn sjekkes; annen trafikk berøres ikke."), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (running) {
                    Text(tx.t("${st.queries} lookups checked · ${st.blocked} blocked", "${st.queries} oppslag sjekket · ${st.blocked} blokkert") + if (st.warned > 0) tx.t(" · ${st.warned} warnings", " · ${st.warned} advarsler") else "", fontWeight = FontWeight.SemiBold)
                    st.recent.take(5).forEach { e -> Text("• ${e.name()} — " + (if (e.reason() == com.aegis.core.DnsFilter.Reason.CANARY) tx.t("TRIPWIRE", "SNUBLETRÅD") else if (e.warnOnly()) tx.t("warned", "advart") else tx.t("blocked", "blokkert")), style = MaterialTheme.typography.bodySmall) }
                    OutlinedButton(onClick = { AegisVpnService.stop(context) }, Modifier.fillMaxWidth().heightIn(min = 52.dp)) { IconLabel(R.drawable.ic_power, tx.t("Stop DNS protection", "Stopp DNS-beskyttelse")) }
                } else {
                    Button(onClick = onStart, Modifier.fillMaxWidth().heightIn(min = 52.dp)) { IconLabel(R.drawable.ic_power, tx.t("Turn on DNS protection", "Slå på DNS-beskyttelse")) }
                    Text(tx.t("Android will ask for permission first. Aegis never starts this silently.", "Android spør om tillatelse først. Aegis starter aldri dette i det stille."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Expander(tx.t("How it works and its limits", "Slik virker det og begrensningene")) {
                    Text(tx.t("Uses Android's VPN feature only for DNS lookups (the step that turns a website name into an address). Nothing is decrypted and no certificate is installed. Names not blocked go to your network's normal DNS server. Browsers with their own secure DNS, and apps that skip system DNS, are not covered. Not yet tested on a real device.", "Bruker Androids VPN-funksjon bare for DNS-oppslag (steget som gjør et nettstedsnavn om til en adresse). Ingenting dekrypteres og ingen sertifikater installeres. Navn som ikke blokkeres går til nettverkets vanlige DNS-tjener. Nettlesere med egen sikker DNS og apper som omgår system-DNS dekkes ikke. Ikke testet på en ekte enhet ennå."), style = MaterialTheme.typography.bodySmall)
                    if (running) Text(tx.t("Technical: ${st.failed} resolver errors, ${st.dropped} packets ignored.", "Teknisk: ${st.failed} DNS-feil, ${st.dropped} pakker ignorert."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SectionTitle(tx.t("Your allow and block lists (${allowed.size + blocked.size})", "Dine tillatt- og blokkeringslister (${allowed.size + blocked.size})"), icon = R.drawable.ic_lock)
                OutlinedTextField(value = domain, onValueChange = { domain = it.take(253); domainError = false }, singleLine = true, isError = domainError, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp),
                    label = { Text(tx.t("Domain, e.g. example.com", "Domene, f.eks. example.com")) },
                    supportingText = { if (domainError) Text(tx.t("Enter a domain name like example.com, without http:// or spaces.", "Skriv et domenenavn som example.com, uten http:// eller mellomrom.")) })
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(onClick = { if (Protection.allow(context, domain)) { domain = ""; listVersion++ } else domainError = true }, enabled = domain.isNotBlank(), modifier = Modifier.weight(1f)) { Text(tx.t("Always allow", "Tillat alltid")) }
                    OutlinedButton(onClick = { if (Protection.block(context, domain)) { domain = ""; listVersion++ } else domainError = true }, enabled = domain.isNotBlank(), modifier = Modifier.weight(1f)) { Text(tx.t("Always block", "Blokker alltid")) }
                }
                allowed.take(20).forEach { d -> Row(verticalAlignment = Alignment.CenterVertically) { Text(tx.t("Allowed: ", "Tillatt: ") + d, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall); TextButton(onClick = { Protection.removeAllow(context, d); listVersion++ }) { Text(tx.t("Remove", "Fjern")) } } }
                blocked.take(20).forEach { d -> Row(verticalAlignment = Alignment.CenterVertically) { Text(tx.t("Blocked: ", "Blokkert: ") + d, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall); TextButton(onClick = { Protection.removeBlock(context, d); listVersion++ }) { Text(tx.t("Remove", "Fjern")) } } }
                if (allowed.size > 20 || blocked.size > 20) Text(tx.t("Showing the first 20 of each list.", "Viser de første 20 i hver liste."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SectionTitle(tx.t("AI agent guard", "KI-agentvakt"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_agent); Pill(tx.t("Preview", "Forhåndsversjon"), MaterialTheme.colorScheme.secondary)
                }
                Text(tx.t("AI assistants that choose to integrate can ask Aegis before they send data, share files, install apps, run commands or pay. Aegis refuses or asks you, and never decides alone on risky actions. It cannot see or stop assistants that do not ask.", "KI-assistenter som velger å integrere seg kan spørre Aegis før de sender data, deler filer, installerer apper, kjører kommandoer eller betaler. Aegis nekter eller spør deg, og avgjør aldri alene på risikable handlinger. Den ser eller stopper ikke assistenter som ikke spør."), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (lockdown) Text(tx.t("Emergency stop is on: all requests are refused.", "Nødstopp er på: alle forespørsler nektes."), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                if (waiting > 0) Button(onClick = onReview, Modifier.fillMaxWidth().heightIn(min = 52.dp)) { Text(tx.t("Review $waiting waiting request(s)", "Se på $waiting ventende forespørsel(er)")) }
                else Text(tx.t("Nothing waiting.", "Ingenting venter."), style = MaterialTheme.typography.bodySmall)
                if (paired.isEmpty()) Text(tx.t("No apps connected. An assistant app that supports Aegis will ask to connect, and you decide.", "Ingen apper er koblet til. En assistent-app som støtter Aegis vil be om å koble til, og du bestemmer."), style = MaterialTheme.typography.bodySmall)
                paired.forEach { pkg -> Row(verticalAlignment = Alignment.CenterVertically) { Text(pkg, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall); TextButton(onClick = { onUnpair(pkg) }) { Text(tx.t("Remove", "Fjern")) } } }
                var trustInput by remember { mutableStateOf("") }
                var trustError by remember { mutableStateOf(false) }
                Text(tx.t("Trusted destinations", "Betrodde mottakere"), style = MaterialTheme.typography.titleSmall)
                Text(tx.t("Exact web addresses (for example api.example.org) that an assistant may send data to without asking each time. Sub-domains are not included. Secrets, personal numbers and suspicious wording are still stopped.", "Nøyaktige nettadresser (for eksempel api.example.org) som en assistent kan sende data til uten å spørre hver gang. Underdomener er ikke med. Hemmeligheter, personnumre og mistenkelig ordlyd stoppes fortsatt."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                trustedHosts.forEach { h -> Row(verticalAlignment = Alignment.CenterVertically) { Text(h, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall); TextButton(onClick = { AgentGateway.removeTrusted(context, h) }) { Text(tx.t("Remove", "Fjern")) } } }
                OutlinedTextField(value = trustInput, onValueChange = { trustInput = it.take(253); trustError = false }, singleLine = true, isError = trustError, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp),
                    label = { Text(tx.t("Add a trusted host", "Legg til betrodd adresse")) },
                    supportingText = { if (trustError) Text(tx.t("Enter a plain host name such as api.example.org.", "Skriv et vanlig vertsnavn, for eksempel api.example.org.")) })
                OutlinedButton(onClick = { if (AgentGateway.addTrusted(context, trustInput)) trustInput = "" else trustError = true }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("Trust this host", "Stol på denne adressen")) }
            }
        }
        ServerTokenCard(tx, s.dark, context)
        AgentLogCard(audit, tx, s.dark, context)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// More: appearance, threat database, experimental model, device, about
// ---------------------------------------------------------------------------------------------------------------

@Composable
private fun MoreScreen(s: UiState, vm: AegisViewModel, tx: Tx, context: Context, importBundle: () -> Unit) {
    val i = s.intel
    val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        ScreenTitle(tx.t("More", "Mer"))
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                SectionTitle(tx.t("Appearance and language", "Utseende og språk"))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(selected = !s.norwegian, onClick = { if (s.norwegian) vm.language() }, label = { Text("English") })
                    FilterChip(selected = s.norwegian, onClick = { if (!s.norwegian) vm.language() }, label = { Text("Norsk") })
                }
                Row(Modifier.toggleable(value = s.dark, role = Role.Switch, onValueChange = { vm.theme() }).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(tx.t("Dark appearance", "Mørkt utseende"), Modifier.weight(1f)); Switch(checked = s.dark, onCheckedChange = null)
                }
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("Threat database", "Trusseldatabase"), icon = R.drawable.ic_database)
                Text(intelStatus(i, s.norwegian), color = if (i.loaded && (i.loadWarning || i.stale)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                i.message?.let { Text(intelMessage(it, s.norwegian), color = if (it == "OK" || it == "ROLLED_BACK") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error) }
                if (i.anchorsPresent) {
                    Button(onClick = importBundle, enabled = i.loaded && !i.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) { Text(tx.t("Import signed threat bundle", "Importer signert trusselpakke")) }
                    if (i.canRollback) OutlinedButton(onClick = vm::rollbackIntel, enabled = !i.busy, modifier = Modifier.fillMaxWidth()) { Text(tx.t("Restore previous database", "Gjenopprett forrige database")) }
                    if (i.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(tx.t("A bundle is accepted only if its signature matches a key built into this app and it is newer than any installed before. Nothing is downloaded or uploaded.", "En pakke godtas bare hvis signaturen samsvarer med en nøkkel i appen og den er nyere enn tidligere installerte. Ingenting lastes ned eller opp."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else if (isDebuggable(context)) {
                    Text(tx.t("Test build without a trusted signing key.", "Testversjon uten pålitelig signeringsnøkkel."), style = MaterialTheme.typography.bodySmall)
                } else {
                    Text(tx.t("Threat-database updates are not available in this version yet.", "Oppdateringer av trusseldatabasen er ikke tilgjengelige i denne versjonen ennå."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SectionTitle(tx.t("Experimental text classifier", "Eksperimentell tekstklassifiserer"), Modifier.weight(1f, fill = false), icon = R.drawable.ic_sparkle); Pill(tx.t("Experimental", "Eksperimentell"), MaterialTheme.colorScheme.secondary)
                }
                Row(Modifier.toggleable(value = s.aiEnabled, enabled = s.ai.available && !s.busy, role = Role.Switch, onValueChange = { vm.toggleAi() }).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(tx.t("Use it when checking messages", "Bruk den når meldinger sjekkes"))
                        Text(tx.t("On this phone only. It can add a warning, never removes one, and can be wrong.", "Bare på denne telefonen. Den kan legge til en advarsel, fjerner aldri en, og kan ta feil."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = s.aiEnabled, onCheckedChange = null, enabled = s.ai.available && !s.busy)
                }
                if (!s.ai.available && s.ai.loaded) Text(tx.t("The model could not be loaded; rule-based checks still work.", "Modellen kunne ikke lastes; regelbaserte sjekker virker fortsatt."), style = MaterialTheme.typography.bodySmall)
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionTitle(tx.t("This phone", "Denne telefonen"), icon = R.drawable.ic_phone)
                InfoRow(tx.t("Screen lock set up", "Skjermlås satt opp"), if (keyguard.isDeviceSecure) tx.t("Yes", "Ja") else tx.t("No", "Nei"))
                InfoRow(tx.t("Android version", "Android-versjon"), Build.VERSION.RELEASE)
                InfoRow(tx.t("Security patch level", "Sikkerhetsoppdatering"), Build.VERSION.SECURITY_PATCH.ifBlank { tx.t("Unavailable", "Utilgjengelig") })
                Text(tx.t("Reported by Android. It does not show that the phone is secure or show Play Protect status.", "Rapportert av Android. Det viser ikke at telefonen er sikker eller Play Protect-status."), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = { try { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) } catch (_: Exception) { } }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(tx.t("Open Android security settings", "Åpne Androids sikkerhetsinnstillinger")) }
            }
        }
        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SectionTitle(tx.t("About Aegis", "Om Aegis"), icon = R.drawable.ic_info)
                Text(tx.t("No account, no ads, no analytics, no saved scan history. Network access is used only by the optional DNS protection.", "Ingen konto, ingen reklame, ingen analyse, ingen lagret skannehistorikk. Nettverkstilgang brukes bare av den valgfrie DNS-beskyttelsen."), style = MaterialTheme.typography.bodyMedium)
                Text(tx.t("Aegis finds evidence; it cannot guarantee safety. Local checks can miss threats and flag harmless things. Never share passwords or one-time codes.", "Aegis finner indikasjoner; den kan ikke garantere trygghet. Lokale sjekker kan overse trusler og flagge harmløse ting. Del aldri passord eller engangskoder."), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(tx.t("Version 0.8.1-rc12 · preview build: DNS protection, the AI agent guard and the release build have not been tested on real devices yet.", "Versjon 0.8.1-rc12 · forhåndsversjon: DNS-beskyttelse, KI-agentvakten og utgivelsesbygget er ikke testet på ekte enheter ennå."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().heightIn(min = 40.dp).semantics(mergeDescendants = true) { }, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant); Text(value, fontWeight = FontWeight.SemiBold)
    }
}
