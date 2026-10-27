package com.aegis.app

import androidx.annotation.DrawableRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.core.ResultSummary.Level

/** True when the person has switched system animations off; every animation in the app then snaps instead. */
val LocalReduceMotion = staticCompositionLocalOf { false }

@Composable
private fun ms(duration: Int): Int = if (LocalReduceMotion.current) 0 else duration

/** Decorative or labelled vector icon (the surrounding control carries the accessible name). */
@Composable
fun Ico(@DrawableRes id: Int, modifier: Modifier = Modifier, tint: Color = LocalContentColor.current, size: Dp = 24.dp) =
    Icon(painterResource(id), contentDescription = null, modifier = modifier.size(size), tint = tint)

/** Button content with a leading icon. */
@Composable
fun RowScope.IconLabel(@DrawableRes icon: Int, text: String, maxLines: Int = 1) {
    Ico(icon, size = 20.dp)
    Spacer(Modifier.width(8.dp))
    Text(text, maxLines = maxLines)
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier, @DrawableRes icon: Int? = null) {
    Row(modifier.semantics(mergeDescendants = true) { heading() }, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        if (icon != null) Ico(icon, tint = MaterialTheme.colorScheme.primary, size = 22.dp)
        Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun ScreenTitle(text: String) =
    Text(text, Modifier.semantics { heading() }, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)

/** Small label such as "Preview". Text carries the meaning; colour only supports it. */
@Composable
fun Pill(text: String, color: Color) {
    Text(text, Modifier.background(color.copy(alpha = .16f), RoundedCornerShape(50)).padding(horizontal = 10.dp, vertical = 3.dp),
        color = color, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
}

/** The brand mark (shield with a checking lens). */
@Composable
fun AegisMark(size: Dp = 44.dp) =
    Image(painterResource(R.drawable.ic_logo), contentDescription = null, modifier = Modifier.size(size).clearAndSetSemantics { })

/**
 * Round level badge. It pops in once; for the two most serious levels a single soft ring expands and fades.
 * Nothing loops, and with system animations off it simply appears.
 */
@Composable
fun GlyphBadge(style: LevelStyle, size: Dp = 46.dp, pulse: Boolean = false) {
    val reduce = LocalReduceMotion.current
    var shown by remember { mutableStateOf(reduce) }
    LaunchedEffect(Unit) { shown = true }
    val scale by animateFloatAsState(if (shown) 1f else .6f, if (reduce) tween(0) else spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow), label = "badge")
    val ring = remember { Animatable(if (pulse && !reduce) 0f else 1f) }
    LaunchedEffect(pulse) { if (pulse && !reduce) { ring.snapTo(0f); ring.animateTo(1f, tween(900)) } }
    val accent = style.accent
    Box(Modifier.size(size).scale(scale).clearAndSetSemantics { }
        .drawBehind { if (ring.value < 1f) drawCircle(accent.copy(alpha = .45f * (1f - ring.value)), radius = this.size.minDimension / 2f * (1f + .7f * ring.value)) }
        .background(accent.copy(alpha = .2f), CircleShape).border(2.dp, accent, CircleShape), contentAlignment = Alignment.Center) {
        Ico(style.icon, tint = accent, size = size * .56f)
    }
}

@Composable
private fun Bullet(text: String, marker: String = "•") {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(marker, Modifier.width(18.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(text, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
    }
}

/** The one place results are shown: level and headline first, then why, then what to do, with detail on request. */
@Composable
fun ResultCard(r: ResultUi, dark: Boolean, tx: Tx, modifier: Modifier = Modifier) {
    val level = r.summary.level
    val style = levelStyle(level, dark)
    var expanded by remember(r) { mutableStateOf(false) }
    val reduce = LocalReduceMotion.current
    val enter = remember(r) { Animatable(if (reduce) 1f else 0f) }
    LaunchedEffect(r) { if (!reduce) enter.animateTo(1f, tween(320)) }
    val details = r.summary.details.map { findingText(it, tx.no) } + (r.apk?.let { apkFactLines(it, tx.no) } ?: emptyList()) + r.summary.limitations.map { findingText(it, tx.no) }
    Card(modifier.graphicsLayer { alpha = enter.value; translationY = (1f - enter.value) * 28.dp.toPx() }.animateContentSize().semantics { liveRegion = LiveRegionMode.Polite },
        shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = style.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.Top) {
                GlyphBadge(style, pulse = level == Level.CONFIRMED || level == Level.STRONG)
                Column(Modifier.weight(1f).semantics(mergeDescendants = true) { }) {
                    Text(levelLabel(level, tx.no).uppercase(), color = style.accent, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                    Text(headline(r, tx.no), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    if (r.subjectText.isNotBlank()) Text(r.subjectText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
            }
            if (r.error != null) {
                Text(errorDetail(r.error, tx.no))
            } else {
                if (r.summary.reasons.isNotEmpty()) {
                    SectionTitle(tx.t("Why", "Hvorfor"))
                    r.summary.reasons.forEach { Bullet(findingText(it, tx.no)) }
                } else if (level == Level.CLEAR) {
                    Text(tx.t("Nothing matched the rules and lists on this device.", "Ingenting traff reglene og listene på denne enheten."))
                }
                SectionTitle(tx.t("What to do", "Hva bør du gjøre"))
                r.summary.advice.forEachIndexed { i, a -> Bullet(adviceText(a, tx.no), "${i + 1}.") }
                if (details.isNotEmpty()) {
                    TextButton(onClick = { expanded = !expanded }, contentPadding = PaddingValues(horizontal = 4.dp)) {
                        Text(if (expanded) tx.t("Hide details", "Skjul detaljer") else tx.t("Show details (${details.size})", "Vis detaljer (${details.size})"))
                    }
                    AnimatedVisibility(expanded) {
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            details.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        }
                    }
                }
            }
        }
    }
}

/** One line of overview: an icon, a title, a plain-language state, and where it leads. The icon colour changes smoothly with the state. */
@Composable
fun StatusRow(@DrawableRes icon: Int, title: String, value: String, tint: Color, onClick: () -> Unit) {
    val animated by animateColorAsState(tint, tween(ms(300)), label = "status")
    Card(onClick = onClick, Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Box(Modifier.size(40.dp).clearAndSetSemantics { }.background(animated.copy(alpha = .16f), CircleShape), contentAlignment = Alignment.Center) { Ico(icon, tint = animated, size = 22.dp) }
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Ico(R.drawable.ic_chevron, Modifier.clearAndSetSemantics { }, tint = MaterialTheme.colorScheme.onSurfaceVariant, size = 20.dp)
        }
    }
}

/** A calm, slow glow behind an icon while protection is running. Not drawn at all when system animations are off. */
@Composable
fun BreathingIcon(@DrawableRes icon: Int, active: Boolean, tint: Color, size: Dp = 56.dp) {
    val reduce = LocalReduceMotion.current
    Box(Modifier.size(size).clearAndSetSemantics { }, contentAlignment = Alignment.Center) {
        if (active && !reduce) {
            val t = rememberInfiniteTransition(label = "breath")
            val a by t.animateFloat(.10f, .32f, infiniteRepeatable(tween(2600, easing = LinearEasing), RepeatMode.Reverse), label = "alpha")
            val s by t.animateFloat(.92f, 1.12f, infiniteRepeatable(tween(2600, easing = LinearEasing), RepeatMode.Reverse), label = "scale")
            Box(Modifier.fillMaxSize().scale(s).background(tint.copy(alpha = a), CircleShape))
        } else if (active) Box(Modifier.fillMaxSize().background(tint.copy(alpha = .2f), CircleShape))
        else Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.outline.copy(alpha = .15f), CircleShape))
        Ico(icon, tint = if (active) tint else MaterialTheme.colorScheme.onSurfaceVariant, size = size * .5f)
    }
}

/** Shown on every screen of a build that trusts the published debug test key: anyone could sign a threat bundle it accepts. */
@Composable
fun TestBuildBanner(tx: Tx) {
    Text(tx.t("TEST BUILD: trusts a public test key. Not for protection.", "TESTVERSJON: stoler på en offentlig testnøkkel. Ikke for beskyttelse."),
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.errorContainer).padding(horizontal = 16.dp, vertical = 6.dp).semantics { liveRegion = LiveRegionMode.Polite },
        color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
}

/** Always-visible notice that an AI agent is waiting. Time-limited approvals must never hide inside a settings page. */
@Composable
fun AgentBanner(count: Int, dark: Boolean, tx: Tx, onReview: () -> Unit) {
    val style = levelStyle(Level.SUSPICIOUS, dark)
    Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Polite }, shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = style.container.compositeOver(MaterialTheme.colorScheme.surfaceContainerLow))) {
        Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            GlyphBadge(style, 32.dp)
            Text(if (count == 1) tx.t("An AI agent is waiting for your decision", "En KI-agent venter på avgjørelsen din") else tx.t("$count AI agent requests are waiting for you", "$count forespørsler fra KI-agenter venter på deg"),
                Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Button(onClick = onReview) { Text(tx.t("Review", "Se på")) }
        }
    }
}

@Composable
fun ConfirmDialog(title: String, text: String, confirm: String, cancel: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm) } }, dismissButton = { TextButton(onClick = onDismiss) { Text(cancel) } })
}
