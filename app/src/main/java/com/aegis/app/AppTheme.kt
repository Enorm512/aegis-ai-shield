package com.aegis.app

import androidx.annotation.DrawableRes
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import com.aegis.core.ResultSummary.Level

val Mint = Color(0xFF6CE6B5)
val Night = Color(0xFF0A1118)
val Panel = Color(0xFF14202B)

/** Tiny helper so every screen picks English or Norwegian the same way. */
class Tx(val no: Boolean) { fun t(en: String, nb: String) = if (no) nb else en }

fun appColors(dark: Boolean): ColorScheme = if (dark) darkColorScheme(
    primary = Mint, onPrimary = Night, background = Night, onBackground = Color(0xFFE6EEF5), surface = Panel, onSurface = Color(0xFFE6EEF5),
    secondary = Color(0xFFA0B8CC), onSurfaceVariant = Color(0xFFB4C4D2), outline = Color(0xFF5A6E80), outlineVariant = Color(0xFF2A3947),
    surfaceContainerLowest = Night, surfaceContainerLow = Color(0xFF101A24), surfaceContainer = Panel, surfaceContainerHigh = Color(0xFF1A2835), surfaceContainerHighest = Color(0xFF1F2F3E),
    error = Color(0xFFFF8F8F),
) else lightColorScheme(
    primary = Color(0xFF006C4D), onPrimary = Color.White, background = Color(0xFFF3F7F5), onBackground = Color(0xFF14202B), surface = Color.White, onSurface = Color(0xFF14202B),
    secondary = Color(0xFF44596B), onSurfaceVariant = Color(0xFF44596B), outline = Color(0xFF74808B), outlineVariant = Color(0xFFD3DCE3),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF8FAF9), surfaceContainer = Color.White, surfaceContainerHigh = Color(0xFFF1F5F3), surfaceContainerHighest = Color(0xFFEAF0EE),
    error = Color(0xFFB3261E),
)

/** Colour, tinted surface and glyph for each result level. The wording is always shown as well; colour is never the only cue. */
data class LevelStyle(val accent: Color, val container: Color, @DrawableRes val icon: Int)

fun levelStyle(level: Level, dark: Boolean): LevelStyle {
    val accent = if (dark) when (level) {
        Level.CONFIRMED -> Color(0xFFFF7B7B); Level.STRONG -> Color(0xFFFF9A62); Level.SUSPICIOUS -> Color(0xFFFFC857); Level.UNCLEAR -> Color(0xFFA0B8CC); Level.CLEAR -> Color(0xFF8CC4F0)
    } else when (level) {
        Level.CONFIRMED -> Color(0xFFB3261E); Level.STRONG -> Color(0xFFB4470C); Level.SUSPICIOUS -> Color(0xFF8A5A00); Level.UNCLEAR -> Color(0xFF44596B); Level.CLEAR -> Color(0xFF1F5F8B)
    }
    // "No known warning signs" is deliberately blue-grey with an "i", never a green tick: it is not a statement of safety.
    val icon = when (level) { Level.CONFIRMED -> R.drawable.ic_cross; Level.STRONG -> R.drawable.ic_warn; Level.SUSPICIOUS -> R.drawable.ic_alert; Level.UNCLEAR -> R.drawable.ic_help; Level.CLEAR -> R.drawable.ic_info }
    return LevelStyle(accent, accent.copy(alpha = if (dark) .14f else .10f), icon)
}
