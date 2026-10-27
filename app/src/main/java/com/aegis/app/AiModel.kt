package com.aegis.app

import android.content.Context
import com.aegis.core.TextClassifier

/** Loads the bundled on-device message model. Pure local computation; failure simply means the feature is unavailable. */
object AiModel {
    data class Loaded(val classifier: TextClassifier?, val loadMillis: Long)

    @Volatile private var loaded: Loaded? = null

    fun get(context: Context): Loaded = loaded ?: synchronized(this) {
        loaded ?: run {
            val start = System.nanoTime()
            val clf = runCatching {
                context.applicationContext.assets.open("message_model.txt").use { TextClassifier.load(com.aegis.core.BoundedRead.atMost(it, TextClassifier.MAX_MODEL_BYTES + 1)) }
            }.getOrNull()
            Loaded(clf, (System.nanoTime() - start) / 1_000_000).also { loaded = it }
        }
    }
}

data class AiUi(val loaded: Boolean = false, val available: Boolean = false, val name: String = "", val loadMillis: Long = 0)

internal fun aiStatus(a: AiUi, enabled: Boolean, no: Boolean): String {
    fun t(en: String, nb: String) = if (no) nb else en
    if (!a.loaded) return t("Checking on-device model…", "Sjekker modell på enheten…")
    val lines = mutableListOf<String>()
    lines += if (a.available) t("Built-in text classifier ${a.name} loaded in ${a.loadMillis} ms. It is ${if (enabled) "ON" else "OFF"} (Message tab).", "Innebygd tekstklassifiserer ${a.name} lastet på ${a.loadMillis} ms. Den er ${if (enabled) "PÅ" else "AV"} (Melding-fanen).")
    else t("The built-in text classifier could not be loaded. Rule-based checks still work.", "Den innebygde tekstklassifisereren kunne ikke lastes. Regelbaserte sjekker fungerer fortsatt.")
    lines += t("System AI (Gemini Nano / AICore) and LiteRT are not used by this build. The model is a small experimental text scorer that runs fully on this device, has no network access, and can only raise a message to \"suspicious\".",
        "System-KI (Gemini Nano / AICore) og LiteRT brukes ikke i denne versjonen. Modellen er en liten eksperimentell tekstvurderer som kjører helt på enheten, uten nettverkstilgang, og kan bare løfte en melding til «mistenkelig».")
    return lines.joinToString("\n")
}
