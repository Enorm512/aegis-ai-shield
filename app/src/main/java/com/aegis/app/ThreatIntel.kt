package com.aegis.app

import android.content.Context
import com.aegis.core.ReputationProvider
import com.aegis.core.ThreatBundleVerifier
import com.aegis.core.ThreatStore
import java.io.File

/** Local signed threat database. Trusted keys come from assets; none are shipped yet, so nothing can be imported. */
object ThreatIntel {
    class Holder(val store: ThreatStore, val anchorsPresent: Boolean, val provider: ReputationProvider)

    @Volatile private var holder: Holder? = null

    fun holder(context: Context): Holder = holder ?: synchronized(this) {
        holder ?: run {
            val app = context.applicationContext
            val anchors = ThreatBundleVerifier.TrustAnchors()
            runCatching {
                app.assets.open("trusted_threat_keys.txt").bufferedReader().useLines { lines ->
                    lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
                        .forEach { runCatching { anchors.add(android.util.Base64.decode(it, android.util.Base64.DEFAULT)) } }
                }
            }
            val store = ThreatStore(File(app.filesDir, "threatdb"), anchors, java.time.Clock.systemUTC())
            Holder(store, !anchors.isEmpty, ReputationProvider.LocalDatabase { store.current() }).also { holder = it }
        }
    }

    fun get(context: Context): ReputationProvider = holder(context).provider
}

/** Raw facts only; text is composed at render time so the language toggle applies immediately. */
data class IntelUi(
    val loaded: Boolean = false, val anchorsPresent: Boolean = false, val sequence: Long = 0, val indicators: Int = 0,
    val issued: String = "", val expires: String = "", val stale: Boolean = false, val loadWarning: Boolean = false,
    val canRollback: Boolean = false, val busy: Boolean = false, val message: String? = null,
)

internal fun intelStatus(i: IntelUi, no: Boolean): String {
    fun t(en: String, nb: String) = if (no) nb else en
    if (!i.loaded) return t("Checking threat database…", "Sjekker trusseldatabase…")
    val lines = mutableListOf<String>()
    lines += if (i.sequence == 0L) t("No threat database installed. Links and APK hashes cannot be checked against known threats.", "Ingen trusseldatabase er installert. Lenker og APK-hasher kan ikke sjekkes mot kjente trusler.")
    else t("Version ${i.sequence} · ${i.indicators} indicators · issued ${i.issued} · expires ${i.expires}", "Versjon ${i.sequence} · ${i.indicators} indikatorer · utstedt ${i.issued} · utløper ${i.expires}")
    if (i.stale) lines += t("This database has expired. It is still used, but may miss recent threats.", "Denne databasen er utløpt. Den brukes fortsatt, men kan overse nye trusler.")
    if (i.loadWarning) lines += t("The stored database failed verification and was not used.", "Den lagrede databasen besto ikke verifiseringen og ble ikke brukt.")
    if (!i.anchorsPresent) lines += t("This build contains no trusted signing key, so threat databases cannot be imported.", "Denne versjonen har ingen pålitelig signeringsnøkkel, så trusseldatabaser kan ikke importeres.")
    return lines.joinToString("\n")
}

internal fun intelMessage(code: String, no: Boolean): String {
    fun t(en: String, nb: String) = if (no) nb else en
    return when (code) {
        "OK" -> t("Threat database installed.", "Trusseldatabase installert.")
        "ROLLED_BACK" -> t("Previous database restored. Only a newer signed bundle can replace it.", "Forrige database gjenopprettet. Bare en nyere signert pakke kan erstatte den.")
        "BAD_SIGNATURE" -> t("Rejected: the signature is invalid. The file may be altered.", "Avvist: signaturen er ugyldig. Filen kan være endret.")
        "UNTRUSTED_KEY" -> t("Rejected: signed by a key this app does not trust.", "Avvist: signert med en nøkkel appen ikke stoler på.")
        "ROLLBACK" -> t("Rejected: not newer than the installed database.", "Avvist: ikke nyere enn den installerte databasen.")
        "EXPIRED" -> t("Rejected: this bundle has expired.", "Avvist: denne pakken er utløpt.")
        "FUTURE_DATED" -> t("Rejected: the bundle is dated in the future. Check the device clock.", "Avvist: pakken er datert i fremtiden. Sjekk klokken på enheten.")
        "SEQUENCE_JUMP" -> t("Rejected: the version number jumps unreasonably far ahead. This may be a mistake or a stolen key.", "Avvist: versjonsnummeret hopper urimelig langt fremover. Dette kan være en feil eller en stjålet nøkkel.")
        "TOO_LARGE" -> t("Rejected: the file is too large.", "Avvist: filen er for stor.")
        "IO" -> t("The file could not be read or stored. The installed database is unchanged.", "Filen kunne ikke leses eller lagres. Den installerte databasen er uendret.")
        else -> t("Rejected: the file is not a valid threat bundle.", "Avvist: filen er ikke en gyldig trusselpakke.")
    }
}
