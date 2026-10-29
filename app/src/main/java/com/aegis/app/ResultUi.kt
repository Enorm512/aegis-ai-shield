package com.aegis.app

import com.aegis.core.Finding
import com.aegis.core.ImageCheck
import com.aegis.core.ResultSummary
import com.aegis.core.ResultSummary.Level
import com.aegis.core.ResultSummary.Subject

/** Language-neutral facts about an APK, shown in the result's detail section. */
data class ApkFacts(val packageName: String, val versionName: String, val sha256: String, val certificates: List<String>, val permissions: List<String>)

/**
 * A finished check. Holds codes and raw facts only, so switching language re-renders it without re-running anything.
 * [error] is non-null when the check itself could not run ("input", "apk").
 */
data class ResultUi(val summary: ResultSummary, val subjectText: String, val apk: ApkFacts? = null, val error: String? = null, val image: ImageFacts? = null)

/** What was read from a picture, shown so the person can spot misread text. [text] is trimmed for display. */
data class ImageFacts(val text: String, val ocrRan: Boolean, val qrKinds: List<ImageCheck.QrKind>)

fun errorResult(subject: Subject, kind: String): ResultUi = ResultUi(
    ResultSummary.of(com.aegis.core.Analysis(com.aegis.core.Analysis.Verdict.INSUFFICIENT_EVIDENCE, emptyList(), ""), subject), "", null, kind)

internal fun levelLabel(level: Level, no: Boolean): String = if (no) when (level) {
    Level.CONFIRMED -> "Kjent trussel"; Level.STRONG -> "Sterke faresignaler"; Level.SUSPICIOUS -> "Mistenkelig"; Level.UNCLEAR -> "Uklart"; Level.CLEAR -> "Ingen kjente faresignaler"
} else when (level) {
    Level.CONFIRMED -> "Known threat"; Level.STRONG -> "Strong warning signs"; Level.SUSPICIOUS -> "Suspicious"; Level.UNCLEAR -> "Unclear"; Level.CLEAR -> "No known warning signs"
}

internal fun headline(r: ResultUi, no: Boolean): String {
    if (r.error != null) return if (no) "Kunne ikke gjennomføre sjekken" else "The check could not run"
    val l = r.summary.level
    return when (r.summary.subject) {
        Subject.LINK -> if (no) when (l) { Level.CONFIRMED -> "Denne lenken er en kjent trussel"; Level.STRONG -> "Sterke tegn på svindel"; Level.SUSPICIOUS -> "Lenken ser mistenkelig ut"; Level.UNCLEAR -> "Kunne ikke vurdere lenken"; Level.CLEAR -> "Ingen kjente faresignaler" }
            else when (l) { Level.CONFIRMED -> "This link is a known threat"; Level.STRONG -> "Strong signs of a scam"; Level.SUSPICIOUS -> "This link looks suspicious"; Level.UNCLEAR -> "Couldn't assess this link"; Level.CLEAR -> "No known warning signs" }
        Subject.MESSAGE -> if (no) when (l) { Level.CONFIRMED -> "Meldingen peker på en kjent trussel"; Level.STRONG -> "Sterke tegn på svindel"; Level.SUSPICIOUS -> "Noen tegn på svindel"; Level.UNCLEAR -> "For lite å vurdere ut fra"; Level.CLEAR -> "Ingen kjente faresignaler" }
            else when (l) { Level.CONFIRMED -> "This message points to a known threat"; Level.STRONG -> "Strong signs of a scam"; Level.SUSPICIOUS -> "Some signs of a scam"; Level.UNCLEAR -> "Not enough to judge"; Level.CLEAR -> "No known warning signs" }
        Subject.IMAGE -> if (no) when (l) { Level.CONFIRMED -> "Bildet peker på en kjent trussel"; Level.STRONG -> "Sterke tegn på svindel i bildet"; Level.SUSPICIOUS -> "Noe i bildet krever forsiktighet"; Level.UNCLEAR -> "Kunne ikke lese nok fra bildet"; Level.CLEAR -> "Ingen kjente faresignaler" }
            else when (l) { Level.CONFIRMED -> "This picture points to a known threat"; Level.STRONG -> "Strong signs of a scam in this picture"; Level.SUSPICIOUS -> "Something in this picture needs care"; Level.UNCLEAR -> "Couldn't read enough from this picture"; Level.CLEAR -> "No known warning signs" }
        Subject.APK -> if (no) when (l) { Level.CONFIRMED -> "Kjent skadelig fil"; Level.STRONG -> "Sterke faresignaler i filen"; Level.SUSPICIOUS -> "Risikabel kombinasjon av funksjoner"; Level.UNCLEAR -> "Kunne ikke gjennomgå filen"; Level.CLEAR -> "Ingen kjente faresignaler" }
            else when (l) { Level.CONFIRMED -> "Known malicious file"; Level.STRONG -> "Strong warning signs in the file"; Level.SUSPICIOUS -> "Risky combination of capabilities"; Level.UNCLEAR -> "Couldn't review this file"; Level.CLEAR -> "No known warning signs" }
    }
}

internal fun errorDetail(kind: String, no: Boolean): String = when (kind) {
    "image_source" -> if (no) "Aegis leser bare bilder som deles fra en annen app eller velges i bildevelgeren." else "Aegis only reads pictures shared from another app or chosen in the photo picker."
    "image_too_big" -> if (no) "Bildet er større enn 40 MB." else "The picture is larger than 40 MB."
    "image_not_image", "image_unreadable" -> if (no) "Bildet kunne ikke åpnes. Prøv et vanlig skjermbilde (PNG eller JPEG)." else "The picture could not be opened. Try an ordinary screenshot (PNG or JPEG)."
    "apk" -> if (no) "Filen kunne ikke leses, overskred grensen på 100 MiB eller bestod ikke arkiv-/parserkontrollene. Dette avgjør ikke om den er skadelig." else "The file could not be read, exceeded the 100 MiB limit, or failed archive/parser checks. This does not determine whether it is malicious."
    else -> if (no) "Kontroller teksten og prøv igjen." else "Check the input and try again."
}

internal fun findingText(f: Finding, no: Boolean): String = if (no) norwegianFinding(f.code, f.detail) else f.detail

internal fun adviceText(code: String, no: Boolean): String = if (no) when (code) {
    "DO_NOT_OPEN" -> "Ikke åpne denne lenken."
    "GO_OFFICIAL_ROUTE" -> "Hvis den utgir seg for å være fra banken, et leveringsselskap eller det offentlige: åpne den offisielle appen eller skriv adressen selv."
    "NEVER_SHARE_CODES" -> "Del aldri engangskoder, passord, PIN eller BankID-opplysninger med noen som kontakter deg."
    "PAYMENT_HARD_TO_RECOVER" -> "Ikke betal med gavekort eller krypto. Slike betalinger er svært vanskelige å få tilbake."
    "ALREADY_ACTED" -> "Har du allerede klikket og oppgitt opplysninger eller betalt: kontakt banken din med en gang via nummeret på kortet eller i bankens offisielle app, bytt passordet du brukte, og slå på tofaktor."
    "REPORT_IT" -> "Meld fra til selskapet som blir etterlignet. I Norge kan du også anmelde svindel til politiet på politi.no."
    "DO_NOT_INSTALL" -> "Ikke installer denne filen."
    "INSTALL_FROM_STORE" -> "Installer apper fra en pålitelig butikk som Google Play, og sjekk hvem som har laget appen."
    "ALREADY_INSTALLED" -> "Hvis den allerede er installert: fjern den i Innstillinger → Apper, kjør en Play Protect-skanning og bytt passord du har brukt på telefonen."
    "CHECK_INPUT" -> "Sjekk teksten for skrivefeil og prøv igjen."
    "CHECK_IMAGE" -> "Prøv et skarpere skjermbilde, beskjær til meldingen eller QR-koden, eller lim inn teksten i stedet."
    "DO_NOT_SCAN" -> "Ikke skann denne QR-koden, og ikke installer noe den peker til."
    "KEEP_QR_PRIVATE" -> "Ikke send dette bildet til noen. Hvis du allerede har gjort det, sett opp tofaktor på nytt i kontoen det gjelder."
    "VERIFY_OTHER_WAY" -> "Er du usikker, sjekk med avsenderen via en kanal du allerede stoler på."
    "STAY_CAUTIOUS" -> "Ingenting traff, men denne sjekken kan ikke bevise at noe er trygt."
    else -> code
} else when (code) {
    "DO_NOT_OPEN" -> "Don't open this link."
    "GO_OFFICIAL_ROUTE" -> "If it claims to be from your bank, a delivery service or an authority, open their official app or type the address yourself."
    "NEVER_SHARE_CODES" -> "Never share one-time codes, passwords, PINs or BankID details with anyone who contacts you."
    "PAYMENT_HARD_TO_RECOVER" -> "Don't pay with gift cards or crypto. Those payments are very hard to get back."
    "ALREADY_ACTED" -> "If you already clicked and entered details or paid: contact your bank right away using the number on your card or in its official app, change the password you used, and turn on two-step login."
    "REPORT_IT" -> "Report it to the company being impersonated. In Norway you can also report fraud to the police at politi.no."
    "DO_NOT_INSTALL" -> "Don't install this file."
    "INSTALL_FROM_STORE" -> "Install apps from a trusted store such as Google Play, and check who made the app."
    "ALREADY_INSTALLED" -> "If it is already installed: remove it in Settings → Apps, run a Play Protect scan, and change passwords you have used on this phone."
    "CHECK_INPUT" -> "Check the text for typos and try again."
    "CHECK_IMAGE" -> "Try a sharper screenshot, crop it to the message or QR code, or paste the text instead."
    "DO_NOT_SCAN" -> "Don't scan this QR code, and don't install anything it points to."
    "KEEP_QR_PRIVATE" -> "Don't send this picture to anyone. If you already did, set up two-step login again for that account."
    "VERIFY_OTHER_WAY" -> "If you are unsure, check with the sender through a channel you already trust."
    "STAY_CAUTIOUS" -> "Nothing matched, but this check cannot prove that something is safe."
    else -> code
}

internal fun apkFactLines(f: ApkFacts, no: Boolean): List<String> {
    fun t(en: String, nb: String) = if (no) nb else en
    val perms = f.permissions.take(80)
    return listOf(
        t("Package: ", "Pakke: ") + f.packageName,
        t("Version: ", "Versjon: ") + f.versionName.ifBlank { "—" },
        "SHA-256: ${f.sha256}",
        t("Reported certificate SHA-256: ", "Rapportert sertifikat SHA-256: ") + f.certificates.ifEmpty { listOf(t("Unavailable", "Utilgjengelig")) }.joinToString("\n"),
        t("Requested permissions (not proof of misuse): ", "Forespurte tillatelser (beviser ikke misbruk): ") +
            (perms.ifEmpty { listOf(t("None reported", "Ingen rapportert")) }.joinToString("\n") + if (f.permissions.size > 80) "\n" + t("Additional permissions omitted: ", "Flere tillatelser utelatt: ") + (f.permissions.size - 80) else ""),
        t("Read-only review of the archive and manifest. Nothing was installed or run, and certificates reported by Android's parser do not establish trust.", "Skrivebeskyttet gjennomgang av arkiv og manifest. Ingenting ble installert eller kjørt, og sertifikater rapportert av Androids parser fastslår ikke tillit."),
    )
}

internal fun qrKindName(k: ImageCheck.QrKind, no: Boolean): String = if (no) when (k) {
    ImageCheck.QrKind.WEB_LINK -> "nettlenke"; ImageCheck.QrKind.DEVICE_LINK -> "kobling av ny enhet"; ImageCheck.QrKind.CRYPTO_PAYMENT -> "kryptobetaling"
    ImageCheck.QrKind.PAYMENT_REQUEST -> "betalingsforespørsel"; ImageCheck.QrKind.BANK_TRANSFER -> "bankoverføring"; ImageCheck.QrKind.SIGNIN_SECRET -> "tofaktornøkkel"
    ImageCheck.QrKind.WIFI -> "Wi-Fi"; ImageCheck.QrKind.TEXT_MESSAGE -> "SMS"; ImageCheck.QrKind.CONTACT -> "kontakt"; ImageCheck.QrKind.APP_LINK -> "applenke"; ImageCheck.QrKind.TEXT -> "tekst"
} else when (k) {
    ImageCheck.QrKind.WEB_LINK -> "web link"; ImageCheck.QrKind.DEVICE_LINK -> "new-device sign-in"; ImageCheck.QrKind.CRYPTO_PAYMENT -> "crypto payment"
    ImageCheck.QrKind.PAYMENT_REQUEST -> "payment request"; ImageCheck.QrKind.BANK_TRANSFER -> "bank transfer"; ImageCheck.QrKind.SIGNIN_SECRET -> "two-step login key"
    ImageCheck.QrKind.WIFI -> "Wi-Fi"; ImageCheck.QrKind.TEXT_MESSAGE -> "text message"; ImageCheck.QrKind.CONTACT -> "contact"; ImageCheck.QrKind.APP_LINK -> "app link"; ImageCheck.QrKind.TEXT -> "text"
}

/** Lines for the details section: what was actually read, so misread text is visible. */
internal fun imageFactLines(f: ImageFacts, no: Boolean): List<String> {
    fun t(en: String, nb: String) = if (no) nb else en
    val qr = if (f.qrKinds.isEmpty()) t("QR codes found: none", "QR-koder funnet: ingen")
        else t("QR codes found: ", "QR-koder funnet: ") + f.qrKinds.joinToString(", ") { qrKindName(it, no) }
    val text = when {
        !f.ocrRan -> t("Text: could not be read on this phone.", "Tekst: kunne ikke leses på denne telefonen.")
        f.text.isBlank() -> t("Text read: none", "Tekst lest: ingen")
        else -> t("Text read (check for misreadings):\n", "Tekst lest (se etter feillesninger):\n") + f.text
    }
    return listOf(qr, text, t("The picture was read on this phone and not saved or sent anywhere.", "Bildet ble lest på denne telefonen og ikke lagret eller sendt noe sted."))
}
