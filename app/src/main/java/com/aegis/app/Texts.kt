package com.aegis.app

/** Norwegian wording for stable finding codes. English wording comes from the core engine's own detail text. */
internal fun norwegianFinding(code: String, detail: String): String = when (code) {
    "HOST" -> detail.replace("Destination host: ", "Målvert: ")
    "QR_DEVICE_LINK" -> "En QR-kode i bildet logger inn en ny enhet på en meldings- eller chatkonto (for eksempel WhatsApp, Telegram, Signal eller Discord). Den som laget koden får tilgang til kontoen og meldingene når du skanner den. Skann slike koder bare når de vises på din egen datamaskin."
    "QR_SIGNIN_SECRET" -> "En QR-kode i bildet inneholder den hemmelige nøkkelen til en kodegenerator for tofaktor. Alle som har bildet kan lage innloggingskodene dine. Send det aldri til noen, og ikke legg til en kode fra noen som har kontaktet deg."
    "QR_CRYPTO_PAYMENT" -> "En QR-kode i bildet er en adresse for kryptobetaling. Kryptobetalinger kan ikke reverseres, og krav om betaling i krypto er vanlig i svindel."
    "QR_PAYMENT_REQUEST" -> "En QR-kode i bildet er en betalingsforespørsel. Skanner du den, sender du penger; du mottar aldri penger på denne måten. Detaljer: $detail"
    "QR_BANK_TRANSFER" -> "En QR-kode i bildet fyller ut en bankoverføring. Sjekk mottakeren med selskapet via en kanal du allerede stoler på før du betaler. Detaljer: $detail"
    "QR_WIFI" -> "En QR-kode i bildet kobler til et Wi-Fi-nettverk. Et ukjent nettverk kan se trafikk som ikke er kryptert. Detaljer: $detail"
    "QR_TEXT_MESSAGE" -> "En QR-kode i bildet lager en SMS. SMS til korte numre kan koste penger. Detaljer: $detail"
    "QR_CONTACT" -> "En QR-kode i bildet inneholder kontaktopplysninger. Detaljer: $detail"
    "QR_APP_LINK" -> "En QR-kode i bildet åpner en annen app. Aegis kan ikke se hvor den fører. Detaljer: $detail"
    "QR_LINK" -> detail.replace("A QR code in the picture opens ", "En QR-kode i bildet åpner ").replace("a web address that could not be read", "en nettadresse som ikke kunne leses")
    "QR_APP_DOWNLOAD" -> "QR-koden laster ned en appfil utenfor en appbutikk. Svindelsamtaler og -meldinger ber ofte folk installere apper på denne måten."
    "IMAGE_QR_LIMIT" -> "Bare de første QR-kodene ble sjekket. Detaljer: $detail"
    "IMAGE_OCR_UNAVAILABLE" -> "Tekst kunne ikke leses fra bildet på denne telefonen, så bare QR-koder ble sjekket."
    "IMAGE_TEXT_READ" -> detail.replace("Text read from the picture: about ", "Tekst lest fra bildet: omtrent ").replace(" words.", " ord.")
    "IMAGE_NOTHING_READ" -> if (detail.startsWith("Too little")) "For lite tekst ble lest fra bildet til å vurdere det." else "Ingen tekst eller QR-kode kunne leses fra bildet."
    "IMAGE_LIMITS" -> "Bildet ble lest på denne telefonen. Tekstgjenkjenning kan lese feil eller hoppe over ord, noe som kan skjule eller skape faresignaler. Bilder, logoer, farger og hvem som sendte det vurderes ikke."
    "ML_SCAM_LANGUAGE" -> "Den eksperimentelle tekstklassifisereren på enheten gir ordlyden en høy score mot kjente svindelmeldinger, selv om ingen regel traff. Det er et svakt signal som kan ta feil; bekreft via en offisiell kanal."
    "ML_AGREES" -> "Den eksperimentelle tekstklassifisereren gir også ordlyden en høy score. Den er bygget på lignende eksempler som reglene, så dette er ikke uavhengig bekreftelse."
    "VERIFY_REQUEST" -> "Meldingen ber deg bekrefte eller oppdatere konto-, identitets- eller kortopplysninger under press."
    "APK_DROPPER_PATTERN" -> "Appen kan be om å installere andre pakker, kan bruke nettverket, og starter enten ved oppstart eller mangler startikon. Slik virker skadevare som laster ned mer skadevare; appbutikker og filbehandlere ber også om installasjonsrett, så sjekk hvor filen kom fra."
    "LOOKALIKE_BRAND" -> "Domenenavnet ligner et kjent merke (tegn eller stavemåte som ligner, eller ett tegn forskjell), men er ikke et av merkets offisielle domener. Noen etterlignere er urelaterte, lovlige virksomheter; bekreft uavhengig. Detaljer: $detail"
    "PARCEL_FEE" -> "Meldingen ber deg betale et gebyr for en pakke eller levering. Pakke- og tollsvindel bruker ofte små gebyrer for å hente ut kortopplysninger. Sjekk sporingen hos avsenderen eller transportøren, ikke via lenken."
    "FAMILY_IMPERSONATION" -> "Meldingen utgir seg for å være et familiemedlem med ny telefon eller nytt nummer og ber om penger. Ring personen på det kjente nummeret før du sender noe."
    "GIFTCARD_REQUEST" -> "Meldingen ber deg kjøpe gavekort eller lignende verdikort. Disse er vanskelige å spore og få tilbake, og er en vanlig betalingsmåte i svindel."
    "INVESTMENT_LURE" -> "Meldingen lover høy eller garantert avkastning eller kryptosignaler og ber deg bli med. Slike løfter er et typisk kjennetegn på investeringssvindel."
    "SUSPICIOUS_TLD" -> "Adressen ender på et billig domeneendelse som brukes langt oftere av svindelsider enn av etablerte tjenester. Mange lovlige sider bruker det også; dette gir bare litt vekt."
    "REDIRECT_PARAMETER" -> "Lenken har en parameter som peker til en annen nettadresse og kan sende deg videre. Vanlig i lovlige innloggingsflyter; sjekk hvor den fører."
    "APK_PACKAGE" -> "Pakke- og versjonsopplysninger fra manifestet. Detaljer: $detail"
    "APK_CAPABILITIES" -> "Sensitive funksjoner deklarert i manifestet. Lovlige apper bruker dem også; dette er ikke bevis på misbruk. Detaljer: $detail"
    "APK_OLD_TARGET" -> "Appen retter seg mot et gammelt API-nivå som er eldre enn kjøretidstillatelser i Android 6."
    "APK_NO_LAUNCHER" -> "Appen deklarerer sensitive funksjoner, men har ingen startikon-aktivitet."
    "APK_BANKER_PATTERN" -> "Tilgjengelighetstjeneste kombinert med overlegg, SMS eller pakkeinstallasjon er et mønster sett i banktrojanere. Mange lovlige tilgjengelighetsverktøy finnes; bekreft hvor filen kom fra."
    "APK_SMS_EXFIL_PATTERN" -> "SMS-tilgang pluss nettverk og skjermtilgang kan fange og videresende engangskoder."
    "APK_DEBUGGABLE" -> "Appen er merket som feilsøkbar, noe som er uvanlig for en utgitt app."
    "APK_CLEARTEXT" -> "Appen tillater ukryptert HTTP-trafikk."
    "APK_EXPORTED_COMPONENTS" -> "Noen komponenter kan nås av andre apper uten tillatelse. Vanlig i vanlige apper; et herdingspunkt, ikke et trusselsignal. Detaljer: $detail"
    "APK_MANIFEST_LIMITS" -> "Kun manifestet ble lest. Kode, native biblioteker og kjøretidsatferd ble ikke analysert; et rent resultat gjør ikke appen trygg."
    "APK_MANIFEST_UNREADABLE" -> "Manifestet kunne ikke leses eller er ugyldig, så funksjonene kunne ikke vurderes."
    "INVALID_HASH" -> "Forventet en SHA-256-sjekksum på 64 heksadesimale tegn."
    "NO_HASH_INTELLIGENCE" -> "Et SHA-256-fingeravtrykk alene kan ikke avgjøre om en fil er skadelig."
    "THREATDB_LISTED" -> "Oppføring i den signerte trusseldatabasen. Detaljer: $detail"
    "THREATDB_NOT_LISTED" -> "Ikke oppført i den lokale trusseldatabasen. Dette betyr ikke at den er trygg; nye trusler dukker opp før de blir oppført."
    "THREATDB_UNAVAILABLE" -> "Ingen trusseldatabase er installert, så dette kunne ikke sjekkes mot kjente trusler."
    "SCHEME_ASSUMED" -> "HTTPS ble antatt fordi ingen protokoll var oppgitt."
    "UNENCRYPTED_HTTP" -> "HTTP krypterer ikke trafikken. Dette alene fastslår ikke skadelig hensikt."
    "UNRESOLVED_SHORT_LINK", "SHORTENER" -> "Dette er en kjent lenkeforkorter. Sluttmålet er ukjent fordi ingen lenke ble åpnet."
    "IP_LITERAL" -> "Målet er en IP-adresse. Ingen DNS-oppslag ble utført."
    "MIXED_SCRIPT_HOST" -> "Vertsnavnet blander latinske og kyrilliske eller greske tegn, noe som kan skape visuell forvirring."
    "URGENCY" -> "Meldingen bruker tidspress. Legitime meldinger kan også haste."
    "THREAT_LANGUAGE" -> "Meldingen nevner kontobegrensninger eller juridiske konsekvenser."
    "SECRET_REQUEST" -> "Meldingen ser ut til å be om passord, koder, PIN eller BankID-informasjon. Ikke del autentiseringshemmeligheter."
    "UNUSUAL_PAYMENT" -> "En betalingsforespørsel nevner gavekort eller kryptovaluta, som kan være vanskelig å få tilbake."
    "PRIZE_PAYMENT" -> "Meldingen kombinerer en gevinstpåstand med betalingsspråk."
    "SUSPICIOUS_LINK" -> "En innebygd lenke har faresignaler. Analyser lenken separat for detaljer."
    "INCOMPLETE_LINK_ANALYSIS" -> "En innebygd lenke kunne ikke vurderes fullstendig. Sluttmålet kan være ukjent, eller URL-en kan være ugyldig."
    "UNPARSED_LINK" -> "En innebygd lenke kunne ikke tolkes fullstendig."
    "LINK_SCAN_LIMIT" -> "Kun de første 12 innebygde HTTP(S)-lenkene ble analysert."
    "HEURISTIC_LIMITS" -> "Frakoblede regler for engelsk og norsk kan overse svindel og feiltolke sitater eller sammenheng. Ingen faresignaler beviser ikke trygghet. Forfatterskap eller KI-opphav vurderes ikke."
    "INVALID_URL" -> "URL-en kunne ikke analyseres. Kontroller formatet og grensen på 8192 tegn. Detaljer: $detail"
    "INPUT_LIMIT" -> "Teksten må være innenfor inndatagrensen og kan ikke være tom."
    "USERINFO" -> "URL-en inneholder brukerinformasjon før @. Dette kan skjule målet. Detaljer: $detail"
    "INTERNATIONALIZED_HOST" -> "Vertsnavnet bruker internasjonale tegn. Dette alene er ikke skadelig. Detaljer: $detail"
    "BRAND_OUTSIDE_KNOWN_DOMAIN" -> "Vertsnavnet nevner et merkenavn utenfor den begrensede innebygde domenelisten. Bekreft uavhengig; det kan være legitimt. Detaljer: $detail"
    else -> detail
}

internal fun agentReason(code: String, no: Boolean): String {
    fun t(en: String, nb: String) = if (no) nb else en
    return when (code) {
        "FINANCIAL_ACTION" -> t("Involves money.", "Gjelder penger.")
        "INSTALL_APP" -> t("Would install an app.", "Vil installere en app.")
        "EXECUTE_COMMAND" -> t("Would run a command.", "Vil kjøre en kommando.")
        "CREDENTIAL_USE" -> t("Would use a saved credential.", "Vil bruke en lagret legitimasjon.")
        "MODIFY_SETTINGS" -> t("Would change settings.", "Vil endre innstillinger.")
        "SECRET_IN_OUTBOUND_DATA" -> t("The data being sent contains what looks like a secret key or password.", "Dataene som sendes ser ut til å inneholde en hemmelig nøkkel eller et passord.")
        "PERSONAL_DATA_TO_UNTRUSTED_DESTINATION" -> t("Personal or payment data going to a destination you have not trusted.", "Personlige data eller betalingsdata til et mål du ikke har stolt på.")
        "FILE_TO_UNTRUSTED_DESTINATION" -> t("A file would be shared with a destination you have not trusted.", "En fil ville bli delt med et mål du ikke har stolt på.")
        "UNTRUSTED_DESTINATION_WITHOUT_USER_INSTRUCTION" -> t("Sending to an untrusted destination, and this did not come directly from you.", "Sender til et ikke-klarert mål, og dette kom ikke direkte fra deg.")
        "SENSITIVE_READ_WITHOUT_USER_INSTRUCTION" -> t("Reading sensitive data, not directly requested by you.", "Leser sensitive data uten at du ba direkte om det.")
        "UNTRUSTED_DESTINATION" -> t("Sending to a destination you have not marked as trusted.", "Sender til et mål du ikke har merket som klarert.")
        "SENSITIVE_READ" -> t("Reading sensitive data. Reading is often the first step of sending it somewhere.", "Leser sensitive data. Lesing er ofte første steg før de sendes videre.")
        "INJECTION_INDICATORS" -> t("The request or content contains wording typical of attempts to hijack an AI assistant.", "Forespørselen eller innholdet har ordlyd som er typisk for forsøk på å kapre en KI-assistent.")
        "KILL_SWITCH_ON" -> t("Emergency stop was on.", "Nødstopp var på.")
        "UNKNOWN_AGENT" -> t("The app was not connected.", "Appen var ikke koblet til.")
        else -> code
    }
}
