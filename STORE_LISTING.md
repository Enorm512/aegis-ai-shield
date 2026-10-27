# Store listing draft (not published; assets not produced)

Wording rule: describe what the app checks, never promise protection. No "100%", "complete", "guaranteed", "AI-powered security that stops...", and no detection-rate numbers (none have been measured on real data).

## English
**Title (≤30):** Aegis AI Shield
**Short description (≤80):** Check links, messages and APK files on your device. No account.
**Full description (≤4000):**
Aegis AI Shield helps you pause and look closer before you tap, reply or install.

What it does
• Link check – flags look-alike domains for a fixed list of well-known brands (including BankID, Vipps, banks and delivery services), odd characters, link shorteners and redirect parameters in the link text. Links are never opened, so what a link redirects to is not checked.
• Message check – looks for common scam wording (pressure, requests for codes or passwords, prize and payment scams) in English and Norwegian. It misses most wording it has not been written for. An optional experimental on-device text classifier can add a warning.
• APK review – looks inside an Android installation file you choose: archive sanity, fingerprint, requested permissions and risky combinations of capabilities. Nothing is installed or run.
• Threat database – import a signed list of known bad domains and files; lookups stay on your device.
• Optional DNS protection – uses Android's VPN feature only for DNS lookups, to refuse names on the threat database or your own block list. Other traffic never enters the tunnel; nothing is decrypted.
• Optional AI-agent guard – lets AI assistants that choose to integrate ask Aegis before sharing data, installing apps or paying. It cannot see or stop assistants that do not ask.

Private by design
No account, no ads, no analytics. Checks run on your device. Allowed DNS lookups go to your network's normal DNS server, as they would without the app.

Please note
Aegis gives evidence, not guarantees. A result of "no known warning signs" does not mean something is safe, and warnings can be wrong. Keep Android and your apps updated, and never share passwords or one-time codes.

## Norsk
**Tittel:** Aegis AI Shield
**Kort beskrivelse (≤80):** Sjekk lenker, meldinger og APK-filer på enheten din. Ingen konto.
**Full beskrivelse:** Aegis AI Shield hjelper deg å stoppe opp og se nærmere før du trykker, svarer eller installerer. Funksjoner: lenkesjekk (etterlignede domener inkl. BankID, Vipps, banker og leveringstjenester, skjulte videresendinger, uvanlige tegn, lenkeforkortere – lenker åpnes aldri), meldingssjekk på norsk og engelsk (press, krav om koder og passord, gevinst- og betalingssvindel; valgfri eksperimentell språkmodell på enheten), APK-gjennomgang (arkivkontroll, fingeravtrykk, tillatelser og risikable funksjonskombinasjoner – ingenting installeres eller kjøres), trusseldatabase (importer en signert liste; oppslag skjer på enheten), valgfri DNS-beskyttelse (bruker Androids VPN-funksjon kun for DNS-oppslag; annen trafikk går ikke gjennom tunnelen; ingenting dekrypteres) og valgfri KI-agentvakt (KI-assistenter som velger det kan spørre Aegis før de deler data, installerer apper eller betaler; Aegis ser ikke assistenter som ikke spør). Ingen konto, ingen reklame, ingen analyse. Merk: Aegis gir indikasjoner, ikke garantier. «Ingen kjente faresignaler» betyr ikke at noe er trygt, og advarsler kan ta feil. Del aldri passord eller engangskoder.

## Graphics and metadata still needed
- 512×512 PNG icon (current launcher icon is a vector drawable only).
- 1024×500 feature graphic.
- 2–8 phone screenshots in EN and NO (cannot be captured without a device/emulator).
- Category (Tools or Productivity), contact email, privacy-policy URL, content-rating questionnaire, target audience, Data safety form, VPN and foreground-service declarations.
- Release notes: "First test release. Experimental DNS protection and AI-agent guard."
