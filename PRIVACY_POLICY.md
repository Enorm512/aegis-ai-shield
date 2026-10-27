# Aegis AI Shield — Privacy Policy (DRAFT)

**Draft for legal review. Not approved. Fill every [BRACKET] and have a qualified person (GDPR / Norwegian Personal Data Act) review it before publishing or entering it in Google Play.**

Effective date: [DATE] · Controller: [LEGAL NAME, ADDRESS, ORG. NUMBER] · Contact: [PRIVACY EMAIL]

## Summary
Aegis analyses links, messages and APK files **on your device**. The developer runs no servers for the app, has no accounts, and receives no data from it: no analytics, no advertising, no crash reporting, no tracking. [Confirm this stays true for the shipped build.]

## What the app processes, and where
| Feature | Data | Where it goes |
|---|---|---|
| Link and message checks | Text or URLs you paste or share to the app | Analysed in memory on the device; not stored; not sent anywhere. Links are never opened. |
| APK review | The file you choose | Copied to the app's temporary cache, read, deleted afterwards; not uploaded. |
| Threat database | A signed file you import | Stored on the device; lookups are local. |
| Experimental language model | Message text | Scored by a small model bundled in the app, on the device. |
| DNS protection (optional, you start it) | The domain names your apps look up | Checked locally. Names that are not blocked are passed on to **your network's own DNS server**, to the extent your phone would otherwise send them (if you use encrypted Private DNS in Automatic mode, the passed-on lookups are sent as ordinary, unencrypted DNS while Aegis protection is running). Aegis does not store them (it keeps only a short in-memory list of blocked or warned names, cleared when the app process ends). No other traffic enters the tunnel. |
| AI agent protection (optional) | Requests from AI apps you paired: action type, destination host, a summary and payload they supply | Evaluated on the device. The payload is scanned but not stored in the log. A bounded audit log (500 entries) keeps agent id, action type, destination host, decision and your answers, encrypted in the app's private storage, never payloads. While a request waits (at most 5 minutes) its summary and a clipped preview of the payload are also stored encrypted so the request survives the app being stopped; they are deleted when it is answered or expires. You can export the log yourself; Aegis never sends it anywhere. |
| App powers check ("who can control or read this phone") | Names of installed apps that hold Accessibility, notification access, device admin, default SMS, keyboard or VPN, and whether they came with the phone | Read on the device from Android's own settings when you open Aegis and every 30 minutes while DNS protection runs. The list you last reviewed is stored in the app's private storage so changes can be shown. Never sent anywhere. Aegis does not change these settings. |
| Tripwires (optional, you plant them) | Decoy contact, note or file you choose to save in your own apps, each with a random link under the reserved `.invalid` domain; a list of when a decoy's link was looked up | The decoy is handed to your Contacts app, the share menu or the file picker; Aegis itself writes nothing into other apps. The random tokens and the trip times are stored in the app's private storage. Lookups of decoy links are answered on the device and never forwarded. |
| Your lists and pairings | Domains you allow or block; package names and signing-certificate fingerprints of paired apps | Stored in the app's private storage; excluded from Android backups and device transfer. |

## Permissions
Internet and network state (only to forward allowed DNS lookups and discover your network's DNS server), foreground service (to show that DNS protection is running), notifications (the running notice). No access to contacts, SMS, location, microphone, camera, call logs, accounts, or the installed-app list. Files are chosen through Android's file picker.

## Sharing
None by the developer. If you use DNS protection, your device's DNS lookups go to the DNS server provided by your network or operator, as they do without the app; that party's own privacy policy applies. [Decide with counsel how to declare this in Play's Data safety form.]

## Retention and deletion
Nothing is sent to the developer, so there is nothing to delete on the developer's side. Clear the app's storage or uninstall to remove local data.

## Security
Threat databases must carry a valid signature and be newer than any previous one. Untrusted inputs (files, manifests, network packets, agent requests) are parsed with strict limits. The app has **not** been through an independent security audit. See SECURITY_AUDIT.md.

## Children
The app is not directed to children. [Confirm target audience.]

## Your rights (EEA/Norway)
Access, rectification, erasure, restriction, portability, objection, and complaint to Datatilsynet. Because the developer receives no personal data from the app, most requests cannot involve developer-held data. [Counsel to confirm wording and legal basis if any data is ever processed by the developer.]

## Changes
[Describe how changes are announced.]
