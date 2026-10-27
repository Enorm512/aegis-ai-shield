package com.aegis.core;

import java.util.*;

/**
 * Names a threat feed may never take away from the person. A mistaken or compromised (but correctly signed) feed
 * must not be able to knock out most of the internet. Registrable domains are protected exactly (and as "www."),
 * so a feed can still list abusive sub-domains of big platforms; connectivity-critical names are protected with
 * all their sub-domains. The person's own block list is never limited by this.
 */
public final class ProtectedDomains {
    private static final Set<String> REGISTRABLE = new HashSet<>(Arrays.asList(
        "google.com", "google.no", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com", "ytimg.com", "android.com", "chrome.com",
        "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "windows.com", "windowsupdate.com", "bing.com", "skype.com",
        "apple.com", "icloud.com", "mzstatic.com", "amazon.com", "cloudflare.com", "cloudflare-dns.com", "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "messenger.com", "meta.com",
        "netflix.com", "nflxvideo.net", "spotify.com", "scdn.co", "github.com", "githubusercontent.com", "gitlab.com", "twitter.com", "x.com", "linkedin.com", "reddit.com",
        "wikipedia.org", "wikimedia.org", "mozilla.org", "mozilla.com", "firefox.com", "zoom.us", "slack.com", "dropbox.com", "adobe.com",
        "paypal.com", "paypalobjects.com", "stripe.com", "visa.com", "mastercard.com",
        "vipps.no", "bankid.no", "bankid.com", "dnb.no", "nordea.com", "nordea.no", "sparebank1.no", "skatteetaten.no", "altinn.no", "nav.no", "helsenorge.no", "regjeringen.no",
        "politiet.no", "posten.no", "bring.no", "telenor.no", "telia.no", "nrk.no", "vg.no", "finn.no", "yr.no", "norge.no", "digdir.no", "idporten.no"));
    private static final Set<String> CONNECTIVITY = new HashSet<>(Arrays.asList(
        "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "time.android.com", "captive.apple.com", "dns.google", "one.one.one.one", "dns.quad9.net"));
    private ProtectedDomains() {}

    /** True if a feed entry for exactly this domain must be refused (verifier). */
    public static boolean isProtectedEntry(String domain) {
        String d = domain.toLowerCase(Locale.ROOT);
        return REGISTRABLE.contains(d) || (d.startsWith("www.") && REGISTRABLE.contains(d.substring(4))) || CONNECTIVITY.contains(d);
    }

    /** True if a DNS name must never be blocked because of a feed listing (filter). */
    public static boolean shielded(String name) {
        if (isProtectedEntry(name)) return true;
        for (String c : CONNECTIVITY) if (name.endsWith("." + c)) return true;
        return false;
    }
}
