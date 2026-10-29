package com.aegis.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.aegis.core.DnsFilter
import com.aegis.core.DnsProxy
import com.aegis.core.DnsUpstream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Clock
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * DNS-only VPN. The tunnel owns two virtual resolver addresses and routes ONLY those, so no other traffic enters the
 * tunnel: web, app and encrypted traffic are never read, and no certificate is installed. Queries are filtered locally
 * and allowed ones are forwarded to the network's own resolver over a protected socket.
 *
 * NOT YET TESTED ON A DEVICE OR EMULATOR (none was available); the packet and DNS logic it drives is host-tested.
 */
class AegisVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var proxy: DnsProxy? = null
    private var worker: Thread? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val networks = ConcurrentHashMap<Network, List<InetAddress>>()
    @Volatile private var upstream: List<InetSocketAddress> = emptyList()
    @Volatile private var primary: Network? = null
    private val powerCheck = android.os.Handler(android.os.Looper.getMainLooper())
    // While protection runs, re-check which apps can control or read the phone every 30 minutes (no extra wake-ups:
    // the service is already running). Never throws into the service.
    private val powerTask = object : Runnable { override fun run() { runCatching { PowerWatch.backgroundCheck(this@AegisVpnService) }; powerCheck.postDelayed(this, POWER_CHECK_MS) } }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { Protection.setWanted(this, false); stopProtection(); stopSelf(); return START_NOT_STICKY }
        // A null intent is Android restarting the service after it killed the process; only resume what the person turned on.
        if (intent == null && (!Protection.wanted(this) || prepare(this) != null)) { stopSelf(); return START_NOT_STICKY }
        startProtection()
        return if (Protection.wanted(this)) START_STICKY else START_NOT_STICKY
    }

    /** The person withdrew consent or another VPN app took over: protection stays off until the person turns it on again. */
    override fun onRevoke() { Protection.setWanted(this, false); stopProtection(); stopSelf() }
    override fun onDestroy() { stopProtection(); super.onDestroy() }

    @Synchronized private fun startProtection() {
        if (tun != null) { enterForeground(); return } // every startForegroundService call must be answered with startForeground
        Protection.load(this)
        trackUnderlyingNetworks()
        val builder = Builder().setSession("Aegis DNS protection").setMtu(1280).setBlocking(true)
            .addAddress(CLIENT4, 32).addAddress(CLIENT6, 128)
            .addDnsServer(DNS4).addDnsServer(DNS6)
            .addRoute(DNS4, 32).addRoute(DNS6, 128)
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        val fd = try { builder.establish() } catch (_: Exception) { null }
        // Foreground after establish(): the system-exempted type is documented for active VPN apps. If the system
        // refuses it, the tunnel is shut down rather than run without the visible notice or crash. (Stopping means DNS is
        // no longer filtered: for filtering that is fail-OPEN, which is the intended trade-off against blocking all DNS.)
        // startForegroundService() obliges us to call startForeground on EVERY path, including a failed establish().
        val foreground = enterForeground()
        if (fd == null || !foreground) { fd?.close(); stopProtection(); stopSelf(); return }
        tun = fd
        val out = FileOutputStream(fd.fileDescriptor)
        val protector = object : DnsUpstream.Protector {
            // protect() keeps the socket out of the tunnel; binding to the network whose resolvers we use also keeps a
            // Wi-Fi resolver query from leaving over mobile data (or the reverse) when both are connected.
            override fun protect(s: Socket) { if (!this@AegisVpnService.protect(s)) throw IOException("protect failed"); primary?.bindSocket(s) }
            override fun protect(s: DatagramSocket) { if (!this@AegisVpnService.protect(s)) throw IOException("protect failed"); primary?.bindSocket(s) }
        }
        val provider = try { ThreatIntel.get(this) } catch (_: Exception) { null } // no database is never a reason to refuse to start
        val filter = DnsFilter(provider, Protection.lists)
        val app = applicationContext
        filter.setCanaries(Tripwires.load(app)) { token, name -> Tripwires.onTripped(app, token, name) }
        filter.setAiLookupListener { service -> AgentWatch.onAiLookup(app, service) }
        val p = DnsProxy(filter, DnsUpstream.Plain({ upstream }, protector, 3000), { buf, n -> out.write(buf, 0, n) }, ADDR4, ADDR6, Clock.systemUTC())
        proxy = p
        Protection.proxy = p
        Protection.setRunning(true)
        val input = FileInputStream(fd.fileDescriptor)
        powerCheck.removeCallbacks(powerTask); powerCheck.postDelayed(powerTask, 60_000)
        worker = Thread({
            try { p.run(input) } catch (_: IOException) { } finally { endSession(p) }
        }, "aegis-vpn").also { it.start() }
    }

    /** Ends the session only if it is still the current one, so a late worker cannot tear down a newer session. */
    @Synchronized private fun endSession(p: DnsProxy) { if (proxy === p) { stopProtection(); stopSelf() } }

    @Synchronized private fun stopProtection() {
        powerCheck.removeCallbacks(powerTask)
        callback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        callback = null
        networks.clear()
        proxy?.close(); proxy = null
        Protection.proxy = null
        runCatching { tun?.close() }
        tun = null
        Protection.setRunning(false)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    /** Learn the real networks' resolvers (excluding VPNs), preferring Wi-Fi/Ethernet over mobile data. */
    private fun trackUnderlyingNetworks() {
        val cm = getSystemService(ConnectivityManager::class.java)
        fun recompute() {
            val preferred = networks.entries.sortedBy { e ->
                val caps = cm.getNetworkCapabilities(e.key)
                if (caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) 0 else 1
            }
            // Only the preferred network's resolvers: another network's resolver is not reachable through the bound socket.
            primary = preferred.firstOrNull { it.value.isNotEmpty() }?.key
            upstream = (preferred.firstOrNull { it.value.isNotEmpty() }?.value ?: emptyList()).distinct().map { InetSocketAddress(it, 53) }
        }
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, lp: android.net.LinkProperties) {
                networks[network] = lp.dnsServers.filter { it.hostAddress != DNS4 && it.hostAddress != DNS6 }
                recompute()
            }
            override fun onLost(network: Network) { networks.remove(network); recompute() }
        }
        val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
        cm.registerNetworkCallback(request, cb)
        callback = cb
    }

    private fun enterForeground(): Boolean = try { postNotification(); true } catch (_: Exception) { false }

    private fun postNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        val no = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" }
        nm.createNotificationChannel(NotificationChannel(CHANNEL, if (no) "Aegis-beskyttelse" else "Aegis protection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, AegisVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_stat_aegis)
            .setContentTitle(if (no) "DNS-beskyttelse er på" else "DNS protection is on")
            .setContentText(if (no) "Kun DNS-oppslag sjekkes. Annen trafikk berøres ikke." else "Only DNS lookups are checked. Other traffic is untouched.")
            .setOngoing(true).setContentIntent(open)
            .addAction(Notification.Action.Builder(null, if (no) "Stopp" else "Stop", stop).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIFICATION_ID, n)
    }

    companion object {
        private const val POWER_CHECK_MS = 30 * 60_000L
        const val ACTION_STOP = "com.aegis.app.STOP_PROTECTION"
        private const val CHANNEL = "protection"
        private const val NOTIFICATION_ID = 41
        private const val DNS4 = "10.111.222.2"
        private const val DNS6 = "fd00:ae91:5::2"
        private const val CLIENT4 = "10.111.222.1"
        private const val CLIENT6 = "fd00:ae91:5::1"
        private val ADDR4 = byteArrayOf(10, 111, 0xDE.toByte(), 2)
        private val ADDR6 = byteArrayOf(0xfd.toByte(), 0x00, 0xae.toByte(), 0x91.toByte(), 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)

        /** The person turned protection on (consent already given). */
        fun start(context: Context) { Protection.setWanted(context, true); resume(context) }
        /** Starts the tunnel without changing what the person chose; used after a restart. */
        fun resume(context: Context) { context.startForegroundService(Intent(context, AegisVpnService::class.java)) }
        fun stop(context: Context) { context.startService(Intent(context, AegisVpnService::class.java).setAction(ACTION_STOP)) }
    }
}
