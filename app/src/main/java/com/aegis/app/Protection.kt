package com.aegis.app

import android.content.Context
import com.aegis.core.DnsFilter
import com.aegis.core.DnsProxy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ProtectionStats(val queries: Long = 0, val blocked: Long = 0, val warned: Long = 0, val failed: Long = 0, val dropped: Long = 0,
                           val recent: List<DnsProxy.Event> = emptyList())

/** Process-wide state shared by the VPN service and the UI. Counters live in memory only. */
object Protection {
    private val mutableRunning = MutableStateFlow(false)
    val running = mutableRunning.asStateFlow()
    val lists = DnsFilter.DomainLists()
    @Volatile var proxy: DnsProxy? = null
    @Volatile private var loaded = false
    private const val PREFS = "protection"

    fun setRunning(value: Boolean) { mutableRunning.value = value }

    @Synchronized fun load(context: Context) {
        if (loaded) return
        val p = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        p.getStringSet("allow", emptySet())?.forEach { lists.allow(it) }
        p.getStringSet("block", emptySet())?.forEach { lists.block(it) }
        loaded = true
    }

    private fun save(context: Context) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putStringSet("allow", lists.allowed()).putStringSet("block", lists.blocked()).apply()
    }

    fun allow(context: Context, domain: String): Boolean = lists.allow(domain).also { if (it) save(context) }
    fun block(context: Context, domain: String): Boolean = lists.block(domain).also { if (it) save(context) }
    fun removeAllow(context: Context, domain: String) { lists.unallow(domain); save(context) }
    fun removeBlock(context: Context, domain: String) { lists.unblock(domain); save(context) }

    fun snapshot(): ProtectionStats {
        val p = proxy ?: return ProtectionStats()
        return ProtectionStats(p.queries.get(), p.blocked.get(), p.warned.get(), p.failed.get(), p.dropped.get(), p.recentEvents().takeLast(10).reversed())
    }
}
