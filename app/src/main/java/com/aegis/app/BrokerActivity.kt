package com.aegis.app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import com.aegis.core.AgentFirewall
import com.aegis.core.CapabilityBroker

/** Starts the intent for a brokered action. Returns null on success, otherwise a reason code for the log. */
object BrokerExec {
    fun perform(context: Context, a: CapabilityBroker.Action): String? {
        // Re-checked here as well: what is started must be exactly what passed validation.
        CapabilityBroker.validate(a)?.let { return it }
        val intent = when (a.kind()) {
            CapabilityBroker.Kind.OPEN_URL -> Intent(Intent.ACTION_VIEW, Uri.parse(a.value())).addCategory(Intent.CATEGORY_BROWSABLE)
            CapabilityBroker.Kind.SHARE_TEXT -> Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, a.value()), null)
        }
        if (context !is Activity) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try { context.startActivity(intent); null }
        catch (_: ActivityNotFoundException) { "NO_APP_TO_HANDLE" }
        catch (_: SecurityException) { "NOT_ALLOWED" }
        catch (_: RuntimeException) { "START_FAILED" }
    }
}

/**
 * Invisible, non-exported activity started only by the one-shot launcher Aegis gave an agent for an allowed brokered
 * action. It takes the ticket (single use), re-checks the kill switch and that the agent is still paired, carries the
 * action out from the ticket's content and closes. NOT YET RUN ON A DEVICE.
 */
class BrokerActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AgentGateway.load(this)
        val data = intent?.data
        val id = if (data?.scheme == "aegis-broker" && data.host == "ticket") data.lastPathSegment else null
        val t = AgentGateway.allowTickets.take(id)
        if (t != null) {
            val reason = when {
                AgentGateway.lockdown.value -> "KILL_SWITCH_ON"
                !AgentGateway.paired.value.containsKey(t.agentId()) -> "AGENT_NOT_PAIRED"
                else -> BrokerExec.perform(this, t.action())
            }
            AgentGateway.firewall.noteBroker(t.agentId(), AgentFirewall.ActionType.SEND_DATA, t.request().destination(), reason == null, reason)
            AgentGateway.persist(this)
        }
        finish()
    }
}
