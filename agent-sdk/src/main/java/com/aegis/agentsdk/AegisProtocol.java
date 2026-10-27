package com.aegis.agentsdk;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The Messenger protocol between an AI agent and Aegis. Aegis' gateway service uses these same constants.
 *
 * <pre>
 * MSG_EVALUATE  type, destination, summary, payload, provenance, amountMinor, currency, requestId
 *   -> MSG_RESULT        verdict (ALLOW | ASK_USER | DENY | NOT_PAIRED), reasons[], approvalId, token (ALLOW only), requestId
 * MSG_REDEEM    the same fields plus approvalId, after the person approved in Aegis
 *   -> MSG_REDEEMED      granted, token (when granted), requestId
 * MSG_BROKER    brokerAction (OPEN_URL | SHARE_TEXT), value, summary, provenance, requestId
 *   -> MSG_BROKER_RESULT verdict, reasons[], approvalId, launch (PendingIntent, only for ALLOW), requestId
 *   -> MSG_BROKER_DONE   approvalId, performed, reason   (later, once the person decided on an ASK_USER)
 * </pre>
 * The caller is identified by Android (sending UID and signing certificate); nothing in a message identifies it.
 */
public final class AegisProtocol {
    private AegisProtocol() {}

    public static final String ACTION_BIND = "com.aegis.app.AGENT_FIREWALL";
    /** Aegis' release and debug package names, in the order a client should try them. */
    public static final List<String> AEGIS_PACKAGES = Collections.unmodifiableList(Arrays.asList("com.aegis.aishield", "com.aegis.aishield.debug"));

    public static final int MSG_EVALUATE = 1, MSG_RESULT = 2, MSG_REDEEM = 3, MSG_REDEEMED = 4, MSG_BROKER = 5, MSG_BROKER_RESULT = 6, MSG_BROKER_DONE = 7;

    public static final String KEY_REQUEST_ID = "requestId", KEY_TYPE = "type", KEY_DESTINATION = "destination", KEY_SUMMARY = "summary",
        KEY_PAYLOAD = "payload", KEY_PROVENANCE = "provenance", KEY_AMOUNT_MINOR = "amountMinor", KEY_CURRENCY = "currency",
        KEY_APPROVAL_ID = "approvalId", KEY_VERDICT = "verdict", KEY_REASONS = "reasons", KEY_GRANTED = "granted",
        KEY_BROKER_ACTION = "brokerAction", KEY_VALUE = "value", KEY_LAUNCH = "launch", KEY_PERFORMED = "performed", KEY_REASON = "reason",
        /** Approval token (see ApprovalToken) in MSG_RESULT for ALLOW and in MSG_REDEEMED when granted; absent when none could be issued. */
        KEY_TOKEN = "token";

    public static final String VERDICT_ALLOW = "ALLOW", VERDICT_ASK_USER = "ASK_USER", VERDICT_DENY = "DENY", VERDICT_NOT_PAIRED = "NOT_PAIRED";

    /** Action types an agent may ask about (Aegis' AgentFirewall.ActionType). */
    public static final List<String> ACTION_TYPES = Collections.unmodifiableList(Arrays.asList("SEND_DATA", "SHARE_FILE", "MESSAGE_AGENT", "READ_SENSITIVE",
        "EXECUTE_COMMAND", "INSTALL_APP", "FINANCIAL_TRANSACTION", "USE_CREDENTIAL", "MODIFY_SETTINGS"));
    /** Actions Aegis can carry out itself (Aegis' CapabilityBroker.Kind). */
    public static final String BROKER_OPEN_URL = "OPEN_URL", BROKER_SHARE_TEXT = "SHARE_TEXT";
    public static final List<String> BROKER_ACTIONS = Collections.unmodifiableList(Arrays.asList(BROKER_OPEN_URL, BROKER_SHARE_TEXT));

    public static final int MAX_SUMMARY = 2000, MAX_PAYLOAD = 100_000, MAX_URL = 2048, MAX_SHARE_TEXT = 10_000;
}
