package com.aegis.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.aegis.agentsdk.ApprovalToken
import com.aegis.core.AgentFirewall
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * This phone's approval-token key: EC P-256 in the Android Keystore, usable only by Aegis for signing; the private
 * key never leaves the Keystore. A backend enrols the exported public key (PEM) and then accepts only calls that
 * carry a token signed by it. Replacing the key invalidates every token and needs re-enrolment on the servers.
 * NOT YET RUN ON A DEVICE.
 */
object ApprovalSigner {
    private const val ALIAS = "aegis_approval_signing_v1"
    /** Token lifetime. The server-side cap is ApprovalToken.MAX_LIFETIME_SECONDS. */
    const val LIFETIME_SECONDS = 120L
    private val random = SecureRandom()
    private val mutableKeyId = MutableStateFlow<String?>(null)
    /** Key fingerprint for the screen; null until the key exists or when the Keystore is unavailable. */
    val keyId = mutableKeyId.asStateFlow()

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized private fun publicKeyOrNull(): PublicKey? = runCatching { store().getCertificate(ALIAS)?.publicKey }.getOrNull()

    /** Creates the key on first use. */
    @Synchronized fun publicKey(): PublicKey? {
        publicKeyOrNull()?.let { mutableKeyId.value = ApprovalToken.keyId(it); return it }
        return runCatching {
            val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            g.initialize(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).build())
            g.generateKeyPair().public
        }.getOrNull()?.also { mutableKeyId.value = ApprovalToken.keyId(it) }
    }

    /** Shows the fingerprint if the key already exists, without creating one. */
    fun refresh() { mutableKeyId.value = publicKeyOrNull()?.let { ApprovalToken.keyId(it) } }

    fun pem(): String? = publicKey()?.let { ApprovalToken.toPem(it) }

    /** Deletes the key and makes a new one. Every server must enrol the new public key. */
    @Synchronized fun replace(): Boolean {
        runCatching { store().deleteEntry(ALIAS) }
        mutableKeyId.value = null
        return publicKey() != null
    }

    /**
     * Signs a token for [request] when it has a destination host a server can be the audience for; null otherwise
     * (no host, a destination with spaces or control characters, or no usable key).
     */
    fun issue(request: AgentFirewall.Request, grant: String): String? {
        val dest = request.destination() ?: return null
        val aud = AgentFirewall.hostOf(dest)
        if (aud.isEmpty() || dest.length > ApprovalToken.MAX_DEST) return null
        val pub = publicKey() ?: return null
        val now = System.currentTimeMillis() / 1000
        val jti = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val claims = ApprovalToken.Claims(ApprovalToken.keyId(pub), jti, now, now + LIFETIME_SECONDS, request.agentId(), aud, request.type().name,
            dest, ApprovalToken.bodyHash(request.payload()), request.amountMinor(), (request.currency() ?: "").uppercase(java.util.Locale.ROOT), grant)
        if (claims.invalidField() != null) return null
        return runCatching {
            ApprovalToken.issue(claims) { data ->
                val key = store().getKey(ALIAS, null) as PrivateKey
                Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }
            }
        }.getOrNull()
    }
}
