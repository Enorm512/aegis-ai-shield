package com.aegis.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small encrypted files in the app's private storage, for the agent audit log and waiting approvals. AES-256-GCM with
 * a key kept in the Android Keystore (it never leaves the secure hardware where the phone has it); the file name is
 * bound as associated data so one file cannot be swapped for another. Writes are atomic. Backups are off for the app.
 * A file that cannot be decrypted (key lost, e.g. after a restore to another phone, or a damaged file) reads as
 * [Read.Unreadable], never as empty data. NOT YET RUN ON A DEVICE.
 */
object SealedStore {
    private const val ALIAS = "aegis_sealed_store_v1"
    private const val DIR = "sealed"
    private val MAGIC = byteArrayOf('A'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())

    sealed interface Read { data object Missing : Read; data object Unreadable : Read; data class Ok(val text: String) : Read }

    private fun file(context: Context, name: String) = AtomicFile(File(File(context.applicationContext.filesDir, DIR).apply { mkdirs() }, name))

    @Synchronized private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        return g.generateKey()
    }

    /** Returns false when encryption or the write failed; nothing partial is left behind. */
    @Synchronized fun write(context: Context, name: String, text: String): Boolean {
        val af = file(context, name)
        val out = try { af.startWrite() } catch (_: Exception) { return false }
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key())
            c.updateAAD(name.toByteArray(Charsets.UTF_8))
            val sealed = c.doFinal(text.toByteArray(Charsets.UTF_8))
            out.write(MAGIC); out.write(c.iv.size); out.write(c.iv); out.write(sealed)
            af.finishWrite(out); true
        } catch (_: Exception) { af.failWrite(out); false }
    }

    @Synchronized fun read(context: Context, name: String): Read {
        val af = file(context, name)
        if (!af.baseFile.exists()) return Read.Missing
        return try {
            val b = af.readFully()
            if (b.size < 4 + 12 + 16 || !b.copyOfRange(0, 3).contentEquals(MAGIC)) return Read.Unreadable
            val ivLen = b[3].toInt() and 0xff
            if (ivLen !in 12..16 || b.size < 4 + ivLen + 16) return Read.Unreadable
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 4, ivLen))
            c.updateAAD(name.toByteArray(Charsets.UTF_8))
            Read.Ok(String(c.doFinal(b, 4 + ivLen, b.size - 4 - ivLen), Charsets.UTF_8))
        } catch (_: Exception) { Read.Unreadable }
    }

    @Synchronized fun delete(context: Context, name: String) { runCatching { file(context, name).delete() } }
}
