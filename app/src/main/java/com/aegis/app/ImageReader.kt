package com.aegis.app

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.aegis.core.BoundedRead
import com.aegis.core.ImageCheck
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.googlecode.tesseract.android.TessBaseAPI
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.EnumMap
import kotlin.concurrent.thread
import kotlin.coroutines.resume

/**
 * Reads a picture on the phone: QR codes with ZXing and text with Tesseract (English and Norwegian, models shipped in the APK).
 * Nothing is uploaded, saved or opened; the decoded bitmap lives only for the duration of the check.
 */
object ImageReader {
    const val MAX_BYTES = 40 * 1024 * 1024
    /** Larger pictures are scaled down before reading; a long scrolling screenshot keeps enough detail for text at this size. */
    private const val MAX_PIXELS = 12_000_000
    /** QR codes in screenshots are large; scanning a smaller copy keeps memory use low. */
    private const val MAX_QR_PIXELS = 4_000_000
    private const val MAX_SOURCE_PIXELS = 200_000_000L
    private const val OCR_TIMEOUT_MS = 25_000L
    private val LANGUAGES = listOf("eng", "nor")

    /** [text] is null when text recognition could not run; [error] is set when the picture itself could not be read. */
    data class Read(val text: String?, val qr: List<String>, val error: String? = null)

    /** Only content:// pictures from other apps: a file:// or Aegis-internal address could make Aegis read its own private files. */
    fun acceptable(context: Context, uri: Uri): Boolean =
        uri.scheme == ContentResolver.SCHEME_CONTENT && uri.authority?.startsWith(context.packageName) != true

    suspend fun read(context: Context, uri: Uri): Read {
        if (!acceptable(context, uri)) return Read(null, emptyList(), "source")
        val bytes = try {
            context.contentResolver.openInputStream(uri)?.use { BoundedRead.atMost(it, MAX_BYTES + 1) } ?: return Read(null, emptyList(), "unreadable")
        } catch (c: CancellationException) { throw c } catch (_: Exception) { return Read(null, emptyList(), "unreadable") }
        if (bytes.size > MAX_BYTES) return Read(null, emptyList(), "too_big")
        // Not recycled by hand: a cancelled OCR thread may still be copying it, and bitmap pixels live on the Java heap since Android 8.
        val bitmap = decode(bytes) ?: return Read(null, emptyList(), "not_image")
        return readBitmap(context, bitmap)
    }

    internal fun decode(bytes: ByteArray): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        val w = bounds.outWidth.toLong(); val h = bounds.outHeight.toLong()
        if (w <= 0 || h <= 0 || w * h > MAX_SOURCE_PIXELS) return null
        var sample = 1
        while (w * h / (sample.toLong() * sample) > MAX_PIXELS) sample *= 2
        return try {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = Bitmap.Config.ARGB_8888 })
        } catch (_: OutOfMemoryError) { null }
    }

    suspend fun readBitmap(context: Context, bitmap: Bitmap): Read {
        val qr = qrCodes(bitmap)
        val text = ocr(context, bitmap)
        return Read(text, qr)
    }

    internal fun qrCodes(full: Bitmap): List<String> {
        val pixelCount = full.width.toLong() * full.height
        val bitmap = if (pixelCount <= MAX_QR_PIXELS) full else Math.sqrt(MAX_QR_PIXELS.toDouble() / pixelCount).let { f ->
            Bitmap.createScaledBitmap(full, maxOf(1, (full.width * f).toInt()), maxOf(1, (full.height * f).toInt()), true)
        }
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val source: LuminanceSource = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
        }
        val found = LinkedHashSet<String>()
        // Several QR codes, then one with another binarizer, then light-on-dark codes (dark-mode screenshots).
        for (s in listOf(source, source.invert())) {
            try { QRCodeMultiReader().decodeMultiple(BinaryBitmap(HybridBinarizer(s)), hints).forEach { r -> r.text?.let(found::add) } } catch (_: ReaderException) { }
            if (found.isEmpty()) try { QRCodeReader().decode(BinaryBitmap(GlobalHistogramBinarizer(s)), hints).text?.let(found::add) } catch (_: ReaderException) { }
            if (found.isNotEmpty()) break
        }
        return found.take(ImageCheck.MAX_QR * 2)
    }

    /** The trained-data files must be ordinary files for Tesseract; they are copied from the APK once per app version. */
    private fun dataDir(context: Context): File? {
        val root = File(context.noBackupFilesDir, "tesseract")
        val dir = File(root, "tessdata")
        val stamp = File(root, "version")
        val version = context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime.toString()
        if (stamp.isFile && stamp.readText() == version && LANGUAGES.all { File(dir, "$it.traineddata").isFile }) return root
        return try {
            dir.mkdirs()
            for (lang in LANGUAGES) {
                val target = File(dir, "$lang.traineddata")
                val tmp = File(dir, "$lang.traineddata.tmp")
                context.assets.open("tessdata/$lang.traineddata").use { input -> tmp.outputStream().use { input.copyTo(it) } }
                if (!tmp.renameTo(target)) { target.delete(); check(tmp.renameTo(target)) }
            }
            stamp.writeText(version)
            root
        } catch (_: Exception) { null }
    }

    /** Runs Tesseract on its own thread so a cancelled or overlong check stops it instead of waiting for it. */
    private suspend fun ocr(context: Context, bitmap: Bitmap): String? {
        val root = dataDir(context) ?: return null
        return withTimeoutOrNull(OCR_TIMEOUT_MS) {
            suspendCancellableCoroutine { cont ->
                val tess = TessBaseAPI()
                // stop() must never reach a recycled native instance.
                val lock = Any()
                var recycled = false
                thread(name = "aegis-ocr") {
                    var text: String? = null
                    try {
                        if (tess.init(root.absolutePath, LANGUAGES.joinToString("+"), TessBaseAPI.OEM_LSTM_ONLY)) {
                            tess.pageSegMode = TessBaseAPI.PageSegMode.PSM_AUTO
                            tess.setImage(bitmap)
                            text = tess.getUTF8Text()
                        }
                    } catch (_: Exception) { text = null
                    } finally { synchronized(lock) { recycled = true; tess.recycle() } }
                    if (cont.isActive) cont.resume(text)
                }
                cont.invokeOnCancellation { synchronized(lock) { if (!recycled) runCatching { tess.stop() } } }
            }
        }
    }
}
