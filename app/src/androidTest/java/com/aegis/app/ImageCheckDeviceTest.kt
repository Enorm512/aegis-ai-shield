package com.aegis.app

import android.content.ContentValues
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.provider.MediaStore
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.core.Analysis
import com.aegis.core.ImageCheck
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.util.Locale

/** Screenshot and QR check on Android: Tesseract and ZXing on pictures drawn at test time, and a picture shared to Aegis. */
class ImageCheckDeviceTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val norwegian get() = Locale.getDefault().language in listOf("nb", "no", "nn")

    private val scamLines = listOf("DNB Security notice", "Your account is suspended.", "Verify your account immediately", "and reply with your BankID code.")
    private val loginQr = "tg://login?token=AbCdEf0123456789xyz"

    /** A phone-sized screenshot: lines of text and, optionally, a QR code, in light or dark mode. */
    private fun screenshot(lines: List<String>, qr: String?, dark: Boolean = false): Bitmap {
        val bmp = Bitmap.createBitmap(1080, 1700, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        canvas.drawColor(if (dark) Color.rgb(18, 18, 18) else Color.WHITE)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = if (dark) Color.rgb(235, 235, 235) else Color.BLACK; textSize = 46f; typeface = Typeface.SANS_SERIF }
        lines.forEachIndexed { i, l -> canvas.drawText(l, 60f, 140f + i * 80f, paint) }
        if (qr != null) {
            val m = QRCodeWriter().encode(qr, BarcodeFormat.QR_CODE, 520, 520)
            val fg = if (dark) Color.rgb(235, 235, 235) else Color.BLACK
            for (x in 0 until m.width) for (y in 0 until m.height) if (m.get(x, y)) bmp.setPixel(280 + x, 1000 + y, fg)
        }
        return bmp
    }

    @Test fun readsTextAndLoginQrFromAScreenshot() = runBlocking {
        val read = ImageReader.readBitmap(context, screenshot(scamLines, loginQr))
        assertEquals(listOf(loginQr), read.qr)
        val text = read.text ?: ""
        assertTrue("OCR read the text: $text", text.contains("suspended", ignoreCase = true) && text.contains("BankID", ignoreCase = true))
        val a = ImageCheck.analyze(read.text, read.qr, null, null)
        assertEquals(Analysis.Verdict.STRONG_INDICATORS, a.verdict)
        assertTrue(a.findings.any { it.code == "QR_DEVICE_LINK" } && a.findings.any { it.code == "SECRET_REQUEST" })
    }

    @Test fun darkModeScreenshotIsRead() = runBlocking {
        val read = ImageReader.readBitmap(context, screenshot(scamLines, "https://example.org/menu", dark = true))
        assertEquals("light-on-dark QR decoded", listOf("https://example.org/menu"), read.qr)
        assertTrue("dark-mode text read: ${read.text}", read.text?.contains("suspended", ignoreCase = true) == true)
    }

    @Test fun pictureWithNothingToReadIsUnclear() = runBlocking {
        val read = ImageReader.readBitmap(context, screenshot(emptyList(), null))
        assertTrue(read.qr.isEmpty())
        assertEquals(Analysis.Verdict.INSUFFICIENT_EVIDENCE, ImageCheck.analyze(read.text, read.qr, null, null).verdict)
    }

    @Test fun fileAndOwnUrisAreRefused() {
        assertTrue(!ImageReader.acceptable(context, Uri.parse("file:///data/data/${context.packageName}/files/x.png")))
        assertTrue(!ImageReader.acceptable(context, Uri.parse("content://${context.packageName}.provider/x.png")))
        assertTrue(ImageReader.acceptable(context, Uri.parse("content://media/external/images/media/1")))
    }

    /** End to end: a PNG in the media store, shared to Aegis the way a gallery app does, is read and judged without a tap. */
    @Test fun sharedScreenshotIsCheckedAutomatically() {
        val resolver = context.contentResolver
        val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, "aegis-test-${System.nanoTime()}.png")
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
        })!!
        try {
            resolver.openOutputStream(uri)!!.use { screenshot(scamLines, loginQr).compress(Bitmap.CompressFormat.PNG, 100, it) }
            val share = Intent(context, MainActivity::class.java).setAction(Intent.ACTION_SEND).setType("image/png")
                .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            ActivityScenario.launch<MainActivity>(share).use {
                val headline = if (norwegian) "Sterke tegn på svindel i bildet" else "Strong signs of a scam in this picture"
                compose.waitUntil(30_000) { compose.onAllNodesWithText(headline).fetchSemanticsNodes().isNotEmpty() }
                val advice = if (norwegian) "Ikke skann denne QR-koden" else "Don't scan this QR code"
                assertTrue(compose.onAllNodesWithText(advice, substring = true).fetchSemanticsNodes().isNotEmpty())
            }
        } finally { resolver.delete(uri, null, null) }
    }
}
