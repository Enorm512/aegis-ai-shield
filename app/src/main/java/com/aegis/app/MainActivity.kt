package com.aegis.app

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.aegis.core.ApkArchiveInspector
import com.aegis.core.HashScanner
import com.aegis.core.InputKind
import com.aegis.core.ManifestAnalyzer
import com.aegis.core.MessageAi
import com.aegis.core.ResultSummary
import com.aegis.core.ResultSummary.Subject
import com.aegis.core.ThreatBundleVerifier
import com.aegis.core.ThreatChecks
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.Locale

internal const val MAX_TEXT = 12000
private const val MAX_APK = 100L * 1024 * 1024

object Screens { const val HOME = 0; const val CHECK = 1; const val PROTECT = 2; const val MORE = 3 }

data class UiState(
    val screen: Int = Screens.HOME,
    val input: String = "",
    val norwegian: Boolean = Locale.getDefault().language.let { it == "nb" || it == "no" || it == "nn" },
    val dark: Boolean = true,
    val busy: Boolean = false,
    val result: ResultUi? = null,
    val shared: Boolean = false,
    val inputTooLong: Boolean = false,
    val kindOverride: InputKind.Kind? = null,
    val intel: IntelUi = IntelUi(),
    val ai: AiUi = AiUi(),
    val aiEnabled: Boolean = false,
)

class AegisViewModel(application: android.app.Application) : AndroidViewModel(application) {
    init { application.cacheDir.listFiles()?.filter { it.name.startsWith("apk-review-") && it.extension == "apk" }?.forEach { it.delete() } }
    private var revision = 0L
    /** The running link/message check or APK inspection, so newly shared text can replace it. Main thread only. */
    private var work: Job? = null
    private val mutable = MutableStateFlow(UiState())
    val state = mutable.asStateFlow()

    fun go(screen: Int) { mutable.value = mutable.value.copy(screen = screen) }
    fun input(value: String) { revision++; mutable.value = mutable.value.copy(input = value.take(MAX_TEXT), inputTooLong = value.length > MAX_TEXT, result = null, shared = false, kindOverride = if (value.isBlank()) null else mutable.value.kindOverride) }
    fun setKind(kind: InputKind.Kind) { revision++; mutable.value = mutable.value.copy(kindOverride = kind, result = null) }
    fun language() { mutable.value = mutable.value.copy(norwegian = !mutable.value.norwegian) }
    fun theme() { mutable.value = mutable.value.copy(dark = !mutable.value.dark) }
    fun clear() { if (!mutable.value.busy) { revision++; mutable.value = mutable.value.copy(input = "", result = null, shared = false, inputTooLong = false, kindOverride = null) } }
    fun toggleAi() { revision++; mutable.value = mutable.value.copy(aiEnabled = !mutable.value.aiEnabled, result = null) }

    /**
     * Text arriving from another app is checked straight away: the analysis is local, in memory, and opens nothing.
     * A check still running for earlier input is cancelled first; before, the new text was shown but never checked.
     */
    fun shared(value: String) {
        revision++
        work?.cancel()
        work = null
        mutable.value = mutable.value.copy(input = value.take(MAX_TEXT), screen = Screens.CHECK, result = null, shared = true, inputTooLong = value.length > MAX_TEXT, kindOverride = null, busy = false)
        if (value.isNotBlank()) analyze()
    }

    private fun snapshotIntel(message: String?, busy: Boolean = false): IntelUi {
        val h = ThreatIntel.holder(getApplication())
        val db = h.store.current()
        return IntelUi(true, h.anchorsPresent, db.sequence, db.size(), if (db.isEmpty) "" else db.issued.toString().take(10), if (db.isEmpty) "" else db.expires.toString().take(10),
            db.isStale(java.time.Instant.now()), h.store.loadWarning() != null, h.store.canRollback(), busy, message)
    }

    fun refreshIntel() {
        if (mutable.value.intel.loaded) return
        viewModelScope.launch {
            val (ui, ai) = withContext(Dispatchers.IO) { snapshotIntel(null) to AiModel.get(getApplication()).let { AiUi(true, it.classifier != null, it.classifier?.name() ?: "", it.loadMillis) } }
            mutable.value = mutable.value.copy(intel = ui, ai = ai)
        }
    }

    fun importBundle(uri: Uri) {
        if (mutable.value.intel.busy) return
        mutable.value = mutable.value.copy(intel = mutable.value.intel.copy(busy = true, message = null))
        viewModelScope.launch {
            val ui = withContext(Dispatchers.IO) {
                try {
                    val bytes = getApplication<android.app.Application>().contentResolver.openInputStream(uri)?.use { com.aegis.core.BoundedRead.atMost(it, ThreatBundleVerifier.MAX_BUNDLE_BYTES + 1) } ?: error("unreadable")
                    ThreatIntel.holder(getApplication()).store.install(bytes)
                    snapshotIntel("OK")
                } catch (e: ThreatBundleVerifier.BundleException) { snapshotIntel(e.reason.name)
                } catch (cancelled: CancellationException) { throw cancelled
                } catch (_: Exception) { snapshotIntel("IO") }
            }
            mutable.value = mutable.value.copy(intel = ui)
        }
    }

    fun rollbackIntel() {
        if (mutable.value.intel.busy) return
        mutable.value = mutable.value.copy(intel = mutable.value.intel.copy(busy = true, message = null))
        viewModelScope.launch {
            val ui = withContext(Dispatchers.IO) { snapshotIntel(if (runCatching { ThreatIntel.holder(getApplication()).store.rollback() }.getOrDefault(false)) "ROLLED_BACK" else "IO") }
            mutable.value = mutable.value.copy(intel = ui)
        }
    }

    fun analyze() {
        val snapshot = mutable.value
        val requestRevision = revision
        if (snapshot.busy || snapshot.input.isBlank() || snapshot.inputTooLong) return
        val kind = snapshot.kindOverride ?: InputKind.detect(snapshot.input)
        val subject = if (kind == InputKind.Kind.LINK) Subject.LINK else Subject.MESSAGE
        mutable.value = snapshot.copy(busy = true, result = null)
        work = viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                try {
                    val analysis = if (subject == Subject.LINK) ThreatChecks.url(snapshot.input, ThreatIntel.get(getApplication()))
                    else MessageAi.analyze(snapshot.input, if (snapshot.aiEnabled) AiModel.get(getApplication()).classifier else null)
                    val shown = if (subject == Subject.LINK) analysis.findings.firstOrNull { it.code == "HOST" }?.detail?.removePrefix("Destination host: ")
                        else null
                    val text = shown ?: snapshot.input.trim().replace(Regex("\\s+"), " ").let { if (it.length > 90) it.take(90) + "…" else it }
                    ResultUi(ResultSummary.of(analysis, subject), text)
                } catch (cancelled: CancellationException) { throw cancelled } catch (_: Exception) { errorResult(subject, "input") }
            }
            mutable.value = mutable.value.copy(busy = false, result = if (revision == requestRevision) result else null)
        }
    }

    fun inspect(uri: Uri) {
        if (mutable.value.busy) return
        revision++
        val requestRevision = revision
        mutable.value = mutable.value.copy(busy = true, result = null, screen = Screens.CHECK)
        work = viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                var temporary: File? = null
                try {
                    val context = getApplication<android.app.Application>()
                    val copy = File.createTempFile("apk-review-", ".apk", context.cacheDir)
                    temporary = copy
                    context.contentResolver.openInputStream(uri)?.use { source ->
                        copy.outputStream().use { out ->
                            val buffer = ByteArray(32768)
                            var total = 0L
                            while (true) {
                                currentCoroutineContext().ensureActive()
                                val count = source.read(buffer)
                                if (count < 0) break
                                check(count > 0) { "Provider returned an unexpected empty read" }
                                currentCoroutineContext().ensureActive()
                                total += count
                                require(total <= MAX_APK) { "APK exceeds 100 MiB" }
                                out.write(buffer, 0, count)
                            }
                        }
                    } ?: error("Unreadable file")
                    currentCoroutineContext().ensureActive()
                    ApkArchiveInspector.inspect(copy)
                    currentCoroutineContext().ensureActive()
                    val hash = copy.inputStream().use { HashScanner.sha256(it, MAX_APK) }
                    currentCoroutineContext().ensureActive()
                    val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
                    @Suppress("DEPRECATION")
                    val info = context.packageManager.getPackageArchiveInfo(copy.absolutePath, flags) ?: error("Android could not parse the APK")
                    @Suppress("DEPRECATION")
                    val signers = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
                    val certs = signers.orEmpty().map { sig -> MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) } }
                    val intel = ThreatIntel.get(context)
                    var reputation = ThreatChecks.apkHash(hash, intel)
                    for (cert in certs) reputation = ThreatChecks.signer(reputation, cert, intel)
                    val capability = ManifestAnalyzer.analyzeFile(copy)
                    val facts = ApkFacts(info.packageName, info.versionName ?: "", hash, certs, info.requestedPermissions.orEmpty().toList())
                    ResultUi(ResultSummary.of(ResultSummary.combine(capability, reputation), Subject.APK), info.packageName, facts)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    errorResult(Subject.APK, "apk")
                } finally { temporary?.delete() }
            }
            mutable.value = mutable.value.copy(busy = false, result = if (revision == requestRevision) result else null)
        }
    }
}

class MainActivity : ComponentActivity() {
    private val model: AegisViewModel by viewModels()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) acceptShared(intent)
        setContent { val state by model.state.collectAsStateWithLifecycle(); AegisApp(state, model, this) }
        window.decorView.filterTouchesWhenObscured = true // ignore taps while another app draws over this one (approvals, pairing, VPN start)
    }
    override fun onResume() { super.onResume(); AgentNotifier.clear(this) }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); acceptShared(intent) }
    private fun acceptShared(intent: Intent?) {
        if (intent?.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            try {
                intent.getStringExtra(Intent.EXTRA_TEXT)?.let(model::shared)
                intent.removeExtra(Intent.EXTRA_TEXT)
            } catch (_: RuntimeException) {
                // Malformed external extras are data, never a reason to crash the activity.
                model.shared("")
            }
        }
    }
}
