// Sample agent: a demo harness (no AI model) showing how an assistant integrates with Aegis through the agent SDK.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.aegis.sampleagent"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.aegis.sampleagent"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "0.2.0-demo"
    }
    buildTypes { release { isMinifyEnabled = false } }
    lint { abortOnError = true }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
// The demo has no tests; without test variants no extra (unverified) test classpaths are resolved.
androidComponents { beforeVariants { it.enableAndroidTest = false; it.enableUnitTest = false } }
dependencies {
    implementation(project(":agent-sdk-android"))
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    // Same lifecycle versions as the Aegis app, so only already-verified artifacts are resolved (gradle/verification-metadata.xml).
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
}
