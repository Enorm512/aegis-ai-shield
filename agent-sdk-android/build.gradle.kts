// Aegis agent SDK, Android binding: finds Aegis, binds its gateway and speaks AegisProtocol over a Messenger.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.aegis.agentsdk.android"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = true }
}
dependencies {
    api(project(":agent-sdk"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
}
