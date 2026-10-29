pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories {
        google(); mavenCentral()
        // JitPack serves only the Tesseract OCR wrapper, and that group may come from nowhere else. Checksums are pinned in gradle/verification-metadata.xml.
        exclusiveContent { forRepository { maven("https://jitpack.io") }; filter { includeGroup("cz.adaptech.tesseract4android") } }
    }
}
rootProject.name = "AegisAIShield"
include(":app", ":core", ":agent-sdk", ":agent-sdk-android", ":sample-agent")
