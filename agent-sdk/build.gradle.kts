// Aegis agent SDK, platform-neutral part: wire protocol constants, action fingerprints and harness-side provenance
// (taint) tracking. Pure Java 17 with no dependencies, API-26-safe, so it runs in an Android agent and in host tests.
plugins { `java-library` }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
dependencies {
    testImplementation(project(":core")) // only to check that names match Aegis' own enums
}
val sdkRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.agentsdk.AgentSdkTests")
    jvmArgs("-Dfile.encoding=UTF-8")
}
val tokenRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.agentsdk.TokenTests")
    jvmArgs("-Dfile.encoding=UTF-8")
}
tasks.check { dependsOn(sdkRegression, tokenRegression) }
