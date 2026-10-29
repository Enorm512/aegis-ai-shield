plugins { `java-library` }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
val coreRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.CoreTests")
}
val archiveRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.ArchiveTests")
}
val threatIntelRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.ThreatIntelTests")
}
val aiRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.AiTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val dnsRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.DnsTests")
    workingDir = projectDir
}
val manifestRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.ManifestTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val lookalikeRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.LookalikeTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val agentRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.AgentFirewallTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val resultRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.ResultTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val verdictRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.VerdictTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val canaryRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.CanaryTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val capabilityRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.CapabilityTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val correlatorRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.CorrelatorTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val appWatchRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.AppWatchTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val dataToolsRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.DataToolsTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val spotRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.SpotTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val firewallReviewRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.FirewallReviewTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val agentShieldRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.AgentShieldTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val brokerRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.BrokerTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
val imageCheckRegression by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.aegis.core.ImageCheckTests")
    jvmArgs("-Dfile.encoding=UTF-8")
    workingDir = projectDir
}
tasks.check { dependsOn(imageCheckRegression, correlatorRegression, appWatchRegression, brokerRegression, agentShieldRegression, canaryRegression, capabilityRegression, dataToolsRegression, spotRegression, verdictRegression, firewallReviewRegression, resultRegression, coreRegression, archiveRegression, threatIntelRegression, aiRegression, dnsRegression, manifestRegression, lookalikeRegression, agentRegression) }
