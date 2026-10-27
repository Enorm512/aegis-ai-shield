#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
java_cmd="${JAVA_HOME:+$JAVA_HOME/bin/}java"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
"$java_cmd" -m jdk.compiler/com.sun.tools.javac.Main --release 17 -d "$build_dir" src/main/java/com/aegis/core/*.java src/test/java/com/aegis/core/*.java
"$java_cmd" -cp "$build_dir" com.aegis.core.CoreTests
"$java_cmd" -cp "$build_dir" com.aegis.core.ArchiveTests
"$java_cmd" -cp "$build_dir" com.aegis.core.ThreatIntelTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.AiTests
"$java_cmd" -cp "$build_dir" com.aegis.core.DnsTests
"$java_cmd" -cp "$build_dir" com.aegis.core.ManifestTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.LookalikeTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.AgentFirewallTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.ResultTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.VerdictTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.FirewallReviewTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.SpotTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.DataToolsTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.CapabilityTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.CanaryTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.AgentShieldTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$build_dir" com.aegis.core.BrokerTests
# Agent SDK (pure Java). Its tests also use core, to check the shared names and limits agree.
sdk_dir="$build_dir/sdk"
mkdir -p "$sdk_dir"
"$java_cmd" -m jdk.compiler/com.sun.tools.javac.Main --release 17 -encoding UTF-8 -cp "$build_dir" -d "$sdk_dir" ../agent-sdk/src/main/java/com/aegis/agentsdk/*.java ../agent-sdk/src/test/java/com/aegis/agentsdk/*.java
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$sdk_dir:$build_dir" com.aegis.agentsdk.AgentSdkTests
"$java_cmd" -Dfile.encoding=UTF-8 -cp "$sdk_dir:$build_dir" com.aegis.agentsdk.TokenTests
