#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
java_cmd="${JAVA_HOME:+$JAVA_HOME/bin/}java"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
"$java_cmd" -m jdk.compiler/com.sun.tools.javac.Main --release 17 -d "$build_dir" src/main/java/com/aegis/core/*.java
"$java_cmd" -cp "$build_dir" com.aegis.core.AnalysisCli "$@"
