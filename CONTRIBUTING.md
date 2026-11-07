# Contributing

Thanks for looking. Security problems go through SECURITY.md, not issues.

## Most useful right now
1. **Running it on a real phone** and reporting what breaks, with the phone model and Android version. Nothing has been tested outside an emulator.
2. **Agent developers** trying the agent SDK (AGENT_SDK.md, `sample-agent/`) and saying what is missing.
3. **Review** of the gateway (`core/.../AgentFirewall.java`, `app/.../AgentGateway*.kt`) and the approval tokens (`agent-sdk/.../ApprovalToken.java`).

## Building and testing
- `bash core/run-tests.sh` runs the core and SDK tests with only a JDK 17+.
- `gradlew :core:check :app:assembleDebug :app:lintDebug :app:assembleDebugAndroidTest` builds everything. BUILD_INSTRUCTIONS.md has the details.
- `python tools/check_privacy.py` checks the permission set and VPN routing. Adding a permission needs a strong reason.
- CI runs host tests, the emulator tests and a real reboot test on every push.

## Ground rules
- Every change comes with tests. A change to a firewall rule needs a host test, and a change to the gateway or its screens needs an emulator test.
- Write only what was actually checked. If something was not run, say so in TEST_RESULTS.md and KNOWN_LIMITATIONS.md, and never invent detection rates.
- Only add or ask; never make a rule more permissive without discussion. Aegis never takes irreversible action on the person's behalf.
- User-facing text comes in English and Norwegian.
- No copied code from other projects, and no new dependency or dataset without checking its licence (DEPENDENCIES.md, DATA_SOURCES.md).

By contributing you agree that your work is licensed under the Apache License 2.0, like the rest of the project.
