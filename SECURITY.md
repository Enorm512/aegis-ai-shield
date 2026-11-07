# Security policy

Aegis AI Shield is a preview. It has not had an independent security review and has never run on a real phone, so expect bugs. Do not rely on it as your only protection.

## Reporting a vulnerability
Please report privately through GitHub: the repository's **Security** tab → **Report a vulnerability**. Do not open a public issue for a security problem.

Useful to include:
- the Aegis version (`versionName` in `app/build.gradle.kts`, or Android's app info for Aegis) and the Android version
- what an attacker can do, and what they need first (for example a paired agent, an installed app, or Accessibility access)
- steps or a test that shows it

This is a one-person project, so replies may take a while. Fixes are noted in CHANGELOG.md, and the reporter is credited unless they ask not to be.

## What counts
In scope, for example:
- a way for an agent to get an action through the gateway without the person's approval, or to change what was approved
- an approval token that verifies when it should not
- leaking data the privacy policy says stays on the phone
- getting around the emergency stop, a stopped kind of action, read-only mode or the screen-lock check

Known limits are in KNOWN_LIMITATIONS.md and are not new findings. The main ones: an agent that never asks Aegis, or that uses Accessibility, is not seen; detection of scam messages and links is weak; the debug build trusts published test keys on purpose.
