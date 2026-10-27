# Design notes (UX redesign, 2026-10-26)

**Status: compiled, linted and covered by host tests for the logic underneath. The screens have never been looked at on a device or emulator**, so spacing, contrast, clipping and animation feel are unverified. First task for the next session with a phone: walk every screen in light and dark, EN and NO, at 100% and 200% font scale.

## Why
The previous app was one long scrolling page with four filter chips. A review (see conversation notes) found: no at-a-glance status, a "Device" tab holding five unrelated features, results with no severity cue or next step, and time-limited AI-agent approvals buried mid-scroll.

## Information architecture
Bottom navigation, four destinations:
| Destination | Contents |
|---|---|
| **Home** | What needs attention (waiting agent requests, a failed/expired threat database, a worrying last result), shortcuts to check a link/message or an APK, and one status row per feature (DNS protection, threat database, AI agent guard, this phone, experimental model). |
| **Check** | One box for links and messages with auto-detection (`InputKind`, overridable with Link/Message chips), a Paste button, the APK review card, and the single result card. Shared text is checked automatically. |
| **Protection** | DNS protection (state, plain counters, start/stop), allow/block lists with validation, AI agent guard (connected apps, waiting requests). |
| **More** | Language and theme, threat database (import hidden when the build cannot accept bundles), experimental language model switch, phone facts, About. |

A **banner** appears above every screen when an AI agent is waiting, and a notification is posted (generic text only, never agent-supplied text). Review opens a dialog where **Deny / Reject is the prominent button** and approving is the quieter outlined one.

## Result card (`ResultCard`, logic in core `ResultSummary`)
1. Level label + headline + what was checked, with a badge. Five levels: known threat, strong warning signs, suspicious, unclear, no known warning signs. Colour, glyph and words all carry the level. "No known warning signs" is blue-grey with an "i", deliberately not a green tick.
2. **Why**: at most three reasons, ranked by importance (informational facts such as the host never headline).
3. **What to do**: numbered, concrete next steps (don't open it, use the official route, never share codes, what to do if you already clicked or paid, report it, don't install / remove an installed file). Norway-specific: bank contact via official channels and politi.no for reporting.
4. **Details** on request: everything else, standing caveats, and for APKs the package, hash, certificates and permissions.

## Principles kept from before
Evidence not guarantees; never "safe"; local-only wording; experimental features default off and labelled; the VPN is never started silently (disclosure dialog, then Android's consent).

## Quick fixes included
Allow/block text field no longer loses focus after adding; invalid domains now show an error; removing a paired agent asks for confirmation; language switch is a labelled English/Norsk pair (no more "NO" read as the word no); dead import button hidden in release builds; developer-style numbers (resolver errors, ms load times) moved out of the main view; live counters only tick while Home or Protection is visible and only those screens recompose; result auto-scrolls into view; result survives language switch because it stores codes, not strings.

## Not done / next
- Real visual verification and a design pass with icons beyond the four navigation glyphs, a proper logo, and motion polish.
- Screenshots for the store listing.
- Persisting a short "recent checks" list was deliberately not added (it conflicts with the no-saved-history promise); decide explicitly if wanted.
- Pending-approval notifications depend on the notification permission being granted.
- TalkBack/large-font testing (see ACCESSIBILITY.md).

## Visual identity update (0.7.2-rc3)
- **Mark:** shield (identity: protection), split light/deep mint (depth without gradients), navy lens with a tick (check, "pause. check. decide."). Works as a single-colour silhouette (themed icon, status bar). Source: `tools/gen_icons.py` (`mark_geometry`); preview with `java tools/IconPreview.java sheet app/src/main/res out.png`.
- **Icons:** 24-unit grid, 1.8 stroke, round caps/joins, one visual weight; tinted by theme. Level badges use icons plus words, not colour alone.
- **Motion:** purposeful and brief (220-320 ms), one-shot except the DNS "breathing" glow. Honors the system "Remove animations" setting.
- **Known gaps:** no custom typeface (system font), no illustrations/empty-state art, no animated splash beyond the system's icon splash, store screenshots still need a device.
