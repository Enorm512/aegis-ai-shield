# Accessibility review

**No assistive-technology testing has been done** (no device, no TalkBack, no Switch Access, no Accessibility Scanner). The items below come from reading the Compose code and lint.

## Fixed in this stage
- Toggles (dark appearance, experimental language model) are now one `toggleable` row with `Role.Switch`, so a screen reader announces the label and state together instead of an unlabeled switch.
- Section titles carry `heading()` semantics for heading navigation.
- The result card is a polite live region so a new result is announced.
- Decorative logo letter removed from the accessibility tree.
- Fixed 50 dp button heights changed to minimum heights so large font scales do not clip text.
- Status-bar and navigation-bar icon contrast now follows the in-app light/dark theme (previously light icons on a light background in the light theme).
- Text uses `sp` units, content scrolls, input fields have visible labels.

## Known gaps / unverified
- Contrast ratios were not measured; warning text uses the Material error colour and a brown tint on the result card.
- Touch targets rely on Material defaults (48 dp minimum for chips/buttons); not measured on device.
- Focus order, TalkBack wording of long explanatory paragraphs, and the Norwegian screen-reader pronunciation are untested.
- The in-app language switch is a toggle button labelled "EN"/"NO" (not announced as a language change).
- Pending agent approvals are visible only inside the app; no notification, so users of assistive tech may not discover them.
- No automated accessibility checks run in CI (the instrumentation tests exist but have never been run).

## Update after the redesign
Navigation is now a labelled bottom bar (icons hidden from TalkBack, labels spoken), the language control reads "English"/"Norsk", the result card is a polite live region whose header is merged into one announcement, the badge glyph is excluded from the accessibility tree (the label carries the meaning), and the agent banner is a live region. Still untested with TalkBack, Switch Access, font scale 200% or display zoom.

## Update: icons and motion
Icons are decorative (the control or text carries the name) and are excluded from the accessibility tree. Result and banner changes remain polite live regions. All animations are skipped when the system animation scale is 0. Not tested with TalkBack or on a device.
