# QuantumGuard console: design direction

## One line
A ledger, not a dashboard: paper and ink, one ultramarine accent, square corners, hairline rules, and every decision shown as a receipt you can check.

## Who it is for
People in a small organisation who handle sensitive files and are not security specialists (employees), and the three people who look after them (admin, operator, auditor). On their worst day, a laptop left in a taxi, the product has to be calm, exact and fast.

## What the design must say
1. **Nothing here asks to be trusted.** Claims are followed by a receipt, a number or a proof. The receipt slip is the signature element: mono type, dashed rules, a "verified" stamp that appears only after this device has checked the proof itself.
2. **The state of this device is always visible.** A chip in the sidebar names the device, its status and the directory epoch it last saw.
3. **The dangerous action is the easy one.** Reporting a lost device is two clicks and a time. Everything else can wait; that cannot.
4. **No decoration on security-critical screens.** Enrolment, unlock, revoke and verify use plain components. Motion appears only where it explains a real event (keys created, chunks sealed, a slot deleted, a proof climbing to the root).

## Tokens (source: `src/index.css`)
| Role | Light | Dark | Use |
|---|---|---|---|
| background / foreground | paper `#f5f3ec` / ink `#161a22` | `#0e1116` / `#ece9df` | page |
| card (paper-raised) | `#fbfaf6` | `#151920` | panels, slips, dialogs |
| primary | ultramarine `#2438c7` | `#98a4ff` | the one primary action per view, links, focus |
| allow / deny / caution | `#17613e` / `#ad241c` / `#7d4b00` | `#62cf98` / `#ff8375` / `#f0b45a` | decisions and states, always with a word or icon |
| border / rule / input | `#d8d4c7` / `#c4bfb0` / `#b9b4a4` | `#2a303b` / `#3a4150` / `#454d5c` | hairlines; `rule` is the stronger one |

All text pairs meet 4.5:1. Meaning is never carried by colour alone.

- **Type.** IBM Plex Sans for interface text; IBM Plex Mono for anything a machine produced (ids, hashes, epochs, times, counts in tables); Instrument Serif for display lines on the public site and for the single headline of an empty state. Root size is 18px so the component set lands at 13.5px body and 36px controls. Line length 65 to 75 characters for prose.
- **Shape.** Radius 0 everywhere. Panels are separated by 1px rules, not shadows. One lifted shadow (`shadow-lift`) for popovers and dialogs only.
- **Space.** 4px scale. Page gutter 24px (16px under 640px). Table rows 44px. Controls 36px, never under 24px.
- **Motion.** 150 to 250 ms, `ease-out-quiet`. In-app explanatory animations under 1.2 s, never blocking input, each with a reduced-motion equivalent that is text, not a faster animation.
- **Icons.** Lucide only, 16px, 1.5 stroke. No emoji.
- **Voice.** Short declarative sentences. Say what happened, why, and what to do next. Name things the way the person does: "this device", "your files", "access removed". Cryptographic terms appear in details, not headlines.

## Reused components
shadcn/ui (style `radix-lyra`) for every primitive; see `COMPONENTS.md` for the list and licences. Custom components exist only where nothing fits: the receipt slip, the incident timeline, the six explanatory animations and the lattice. Each is listed in `COMPONENTS.md` with the reason.

## Layout
- Console: fixed sidebar (collapses to a sheet under 768px), a top bar with page title, command palette and session clock, and one content column with a 1120px maximum. Tables scroll inside their own container; the page never scrolls sideways.
- Detail lives in a right-hand sheet so the list stays in view; anything that needs a link of its own (file, incident) is also a route.
- One primary button per view, top right of the content header on desktop, full width at the bottom of the header on phones.

## Checks before a screen is called done
Empty, loading (skeleton), error (with recovery), offline, session expired and device revoked states exist; keyboard path works end to end; focus is visible; nothing breaks at 390px; dark theme reads correctly; reduced motion replaces animation with text; axe reports no serious or critical issue.
