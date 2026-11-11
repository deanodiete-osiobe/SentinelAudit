# SentinelAudit — Fixes

Running log of fixes applied to the project. Each entry records what was wrong, what changed, and why.

Status legend: `[ ]` planned · `[~]` in progress · `[x]` done

---

## Priority queue

### P1 — Correctness & honesty
- [x] **Reconcile loader story with reality.** Loopback server is now hardened (loopback `Host` check, per-launch URL token from `secrets.token_urlsafe`, GET/HEAD-only, `allow_reuse_address=False`). DevTools is auto-disabled in frozen builds. README rewritten to describe the actual loader.
- [x] **Authoritative score from backend.** `fix_finding` / `rollback_fix` now return `hardening_score` computed by `compute_hardening_score` over the backend-cached findings; client-side `recomputeScore` removed.
- [x] **Persist rollback state.** Rollback cache now persists to `%LOCALAPPDATA%\SentinelAudit\rollback.json` (atomic write via temp + rename), loads on startup. `run_audit` returns `rollback_available_finding_ids`; UI gates the Rollback button on that set instead of a per-session details flag.
- [x] **Unified session info.** Backend emits `session: { remaining_s, expired }` on every privileged response (success and error). Frontend uses one `isSessionExpired()` helper; the four ad-hoc `session_expired` checks are gone.

### P2 — Accessibility
- [x] **Accessible dialog primitive for all nine modals.** New `<Dialog>` component handles `role`, `aria-modal`, `aria-labelledby`, focus trap, Escape, return-focus, prefers-reduced-motion. Every modal (disclaimer, preview, login, setup, change-login, bulk, pin/access, exit-confirm, rollback-confirm, idle warning) now uses it.
- [x] **Wrap login / setup / change-password / pin in `<form>`.** Enter submits, primary buttons are `type="submit"`.
- [x] **Visible focus rings.** Added CSS-level `:focus-visible` outline for `input`/`textarea`/`select` that overrides Tailwind's `outline-none`. Buttons/links/`role="button"` were already covered.
- [x] **`prefers-reduced-motion` honoured everywhere.** Dialog reads `useReducedMotion`. `motion.section` in App.tsx and the finding-card / details-panel motion in `ResultsFeed.tsx` now strip `initial`/`animate`/`layout`/transition timing when reduced motion is on. Unused `motionProps` removed.
- [x] **Contrast lifted.** `text-white/35` and `/40` → `/65`; `text-white/50` → `/70` across `App.tsx` and `ResultsFeed.tsx`.
- [x] **Status not by color alone.** Status pills in `ResultsFeed` now lead with `✓ / ✕ / ?`. Dashboard PASS/FAIL/UNK tiles have the same glyphs. Password strength meter has a "Very weak / Weak / Fair / Strong / Very strong" text label and a `role="status" aria-live="polite"` wrapper.
- [x] **Live region for error banner.** Outer banner div wrapped with `role="alert" aria-live="assertive" aria-atomic="true"`.
- [x] **Idle-timeout warning.** New `keep_session_alive` backend method returns `{session}`. Frontend `<Dialog>` shows "Still there?" at ≤120s remaining with a live countdown and a "Stay signed in" button that calls `keepSessionAlive()`.
- [x] **Persist disclaimer acceptance** via `localStorage['sentinelaudit.disclaimer.v1'] = 'accepted'`.

### P3 — Coverage, ops & polish
- [x] **Update README "Top 10" claim** — README now lists the actual 19 checks.
- [x] **Stream findings as they complete** — `start_audit` worker thread + `get_audit_progress` polling; UI renders findings incrementally with a `Scanning… N/M` counter.
- [x] **Cancel button during bulk fix** — "Stop After Current Fix" sets a cancel ref checked between items.
- [x] **Header overflow** — Check Updates and Change Login collapsed into a `⋯` overflow menu.
- [x] **Disable `debug=True`** in `webview.start` for shipped builds. (Done in P1.1: `debug_enabled = not frozen`.)
- [ ] **Per-check unit tests** for `fix()` paths and registry helpers — currently only 3 test files for the whole tool.
- [x] **Lockout counter persistence** — verified: rate-limit state lives in `HKLM\SOFTWARE\SentinelAudit\Auth` (registry, survives restart), not RAM. PIN verification now shares the same lockout mechanism under `Pin*`-prefixed values.
- [ ] **Tamper-evident audit log** — `append_remediation_audit_log` writes plain local file. Consider Windows Event Log or signed append-only format if used for compliance.

---

## Applied fixes

<!-- Each entry: title, files touched, before/after summary, rationale. Newest at top. -->

### Production-readiness batch (2026-06-12, second pass)

**Files:** `app/main.py`, `sentinelaudit/windows.py`, `sentinelaudit/models.py`, `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, `frontend/src/components/ResultsFeed.tsx`, new `frontend/src/components/PasswordStrength.tsx`, `README.md`.

1. **Audit gated behind authentication.** The dashboard previously rendered (and the audit ran) before login, with only a blurred modal hiding it. Now `boot()` only fetches admin status + access policy; the audit starts after a successful login/setup (or immediately when not elevated, where no login exists). The main content doesn't render at all until authenticated.
2. **Streaming audit.** New `start_audit()` runs checks on a worker thread; `get_audit_progress()` returns incremental serialized findings plus an interim score. The UI polls every 300 ms and renders findings as each check completes with a `Scanning… N/M` counter. `run_audit` kept for compatibility.
3. **Export matches the screen and respects the session.** `export_excel` now exports the cached `_last_findings` (including applied fixes) instead of re-running the whole audit, and requires a live session when elevated. Frontend handles the session-expired response.
4. **PIN rate limiting.** `verify_remediation_pin_detailed` reuses the login lockout (5 fails / 10 min window, exponential 30 s → 1 h) under `Pin*`-prefixed registry values; `verify_pin` returns `retry_after_s` and the UI shows the lockout countdown.
5. **PIN dialog no longer re-prompts on every Run Audit** — the Run Audit button only re-runs the audit; it no longer re-fetches policy and resets `accessDismissed`/`remediationUnlocked`.
6. **Per-item Apply in bulk remediation.** Each finding row in the bulk modal has an "Apply This Fix" button and a `✓ FIXED` badge once applied; "Apply All (N)" applies only the remaining items; "Stop After Current Fix" cancels mid-run.
7. **Password strength logic deduplicated** into `PasswordStrength.tsx` (`pwStrengthError` + `<PasswordStrengthMeter>`), replacing one function and two inline rule blocks in `App.tsx`; rules mirror the backend's `_validate_password_strength`.
8. **`datetime.utcnow()` → `datetime.now(timezone.utc)`** in `models.py` (deprecation slated for removal).
9. **Header overflow menu** (`⋯`): Check Updates and Change Login moved out of the button row.
10. **README check list** updated from "Top 10" to the actual 19 checks.

### UI correctness batch (2026-06-12, first pass)

**Files:** `frontend/src/index.css` (+ deleted `frontend/tailwind.config.ts`), `frontend/src/App.tsx`, `frontend/src/components/Dialog.tsx`, `frontend/src/components/ResultsFeed.tsx`.

1. **Tailwind v4 theme never loaded.** `@import "tailwindcss"` (v4) ignores `tailwind.config.ts`, so every custom utility (`neon-*`, `bg-bg-*`, `shadow-neon`) compiled to nothing — the shipped CSS had zero theme styles. Tokens moved to an `@theme` block in `index.css`; dead config deleted.
2. **Setup modal appearing after the login modal.** `boot()` never read `setup_required` from the access policy, so the login modal always showed first on fresh installs and flipped to setup later. Boot now syncs `loginSetupRequired`.
3. **Password field lost focus after one keystroke.** `Dialog`'s focus effect depended on the inline `onClose` prop, re-running on every parent render and re-focusing the first focusable element. Callbacks now flow through refs; the effect runs only on open/close transitions.
4. **Result cards color-coded by status** — thick colored left edge + stronger border/tint: red = Fail, green = Pass, amber = Unknown.
5. Pre-existing `react-hooks/set-state-in-effect` lint error fixed (idle-warning reset moved out of the effect body).

### P2 — Accessibility pass

**Files:** new `frontend/src/components/Dialog.tsx`; modified `frontend/src/App.tsx`, `frontend/src/components/ResultsFeed.tsx`, `frontend/src/lib/api.ts`, `frontend/src/index.css`, `app/main.py`.

**Before:** Six (actually nine) modals were bare `<div>` overlays — no `role="dialog"`, no focus management, no Escape handling. Inputs hardcoded `outline-none` with no replacement focus indicator. Status was conveyed by color alone. Idle expiry happened silently. Disclaimer reshowed every launch.

**After (in one batch):**

1. **`<Dialog>` primitive** (`frontend/src/components/Dialog.tsx`)
   - Renders an overlay + a `role="dialog" aria-modal="true" aria-labelledby` container.
   - Focus trap via Tab/Shift+Tab keydown handling; initial focus on first focusable element after `requestAnimationFrame`; return-focus-to-trigger on close.
   - `closeOnEsc` (default true) and `closeOnBackdrop` (default false) opt-outs.
   - Honors `useReducedMotion` — strips the fade-in `initial`/`animate` when reduced motion is on.

2. **All nine modals refactored** to use `<Dialog>` with proper `labelledBy` ids on each `<h1>`/`<h2>`:
   `disclaimer`, `preview`, `setup-login`, `login`, `change-login`, `bulk-remediation`, `access-pin`, `exit-confirm`, `rollback-confirm`, plus a new `idle-warning` dialog.
   - Disclaimer / setup-login / login set `closeOnEsc={false}` (no escape hatch when those are the gate).
   - Bulk modal sets `closeOnEsc={!bulkModal?.applying}` so Escape can't dismiss mid-apply.

3. **Auth flows are real `<form>` elements.** Login, setup-login, change-login, and pin-access use `<form onSubmit={...}>` so Enter submits. Primary buttons are `type="submit"`.

4. **Visible focus rings.** Added a CSS rule in `index.css` for `html input:focus-visible, html textarea:focus-visible, html select:focus-visible { outline: 2px solid rgba(34,211,238,0.55); outline-offset: 2px; }`. Higher specificity than Tailwind's `outline-none` utility, so no need to rip `outline-none` out of every input.

5. **`prefers-reduced-motion` consistently honoured.**
   - `App.tsx`'s `motion.section` and `Dialog`'s overlay strip motion props when `useReducedMotion()` returns true.
   - `ResultsFeed.tsx`'s finding-card and details-panel motion (`layout`, `initial`, `animate`, `exit`, transition duration) all gated on `!reduceMotion`.
   - Unused `motionProps` variable removed.

6. **Contrast.** Bulk replacements: `text-white/35` and `text-white/40` → `text-white/65`; `text-white/50` → `text-white/70`. Covers all `text-xs font-mono` labels in `App.tsx` and `ResultsFeed.tsx`.

7. **Non-color status indicators.**
   - Status pill in `ResultsFeed` now leads with `✓` / `✕` / `?` (decorative `aria-hidden`).
   - Dashboard PASS/FAIL/UNK tiles in `App.tsx` get the same glyphs.
   - Password-strength meter shows a text label ("Very weak" → "Very strong") next to the colored bar, and the whole block is wrapped in `role="status" aria-live="polite"` so screen readers announce strength changes.

8. **Live region for the error banner.** The conditional banner is now wrapped in a persistent `<div role="alert" aria-live="assertive" aria-atomic="true">` so SRs announce errors that appear after page load.

9. **Idle-timeout warning + `keep_session_alive`.**
   - Backend: new `DesktopApi.keep_session_alive()` method gated by `_require_session()`, returns `{ok, session}`. Added to the `exposed_methods` tuple alongside the previously-not-exposed `set_initial_login`.
   - Frontend: `keepSessionAlive` wrapper in `lib/api.ts`. New `idleWarning` state in `App.tsx`; the existing idle-tick interval now triggers a `<Dialog>` ("Still there?") at ≤120 s remaining with a 1-second countdown, a "Stay signed in" button (calls `keepSessionAlive`, resets `lastActiveRef`), and a "Sign out now" button. Effect dependency cleaned up so the timer doesn't tear down each tick.

10. **Disclaimer persistence** via `window.localStorage.setItem('sentinelaudit.disclaimer.v1', 'accepted')` on the "I Understand" button; same key checked in the `useState` initializer to skip the disclaimer on subsequent launches.

**Rationale:** A11y was the largest correctness gap once the P1 honesty/correctness items were closed. The dialog primitive in particular eliminates a whole class of bugs (no focus trap means Tab cycles through the underlying app; no Escape handler means keyboard-only users are stuck; no return-focus means screen readers and keyboard users lose their place after every dialog interaction). Bundling the rest of the a11y work into the same batch keeps the visual style consistent and means one round of QA covers them all.

**Tradeoff acknowledged:** The disclaimer is now per-machine, not per-version. If the legal copy changes materially, bump the storage key (`v1` → `v2`) to re-prompt — currently this is manual.

**Not done in this batch:**
- Header overflow / secondary-action menu (P3 item, not a11y).
- Per-finding cancel during bulk fix (P3 item).
- True portal-style rendering for `<Dialog>` (currently renders inline in the tree). The focus trap and overlay z-50 cover the practical cases, but for full DOM isolation we'd `createPortal` to `document.body`.

---

### P1.4 — Unified session info on every privileged response

**Files:** `app/main.py`, `frontend/src/lib/api.ts`, `frontend/src/App.tsx`

**Before:** The backend signalled session expiry via an ad-hoc `session_expired: true` boolean on error responses, with two different envelope shapes (`change_login` returned `{ok: false, ...}`, the rest returned bare `{error, session_expired}`). The frontend handled this with four scattered checks, including a `'session_expired' in res` membership test and a type-narrowed cast.

**After:** Every privileged response (success or error) now carries `session: { remaining_s, expired }`, produced by a new `_session_info()` helper. The frontend exports `isSessionExpired(res)` and uses it in every callsite — `submitChangeLogin`, `openPreview`, `applyFix`, `applyBulkRemediation`, `confirmRollback`. Same single source of truth across both ends.

**Rationale:** Two error shapes plus a string-key membership check is exactly the kind of inconsistency that introduces session-handling bugs. One field, one helper.

---

### P1.3 — Persist rollback state to disk

**Files:** `app/main.py`, `frontend/src/lib/api.ts`, `frontend/src/App.tsx`, `frontend/src/components/ResultsFeed.tsx`

**Before:** `DesktopApi._rollback_cache` lived only in process memory. Closing the app silently discarded all rollback options. The UI showed the Rollback button based on `finding.details.rollback_supported`, a flag that was only set transiently by `check.fix()` — meaning the button never appeared on a fresh launch, even if rollback data had once existed.

**After:**
- `_rollback_storage_path()` resolves to `%LOCALAPPDATA%\SentinelAudit\rollback.json`.
- `_load_rollback_cache` runs in `DesktopApi.__init__` and rehydrates the in-memory cache.
- `_save_rollback_cache` writes via temp-file + `os.replace` for atomicity, and is called after every cache mutation in `fix_finding` and `rollback_fix`. Successful rollback clears the entry.
- `run_audit` returns `rollback_available_finding_ids: string[]`. `App.tsx` stores it as a `Set<string>` and passes it to `ResultsFeed`, which now shows the Rollback button if-and-only-if the id is in that set. The set is updated locally after fix (add) and rollback (remove) so the UI stays in sync without re-running the full audit.

**Rationale:** A Rollback button that links to nothing is worse than no button. Persisting closes the gap; surfacing it through a dedicated field keeps the UI's truth aligned with the backend's.

**Tradeoff acknowledged:** Plain JSON in `%LOCALAPPDATA%`. The contents are registry paths and prior values — descriptive of the system's previous config, not secret per se. DPAPI encryption is a worthwhile follow-up if this tool ever handles more sensitive remediation state.

---

### P1.2 — Authoritative hardening score from the backend

**Files:** `app/main.py`, `frontend/src/lib/api.ts`, `frontend/src/App.tsx`

**Before:** Backend computed the score via `compute_hardening_score` (in `engine.py`), but after a fix or rollback the frontend recomputed it client-side with a simple `passed / decided` ratio. If the engine ever moved to a weighted/risk-based score, the gauge would silently lie post-remediation.

**After:**
- `DesktopApi` now caches `_last_findings` (populated by `run_audit`).
- A `_splice_finding_and_score(updated)` helper replaces the cached entry by `finding_id` and returns the engine-computed score.
- `fix_finding` and `rollback_fix` return `{finding, hardening_score, session}`.
- Frontend `App.tsx` uses `res.hardening_score` directly in all three callsites (single fix, bulk fix, rollback) and the `recomputeScore` function is removed entirely. Unused `Finding` import dropped.

**Rationale:** The engine is the only place that should be allowed to compute the score. Any client-side recomputation is a permanent invitation to drift.

---

### P1.1 — Hardened loopback static server + README reconciliation

**Files:** `app/main.py`, `README.md`

**Before:** `app/main.py:14-31` opened `socketserver.TCPServer(("127.0.0.1", 0), ...)` with `allow_reuse_address=True`, served the built bundle at `http://127.0.0.1:<port>/index.html`, and started PyWebView with `debug=True` — DevTools shipped in the packaged exe. The README in two places (lines 12, 44) claimed there was no local HTTP server and the UI loaded via `file://`.

**After:**
- `_start_local_server` now returns `(port, token)`. The token is `secrets.token_urlsafe(24)`, generated once per launch.
- The handler overrides `send_head` (covering both GET and HEAD): rejects requests whose `Host` header isn't loopback (403), rejects paths not under `/<token>/...` (404), strips the prefix before delegating to `SimpleHTTPRequestHandler`. Explicit `do_POST` returns 405.
- `_LoopbackServer` sets `allow_reuse_address = False`.
- Window loads `http://127.0.0.1:<port>/<token>/index.html`.
- `webview.start(..., debug=debug_enabled)` where `debug_enabled = not getattr(sys, "frozen", False)` — DevTools off in PyInstaller builds.
- README rewritten with a "How the UI is served" section that describes the actual loader truthfully.

**Rationale:** Lying in the threat-model section of a security tool's README is worse than the underlying issue. The actual loader was also under-defended: any local process could fetch the bundle via simple port guessing. Token-gating closes that, and disabling DevTools in shipped builds removes an unintended capability from end-users.

**Note left for later:** A future hardening would generate the token in the WebView2 fragment instead of the path, or use a Unix-domain-socket-equivalent on Windows (named pipe + PyWebView shim). Out of scope for P1.

---

## Notes / decisions

<!-- Cross-cutting decisions that affect multiple fixes go here (e.g. which dialog library, where AppData lives, token format). -->

_None yet._
