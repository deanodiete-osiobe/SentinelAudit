# SentinelAudit

## Scan layout correction — 24 October 2026

The hardening score now occupies its own centered row. Scan progress/current-check text and sync messages appear in separate wrapping blocks, including narrow windows. Duplicate pass/fail/unknown cards were removed from the sidebar because these counts already appear above. Scores are marked provisional during scanning. The matching Client update preserves older queued reports instead of pruning them at capacity. See `SCAN_AND_SYNC.md` for integration and remaining limitations.


## Scan control, activity trail and optional Admin sync

This update aligns the shared audit engine and fleet report serializer with System Agent Client (`sentinel-integrated-2`). It adds the current-check display, cooperative Cancel scan, clearer failure guidance, a tamper-evident scan/export activity ledger, and an explicit **Sync last scan to Admin** action through an enrolled local Client. Offline scans and Excel exports remain available without Admin.

See [Scan, audit trail and optional synchronization](SCAN_AND_SYNC.md) for setup, privacy limits, verification, engine maintenance and Windows testing. Partial/cancelled scans cannot be exported or uploaded as complete audits. Queued reports are not shown as confirmed Admin receipt. Rebuild both desktop executables to apply the source updates.


SentinelAudit is a Windows security posture auditing application with a React interface in a native pywebview desktop window. It runs local checks, displays findings and coverage, previews supported fixes, and exports Excel reports. Supported remediation and rollback operations require appropriate Windows privileges and application authentication.

The engine version is 0.2.0. This source package includes the coordinated System Agent 2.3 security workspace UI changes; those product version numbers are separate.

## First launch: create your own account

There is no shared username/password to distribute. Launch with **Run as administrator**, open the tray window if needed, and accept the usage notice. A Windows profile without an existing SentinelAudit credential sees **Create your free local account**. Choose a username and a password of at least 12 characters with uppercase, lowercase, a number and a symbol, then confirm it.

No payment, email or cloud registration is required. This creates one local application credential for the Windows profile using Windows Credential Manager; it does not create a Windows user or a System Agent account. Passwords are salted and hashed. Existing installations keep their credentials and show sign-in instead of setup. Change those credentials through the authenticated account controls; reinstalling does not intentionally erase them.

After account creation, an audit starts and the **How to use SentinelAudit** guide opens. Reopen it any time with **How to use** in the header. It covers findings, unknown results, coverage, fix previews, backups, rollback, exports and account access. Read-only/standard-user behavior and elevation requirements are unchanged.

## Architecture and stored data

| Layer | How it works |
| --- | --- |
| Frontend (`frontend/src`) | React/TypeScript interface rendered in a native pywebview window. Calls the exposed Python bridge for audits, account operations, fix previews and exports. |
| Backend (`app/main.py`, `sentinelaudit`) | Python runs Windows checks, evaluates evidence, computes score/coverage, validates application sessions and coordinates authorized remediation. A standalone audit does not upload reports to System Agent automatically. |
| Storage | There is **no application SQL database** in standalone SentinelAudit. The local login uses Windows Credential Manager with a salted password hash. Older installations may migrate legacy registry credentials. Reports/backups are saved to a location selected by the user; remediation audit logs and supported rollback state are runtime files. |

Data flow: React requests an audit → the Python bridge runs Windows checks → findings/progress return to React → the user reviews evidence and chooses whether to export or apply a supported change. Windows elevation and application authentication still govern privileged operations.

The ZIP contains no saved account, previous password, runtime log or user report. A fresh Windows profile creates its own application credential. **Reinstalling or extracting a newer ZIP does not erase credentials already stored on that PC.** Existing credentials belong to that installation/profile and are intentionally preserved. Use a new Windows profile/VM to test first-run setup safely.

Elevated remediation audit logs normally live under `%ProgramData%/SentinelAudit/logs`; user-context logs may use `%LOCALAPPDATA%` or `%APPDATA%`. These files and Credential Manager entries are separate from the source archive. Do not include them in a GitHub release. The System Agent Admin account/database and Client device enrollment are separate from SentinelAudit's local login.

## Capabilities

- Local Windows configuration checks, severity and result filters, searchable findings and sorting.
- Hardening score displayed alongside coverage and unknown results.
- Explicit fix previews, supported remediation and saved rollback state.
- Excel reporting, registry backups, tray operation and session controls.

A separate copy of the engine is bundled in System Agent Client for read-only scheduled fleet audits. Reports flow from that agent to the authenticated System Agent API and Admin console. The standalone desktop app does not automatically upload its reports. See [integration notes](SYSTEM_AGENT_INTEGRATION.md) and [UI release notes](UI_RELEASE.md).

## Run from source on Windows

Prerequisites: Python 3.12, Node.js 22.12+ and Microsoft Edge WebView2 Runtime. In PowerShell from this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
python app/main.py
```

Run elevated when privileged checks or remediation are needed. Elevated launches can start in the tray; use the tray icon to open the window. Developer tools are opt-in with `SENTINEL_DEBUG=1` for source launches and disabled in frozen builds.

## Build a Windows desktop application

From the activated environment:

```powershell
python build_exe.py
```

Output: `dist/SentinelAudit/SentinelAudit.exe`. Distribute the **entire** `dist/SentinelAudit` directory, including `_internal`, not just the executable. The checked-in `SentinelAudit.spec` bundles the frontend and assets. The application preserves standard-user launch behavior; use Run as administrator when needed.

No prebuilt or signed executable is included. Building dependencies requires network access; local audit execution does not require a cloud service. See [Windows build and pilot guide](WINDOWS_BUILD.md).

## Validation and limits

Run `python tests/run_portable.py` for 12 portable tests with mocked Windows APIs. The prior release also passed the frontend production build and browser fixture checks. These checks do not validate native Windows evidence, elevation, WebView2, registry changes, installers or rollback on real machines. A controlled Windows pilot remains required before production rollout.

## Export feedback

Exports now display a consistent success notification. See [export feedback behavior and validation](EXPORT_FEEDBACK.md).

## Final source update validation

The final onboarding/access update passed 60 System Agent backend tests, 12 SentinelAudit portable tests, both production frontend builds and browser workflow checks. See [final source release notes](FINAL_RELEASE.md). Native Windows validation is still required before distributing rebuilt binaries.

## Clean-start and live telemetry update

See [current update, validation and security roadmap](CLEAN_START_RELEASE.md). The latest backend suite passes 65 System Agent tests; 12 SentinelAudit portable tests also pass. Native Windows validation remains required.
