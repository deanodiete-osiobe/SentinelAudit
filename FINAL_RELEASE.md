# Final source release: onboarding, live telemetry and user access

## Changes

- SentinelAudit's existing Windows Credential Manager setup is now presented as free local account creation with a personal username and password. The prefilled Admin username was removed. Existing credentials are preserved.
- The new in-app guide opens after setup and can be reopened from How to use. It explains assessments, coverage, unknowns, remediation previews, backups, rollback, exports and account boundaries.
- Admin polls dashboard/activity data and active Metrics every two seconds while visible. Background requests are sequential; hidden-window refreshes pause, and stale Metrics responses are ignored.
- Fresh Client configurations sample telemetry every two seconds. Existing interval settings are preserved. Event and posture schedules remain separate; this is polling, not push delivery.
- Metrics now uses the actual hours filter, capped at 600 latest samples. Previously the API assumed twelve samples per hour. This cap bounds transfer and chart rendering; it is not historical aggregation.
- Background dashboard updates no longer reset the selected endpoint. Responses from canceled background dashboard effects are discarded.
- Administrators can change roles and delete users with confirmation. The API rechecks actor privileges inside a database transaction, preserves the last administrator, prevents self-removal/self-role changes, and revokes target sessions and pending OTPs.
- Role explanations appear in Security and the signed-in role appears in the header. New users default to Viewer. Non-admin accounts do not receive account-management controls.
- Bootstrap credentials only create an account in an empty account database, preventing deleted bootstrap users from being recreated on subsequent starts.
- README and runbook instructions updated. Existing export-success/error/cancellation behavior retained. Desktop build recipes remain distributable in source control.

## Validation performed

- System Agent: 60 Python tests passed, including seven new user-access/telemetry tests and the HTTP enrollment/telemetry/response integration test.
- SentinelAudit: 12 portable tests passed with Windows APIs mocked.
- Both TypeScript/Vite production builds passed.
- Browser fixtures passed: first account setup, automatic guide, reopening the guide, report export success/cancel/error, Admin export download/error feedback, role edit, delete/cancel, and own-account protection.
- Admin browser checks passed at 1440, 768 and 390 pixels across all eight views and six Security sections. Checks cover chart keyboard inspection, two-second refresh, retained endpoint selection, hidden-window polling pause, error feedback, theme changes, search, enrollment and login layout. No browser page errors were recorded.

Run `python -m unittest discover -s tests -v` in System Agent. Run `python tests/run_portable.py` in SentinelAudit. Frontends use `npm ci` then `npm run build`. Browser scripts are under `tests/browser`; they require Playwright and Chromium, with `CHROMIUM_EXECUTABLE` available for a custom browser path. Browser APIs/desktop bridges use synthetic fixtures.

## Before a public binary release

Rebuild all changed Windows executables. Test account creation in a fresh Windows profile, existing-account sign-in, Credential Manager persistence, native export dialogs, elevation and remediation on an expendable Windows machine. Verify an enrolled Windows agent produces new samples, then test changing and deleting a second fleet account. Confirm revoked sessions cannot read or mutate data. Check the desired interval on upgraded clients.

Native Windows packaging, WebView2/elevation, actual endpoint collection, signed installers and large-fleet load were not validated in this Linux session. This is a tested source release candidate, not an unconditional production certification. The faster sampling rate increases storage and traffic; tune interval and retention for the deployment. Metrics displays up to 600 samples, and the existing fleet query cap remains 1,000 endpoints.

Do not commit runtime databases, local environment secrets, credentials, exports, caches or private keys. Use the documented production TLS/MFA setup for network deployments. No GitHub publication or binary signing was performed.
