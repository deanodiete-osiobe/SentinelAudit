# Clean-start and live-telemetry update

## What is now different

Admin desktop mode now offers first-account creation when its runtime database has no users. The first account is an administrator; later accounts are managed by an authenticated administrator. Setup is restricted to the desktop process, direct loopback connections, an approved local Host/Origin and JSON requests. Forwarded/proxy requests are refused. A database transaction allows only one concurrent first-account request to succeed. Existing accounts are never overwritten, and setup does not grant a session or bypass configured MFA. Headless production deployment retains the explicit bootstrap procedure.

SentinelAudit already supports one local application credential per Windows profile. Its README now explains Credential Manager, legacy credential migration and runtime logging. No account database or credential file is distributed. Client does not have human sign-up: an administrator enrolls the device, which receives its own credential.

Metrics now defaults to a rolling two-minute window with a smoothly advancing time axis, pause/resume, History, sample inspection and age feedback. Every plotted value is received telemetry. There are no synthetic points or invented fluctuations. Missing readings are not converted to zero. Stale data eventually leaves the live window, and reduced-motion and hidden-window behavior are respected. Data acquisition still polls every two seconds: animation is not a claim of server push delivery or millisecond measurement resolution. A sub-second spike between measurements may not be captured.

Both READMEs explain frontend/backend/storage responsibilities, communication, runtime locations, first installation versus upgrade behavior and how to run/build the applications.

## Validation

65 System Agent backend tests and 12 SentinelAudit portable tests passed. New tests cover first-account creation, salted password verification, existing-account preservation, remote/cross-origin/proxy rejection, production-mode refusal, input validation and concurrent setup. The updated Admin TypeScript/Vite build passed; the Sentinel frontend is unchanged from its previously successful build.

Browser fixtures passed first-account creation/confirmation and existing-account behavior at 1440, 768 and 390 pixels. The broader Admin suite passed all eight views and six Security sections, live time-axis movement, pause/resume, History, two-second polling, hidden-window pause, endpoint selection retention, role management, search, theme changes and login layout. Fixtures do not validate Windows Credential Manager, native elevation or real device delivery.

Archive checks reject runtime databases, logs, credentials, private keys and local environment files. Test fixture identities are synthetic and not loaded by the application. Real runtime data remains outside the ZIP. Reinstalling deliberately preserves data already present on the PC.

## Next security priorities

1. Tamper-evident audit evidence with remote append-only retention or independently signed checkpoints. A local hash chain alone cannot prevent an administrator from rewriting the whole chain. Include verification on export and alert on missing/modified records. Reference: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
2. Correlate multiple endpoint events into an incident, document each rule's logic and map appropriate detections to MITRE ATT&CK. Validate with benign simulations, test false positives and expose the underlying evidence.
3. Sign public Windows binaries and installers, publish checksums, and extend the existing CI with Windows first-run/build smoke tests. Artifact signing verifies publisher/content; it does not certify that the software has no vulnerabilities. Reference: https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control

These are proposed next steps, not features implemented in this update. Existing controls include roles, session revocation, optional configured email MFA, authenticated agent enrollment, validated posture evidence and signed-update verification. The project remains an endpoint monitoring/posture platform with investigation features; it is not a replacement for a mature SIEM or EDR product. Perform a Windows pilot and realistic fleet-load validation before a production binary release.
