# Windows executable build and pilot guide

## Build host

Build Windows artifacts on Windows using Python 3.12, Node.js 22.12+ for React builds and Microsoft Edge WebView2 Runtime for the two webview interfaces. Install the repository requirements inside a virtual environment. Python and Node are build dependencies; users of the packaged application do not need them installed. WebView2 is an external runtime prerequisite, not bundled by these specs.

Run `python build_exe.py` at the relevant project root. System Agent Client uses `Client App/build.bat`, which anchors its working directory and installs its requirements. Build scripts fail on errors; the Python wrappers reject non-Windows hosts. Close previous application instances before rebuilding. Builds never force-terminate a running Admin console.

| Application | Output | Distribution |
| --- | --- | --- |
| SentinelAudit | `dist/SentinelAudit/SentinelAudit.exe` | Complete SentinelAudit folder, including `_internal` |
| System Agent Admin | `dist/SystemAgentAdmin.exe` | Single executable plus deployment configuration |
| System Agent Client | `Client App/dist/SystemAgentClient.exe` | Single executable plus endpoint configuration |

The packages contain source and build configuration, not validated Windows binaries. No installer or signature was produced here. System Agent's existing release scripts can orchestrate installer/signing steps when their external tools and certificates are configured; validate those separately. Use the production deployment guide for a network server; the embedded desktop API is a local evaluation workflow.

## Required pilot before rollout

1. Build on a clean Windows machine and retain dependency versions and build logs. Review PyInstaller warnings for missing required modules.
2. Launch all three artifacts on a second Windows machine without Python or Node. Confirm WebView2 handling, icons, initial authentication, writable data locations and restart persistence. Open SentinelAudit from its tray if initially hidden.
3. Exercise standard-user and elevated SentinelAudit audits. Check real evidence against Windows settings; verify unknown results, Excel export, one approved fix and rollback on a disposable VM snapshot.
4. Enroll a test Client against a TLS-protected test server. Verify scheduled and requested audits, offline queue/reconnect, evidence filtering, deduplication and latest report rendering.
5. Confirm viewer/analyst/admin permissions, exception expiry, conflicting edits and audit history. Verify Client headless/service lifecycle and signed update acceptance/rejection using the deployment runbook.
6. Sign final release artifacts with the organization's certificate, verify signatures and hashes, and test installation/uninstallation and backup/restore before broader rollout.

Record actual results, OS/build architecture and blockers. Passing source tests does not mark this pilot complete.
