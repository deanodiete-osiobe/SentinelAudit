# Export feedback update

Successful exports display **Data exported successfully**.

SentinelAudit shows the saved path after its desktop bridge confirms Excel report or registry backup writing. Report cancellation displays Export cancelled; errors retain their error feedback without a success notification. The notification is accessible through a polite live region, can be dismissed and clears after eight seconds.

System Agent Admin uses one notification handler for JSON/CSV exports, endpoint and event details, audit diagnostics, command-search exports, support bundles and database backups. Its message identifies the filename and states that the download started. Browser/WebView downloads cannot confirm the user's final save location or whether a subsequent save dialog was cancelled. A failure starting a download produces Export failed. Duplicate per-screen success notifications were removed.

Validation: both production builds pass. Browser fixtures verify SentinelAudit report success/path, cancellation and failure; Admin checks verify the download event and filename, one success notification, and no new success notification on a forced download failure. Native Windows save dialogs still require user validation.

Rebuild SentinelAudit and System Agent Admin with `python build_exe.py` from each project's activated build environment. The endpoint Client does not need rebuilding for this change.
