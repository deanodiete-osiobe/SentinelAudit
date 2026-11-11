# Scan, audit trail and optional Admin sync

## Standalone operation

SentinelAudit remains a local Windows desktop application. Local accounts, scans, remediation previews and Excel exports do not require an Admin server or an installed Client. Existing credentials are preserved; no accounts or runtime data are bundled. The standalone app does not become a fleet login console.

Run Audit shows the current check and completed/total checks. Cancel scan requests cooperative cancellation: the active Windows check finishes or reaches its existing command timeout, then no new check starts. It does not forcibly kill arbitrary Windows processes. Partial findings remain visible and are clearly labelled cancelled; export and sync require a completed scan. A failed check is Unknown, with guidance to inspect permissions/services/policy; it is never converted into Pass. A worker-level failure ends progress with an actionable error.

Exports use the completed local findings, including subsequent local changes, without secretly starting another scan. The file is written to a temporary file and atomically replaced. Successful saves, cancellations and failures have distinct feedback. Changes made by remediation invalidate fleet sync until a fresh audit; this prevents sending an old scan as evidence that a fix succeeded. Run Audit again after applying changes.

## Tamper-evident activity

The per-user file `%LOCALAPPDATA%\SentinelAudit\activity-ledger.sqlite3` records scan start/completion/cancellation/failure, report and registry-export requests/outcomes, and sync requests/queuing. Records contain the local actor, time, sequence, previous hash and SHA-256 hash. Completed reports/exports include a content digest. Raw passwords, enrollment credentials and BitLocker recovery material are not put into these activity records.

The chain is verified before writing; a local receipt detects tail deletion when that receipt survives. Verification failures preserve the file and block new scan/export activity instead of silently replacing evidence. Check free space and directory permissions for storage failures. For integrity failures, preserve the ledger and compare it with an independently retained trusted copy; restore through an administrator-approved recovery process. No automatic reset or destructive repair is provided. The ledger has a roughly 256 MiB capacity guard; archive/rotation is an administrative task.

Verify the ledger from source:

```powershell
python -m sentinelaudit.activity
# Or verify a copied ledger:
python -m sentinelaudit.activity --path C:\Evidence\activity-ledger.sqlite3
```

This is tamper evidence, not tamper prevention or digital signing. A privileged attacker who replaces both history and local checkpoint can evade local-only verification. Independently retain trusted copies/head hashes for stronger assurance. This desktop ledger is not automatically uploaded to Admin and does not detect arbitrary Windows Event Log clearing. The Client's separate enterprise ledger remains a separate component.

## Optional synchronization: explicit local handoff

1. Install the accompanying System Agent Client on the same Windows PC and enroll it with your central Admin server. Confirm it is collecting data normally. Use the updated Client package to keep engine version `sentinel-integrated-2` aligned.
2. Run SentinelAudit as Administrator and sign in locally. Elevated access is required to write into the Client's protected ProgramData queue; it is not required solely for ordinary offline export.
3. Complete a scan, then select **Sync last scan to Admin**. This queues that completed scan only. Synchronization is opt-in per scan; there is no automatic upload toggle or hidden background transfer from SentinelAudit.
4. Keep Client running. Client uses its existing identity, API key and TLS/mTLS configuration to deliver the report to `/api/posture`. SentinelAudit does not ask for a server password or copy credentials into JavaScript.
5. In Admin, open Security posture and match the endpoint, collection time and finding results. **Queued locally does not mean received by Admin.** A stopped/paused/offline Client may delay delivery; resume/reconnect it as appropriate.

The fixed handoff directory is `%ProgramData%\SystemAgentClient\posture`. Pending reports are atomically published using their UUID run IDs. Repeated queuing of the same run is idempotent while present. The backend also deduplicates retained run IDs. If the 32-report queue is full, SentinelAudit rejects the handoff without deleting existing reports. The updated Client also refuses new reports at capacity instead of pruning old evidence, and retains rejected reports for administrator review. This is bounded buffering, not unlimited lossless replication.

Only the shared allowlisted findings schema is queued: schema/engine version, run ID, collection time, finding ID/name/status/risk and selected simple observations. Raw command output, detailed account lists, local application accounts, rollback caches and UI state are excluded. A desktop-context audit may differ from a service-context audit for user-dependent checks. Admin's latest report can later be superseded by a newer scheduled Client audit.

## Engine alignment

The shared engine and `sentinelaudit/posture.py` serializer are byte-aligned with the Client bundle. `engine-manifest.json` and the Client's `sentinel-core-manifest.json` record the reviewed file hashes. Desktop-only activity/sync bridge code is intentionally outside the shared engine.

Maintainers can check alignment from the System Agent root:

```powershell
python tools/sync_sentinel_core.py --source ..\SentinelAudit-main
# After reviewing intentional engine changes:
python tools/sync_sentinel_core.py --source ..\SentinelAudit-main --write
```

Advance the shared engine version for behavior changes, run both test suites and rebuild both executables. A source update does not modify an already installed executable.

## Validation and Windows pilot

Portable tests cover progress, duplicate-start exclusion, cooperative cancellation, session gates, error-to-Unknown handling, report allowlisting, export success/cancel/failure records, modified/truncated ledgers, queue conflicts/capacity and credential exclusion. Browser fixtures exercise cancellation, partial-result restrictions, queue feedback, exports and responsive layout. These are not live Windows checks.

Before release, test on a Windows VM: cancel during a slow check; verify no later checks start; rerun and export; simulate a denied export destination; verify the ledger; queue a report with Client stopped, start Client and confirm it in Admin; test queue-full/authentication failures; and compare standalone/Client finding IDs and collection times. Test the packaged EXE and elevated/service permissions. No production deployment or GitHub push was performed.
