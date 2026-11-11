> Update: standalone completed scans can now be explicitly handed to the local enrolled Client. See [SCAN_AND_SYNC.md](SCAN_AND_SYNC.md) for this workflow and its limits. The existing scheduled-agent audit flow below remains available.

# SentinelAudit integration — System Agent 2.2.0 candidate

## What each application does

SentinelAudit is the local Windows audit and remediation UI. System Agent supplies endpoint identity, background collection, authenticated transport, central storage, administrator access and the fleet dashboard. The agent now includes the same reviewed SentinelAudit check sources, without launching the desktop UI or using its login credentials.

This is an implemented source integration, not a deployed or Windows-certified release. There are 19 baseline checks, not a general-purpose EDR, vulnerability scanner or CIS certification engine. Results are endpoint self-reports, not hardware attestation.

## How synchronization works

1. Install the updated agent on a Windows endpoint and enroll it with the existing server enrollment flow. The agent service runs independently of the SentinelAudit window.
2. A read-only audit starts 15–60 seconds after a first start, then about every six hours with up to five minutes of jitter. A persisted last-audit timestamp reduces restart storms. Only one audit/upload worker runs at a time. Individual commands retain their own timeouts; the audit process has a 180-second deadline. A failed audit is logged and retried after 15 minutes; no fabricated successful report is uploaded.
3. The agent writes the completed report atomically into its protected `posture` directory before attempting upload. Reports contain a schema version, engine version, UUID run ID, UTC collection time and finding IDs/names/status/risk. Raw evidence, recovery passwords and local credentials are excluded by an explicit field allowlist.
4. An independent HTTP session posts reports to `POST /api/posture` using the enrolled X-API-Key and existing TLS verification. The server derives client identity from that key, validates the payload, and recomputes score and coverage. Admin sessions protect `GET /api/posture`.
5. Offline reports survive agent restarts and are retried during the monitoring loop (normally around every 10 seconds). The same run ID is preserved until acknowledgment. Identical duplicate uploads are accepted; conflicting reuse is rejected. Delayed uploads cannot replace newer audit state in the dashboard.
6. The new Posture tab refreshes every 15 seconds. It shows score, coverage, counts, detailed status rows, collection time, receipt time and a stale warning after 12 hours.
7. An administrator with the existing response-control permissions can request `run_posture_audit`. This uses the existing audited action queue, claim/expiry rules and result reporting. Completion means collection finished and was saved locally; the command result explicitly says whether upload remains pending. If another worker is active, the request fails with a busy message and can be retried.
8. A user applies a local fix through SentinelAudit's existing preview/apply/rollback workflow. The next scheduled or requested agent audit observes the changed Windows settings. No desktop database, login, rollback file or live UI state is synchronized. No remote remediation was added.

Service-context and desktop-context findings may differ for user-dependent checks. Use the same engine revision and compare collection times before treating a difference as drift. Updating the standalone application alone does not update the agent's vendored checks.

## Score and reliability limits

- Score = passed / (passed + failed), rounded to 0–100. Unknowns are excluded; coverage = (passed + failed) / total. A score of 100 with low coverage is not a secure-system guarantee.
- Each endpoint retains the newest 32 pending reports. Oldest reports are pruned with a log warning when full. Disk failure can prevent saving; this is logged and the audit is retried. This is bounded buffering, not unlimited lossless historical replication.
- Invalid JSON and permanent 400/409/413 rejections are quarantined locally as `.rejected`, capped at 32 files, so they cannot block valid later uploads. Authentication failures and temporary server failures retain reports for retry. Check logs and enrollment/TLS configuration if receipt times stop advancing.
- The server retains 100 reports per endpoint. Deduplication applies to retained runs. Latest-state selection uses endpoint collection time, not arrival order; endpoint clocks must be synchronized. Timestamps more than five minutes in the future are rejected.
- The initial fleet API returns at most 1,000 endpoint reports. There is no historical-report UI or export route in this increment; history is retained in SQLite for future use.
- A compromised administrator or endpoint can falsify state. The integration does not implement signed attestation, automatic remediation, alert correlation for posture regressions, or cross-device policy reconciliation.

## Review and optimization delivered

SentinelAudit: fixed two syntax-breaking indentation defects; prevented an HTTP thread from keeping the app alive after UI exit; removed raw BitLocker protector output; corrected partial-firewall and TLS tri-state assessment; replaced the password-complexity registry assumption with a temporary security-policy export; prevented minimum-password remediation from lowering an already stronger policy; added coverage; made developer debugging opt-in; refreshed vulnerable frontend dependencies.

System Agent: isolated audits and network uploads from telemetry; bounded audit runtime and queue sizes; added idempotent authenticated storage and indexed latest-report lookup; shared the existing action-result outbox lock across network sessions; added the fleet Posture page and read-only audit command; advanced reported agent/update version to 2.2.0. Server changes are additive and older agents remain supported.

The vendored MIT license is preserved at `Client App/sentinelaudit/LICENSE`. `Client App/sentinel-core-manifest.json` records SHA-256 hashes of all integrated Python engine files. A test detects accidental drift from that manifest. When changing checks, review the standalone source, copy the changed engine into the client, update the manifest and engine version, rebuild both applications and rerun tests. The manifest is a maintenance check, not a cryptographic publisher signature.

## Deployment

1. Back up the server database using the existing supported procedure. Stop the server before replacing its source. Follow `PRODUCTION_DEPLOYMENT.md` for production HTTPS, canonical origin, authentication and reverse-proxy configuration.
2. Install server dependencies and build the admin frontend (`npm ci`, `npm run build`; Node 22.12+). Starting the updated server creates the additive posture table/index automatically. Deploy the server first so agents have a compatible destination.
3. On a Windows build host, install `Client App/requirements.txt`, including Pydantic 2.14.0. Build using the existing `Client App/SystemAgentClient.spec` workflow. The spec includes the audit engine and Pydantic; the executable uses multiprocessing freeze support for its audit worker. This packaging path requires Windows validation.
4. Test the new executable on one enrolled pilot endpoint before fleet rollout. If using the existing signed updater, publish a properly signed 2.2.0 manifest and package; never bypass the existing signature checks. No update was published as part of this work.
5. Build/run the accompanying SentinelAudit desktop package separately. It does not need a server URL or agent key. Do not copy its credentials or recovery material into the server.
6. Confirm a report in Posture, disconnect networking, run another audit, restart the agent, reconnect and verify eventual delivery. Apply a local fix, request a fresh audit, and verify the corresponding status changes.

If rolling back server source, stop it and restore the previous code/DB backup using existing procedures. Pending agent reports will remain buffered if `/api/posture` is unavailable, subject to the queue cap. Rolling back an EXE through the signed updater is intentionally blocked by version checks; use the documented controlled recovery procedure.

## Validation performed

- 47 System Agent tests pass, including existing real HTTP/Waitress integration and new WSGI posture tests for authentication, identity binding, field allowlisting, server scoring, coverage, duplicate/conflicting retries, delayed arrivals, retention, stale state and the admin command queue.
- Agent unit tests cover persistent offline reports, acknowledgment deletion, concurrent-worker exclusion, bounded retention, rejected-record quarantine and vendored source hashes.
- 12 SentinelAudit tests pass with Windows registry APIs mocked on Linux, including BitLocker secret exclusion, incomplete firewall profiles, TLS client/server uncertainty and stronger-password-policy preservation.
- Both TypeScript/Vite production builds pass. SentinelAudit's updated npm audit reports zero known vulnerabilities at validation time.
- Python compilation passes. Test output is included in `docs/validation/integration/`.

Not validated here: live Windows command outputs across editions/languages; PyWebView runtime behavior; a built Windows executable's child-process launch; service install/start/stop under SCM; real on-host remediation/rollback; signed update rollout; high-volume fleet load; endpoint ACLs under domain deployment. Complete these on Windows before calling the combined system production-ready. The source review was targeted, not exhaustive.

Technical references used for the Windows changes:
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export
