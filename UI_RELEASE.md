# Security workspace redesign — 2.3.0 candidate

This release implements the six prioritized changes in the existing Python/React applications. It preserves the previous monitoring, response, enrollment and local-remediation capabilities. Read these notes before the older integration notes where behavior differs.

## What changed

1. **Visual foundation:** coordinated graphite surfaces and teal accents, consistent spacing, quieter borders, responsive tables/navigation, readable typography, explicit focus states and reduced-motion support. The admin workspace supports the existing light theme. SentinelAudit remains a dark desktop interface; its minimum native window size is now 620 × 580.
2. **Status clarity:** distinguishes queued requests, claimed/running requests awaiting results, collection failures, local completion with upload pending, received reports and stale evidence. Coverage remains adjacent to the technical score. Scheduled audits do not stream live progress to the server; without a command result or new report, the UI cannot know their current local state. Local SentinelAudit explicitly identifies its results as local.
3. **Endpoint workspace:** the Endpoints tab inside Security posture combines identity, connectivity, posture, latest CPU/memory/disk sample, events, command history and inventory. Refreshes use the existing authenticated profile API. Legacy fleet-management tools remain available through the main navigation.
4. **Evidence and guidance:** finding dialogs show observed result, collection time, stale warnings, curated rationale and recommendations. New agent reports can include an explicit allowlist of scalar measurements for BitLocker, firewall and password-policy checks. Other checks display status-only evidence and direct the analyst to local SentinelAudit for detail. Raw output, credentials and recovery passwords remain excluded. Server validation independently enforces the allowlist; viewer access is required to read reports.
5. **Finding workflows:** deferred search, result/risk/workflow filters, sorting and 25-row pagination. Analysts/admins can set a free-text owner/team label, acknowledge a finding or record an exception with a reason and expiry within 365 days. Exceptions expire at the selected UTC date's end of day and automatically become effectively open. They do not alter technical findings or scores. Optimistic revisions reject stale edits with HTTP 409. Changes are transactionally retained in posture_triage_history and recorded in the existing admin audit log. Viewer controls are disabled and the server rejects unauthorized writes.
6. **Actionable overview:** cards link to high-risk failures excluding active exceptions, pass-to-fail regressions, missing/stale endpoints and failed audit requests. The attention queue opens finding investigations. Evidence-health figures show received-check coverage and unknown results. Regressions compare the latest two retained endpoint reports; they are not a general historical trend model.

The admin opens in the new Security posture workspace. The original monitoring dashboard remains available. SentinelAudit adds clickable summary filters, search, result/risk filters, sorting and an explicit Preview fix action without changing remediation authorization.

## Deployment

Back up the database first. Deploy the server source, including `server/posture_catalog.json`, and rebuilt admin frontend. Startup adds `posture_triage` and `posture_triage_history`. There are no destructive schema migrations. The admin PyInstaller spec now includes the frontend build and guidance catalog.

Rebuild and pilot the Windows agent to enable the new safe observations. Old reports remain readable and show that detailed measurements were not uploaded. Report schema stays backward-compatible at version 1. The agent identifies itself as 2.3.0 and retains signed-update checks. No installer, service, update or site was published during this work.

Build each frontend with Node 22.12+ using `npm ci` then `npm run build`. For backend testing, install the existing requirements and run `python -m unittest discover -s tests -v` in System Agent. In SentinelAudit run `python tests/run_portable.py`.

## Validation

- 53 System Agent tests pass, including six added workflow/evidence tests covering authorization, revision conflicts, exception expiry, history, invalid input, measurement filtering, regressions and upload acknowledgment state.
- 12 SentinelAudit portable tests pass; Windows APIs are mocked on Linux.
- Both TypeScript/Vite production builds and Python compilation pass.
- Playwright exercised both actual React applications with synthetic API/desktop-bridge fixtures at widths 1440, 768 and 390. No page-wide horizontal overflow or uncaught page errors remained in those checks.
- Admin browser checks covered summary filtering, finding workflow submission, endpoint telemetry rendering and audit requests. Local browser checks covered summary filters, search, no-results feedback and remediation preview. Screens were visually inspected; a mobile header overflow and compressed local finding layout were fixed.
- Browser fixtures are isolated in `tests/browser/*.cjs`; no fixture data or fake authentication is included in application code. To rerun, install Playwright in a development environment and its Chromium browser. Optionally set CHROMIUM_EXECUTABLE to an installed compatible Chromium executable. Scripts launch Vite and write temporary QA outputs into `qa/` from the current directory.

This is not a formal accessibility audit or a fleet-scale benchmark. Native Windows WebView/SCM behavior, actual Windows evidence, installation, remediation and signed rollout still require a Windows pilot. The first fleet API still caps reporting endpoints at 1,000; findings pagination currently limits rendering rather than server-side retrieval. Owners are labels, not a user-directory integration; no email notifications are sent. The admin audit screen exposes the workflow audit events; the new transactional history table does not yet have a dedicated timeline UI.
