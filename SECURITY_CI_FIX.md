# Security scan and package layout correction

Prepared against GitHub commit `9e87102e36d8b1966bcbf1beadf4ee746f7b0d26`.

## What changed

- Restored the `sentinelaudit/` package. The uploaded root modules and audit/reporting/services directories broke the application's package imports.
- Replaced silent exception handlers with contextual logging that does not print secrets, command output or credential values.
- Validated command arguments/timeouts, explicitly disabled shell execution and restricted audit executables to approved Windows tools resolved through `GetSystemDirectoryW` (not PATH or the working directory).
- Added rule-specific Bandit explanations for reviewed subprocess use, a finding-status label and a deliberate redaction test marker. No global rule skips, lowered severity thresholds or `continue-on-error` were added. Generated artifacts/dependencies are excluded from first-party scanning; build_exe.py and tests remain scanned.
- Fixed Python lint violations and unused imports without changing the audit findings schema; refreshed shared-engine hashes. Before copying this revised engine into Client, use its documented synchronization tool and rerun its tests.
- Changed CI to Node 22 to match frontend requirements.
- Split security scanning into independent source/Python/frontend jobs. Dependency failures no longer disappear behind `|| true`; Python auditing installs the application's dependencies on Windows, and npm auditing checks the locked dependency tree.
- Updated the frontend lockfile using compatible dependency fixes, including the reported high-severity Zod finding. Moderate development-tool dependency findings remain; no forced breaking downgrade was applied.

## Validation performed locally

- Bandit 1.9.4: zero unsuppressed findings, including the build script and tests.
- Ruff: passed.
- Portable Python suite: 29 tests passed, including subprocess validation and build recipe invocation with mocks.
- Frontend lint and production build: passed.
- `pip-audit -r requirements.txt`: no known vulnerabilities in the resolved Linux dependency set. Windows-specific transitive dependencies are checked by the Windows job, not validated by this local result.
- `npm audit --audit-level=high`: exit 0; 10 moderate dependency findings remain in development tooling.

The Windows CI run, native OS APIs, installed EXE and hosted Actions jobs have not been executed from this workspace. Local tests mock native Windows operations. This patch has not been pushed to GitHub.

## Apply through GitHub Desktop

Download `SentinelAudit-remaining-ci-fix.patch`. Open a terminal in the local SentinelAudit Git repository (the directory containing `.git` and README.md). With Git installed, run:

```powershell
git apply --check "$env:USERPROFILE\Downloads\SentinelAudit-remaining-ci-fix.patch"
git apply "$env:USERPROFILE\Downloads\SentinelAudit-remaining-ci-fix.patch"
```

Adjust the file path if the download is elsewhere. The check must succeed first; do not force a patch that reports conflicting changes. In GitHub Desktop, review the moved files and modifications, commit with summary `Fix security scans and restore package layout`, then Push origin. GitHub Actions will start on the new commit; rerunning the old failed commit does not include these corrections.

The corrected source ZIP is an alternative for manual use. Simply overlaying it on the old flattened repository is insufficient: remove the old root `audit/`, `reporting/`, `services/`, `__init__.py`, `activity.py`, `models.py`, `posture.py`, `sync.py`, and `windows.py` after verifying their restored counterparts inside `sentinelaudit/`. Preserve the repository's `.git` directory and any unrelated local work.
