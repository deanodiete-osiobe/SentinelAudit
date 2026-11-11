export type RiskLevel = 'Low' | 'Medium' | 'High'
export type FindingStatus = 'Pass' | 'Fail' | 'Unknown'

export interface Finding {
  finding_id: string
  name: string
  risk_level: RiskLevel
  status: FindingStatus
  description: string
  details: Record<string, unknown>
  fix_available: boolean
  last_checked_utc: string
}

export interface AuditResult {
  hardening_score: number
  findings: Finding[]
  generated_utc: string
  rollback_available_finding_ids?: string[]
}

export interface AuditProgress {
  cancelled?: boolean
  cancelling?: boolean
  current_check?: string
  error?: string
  running: boolean
  done: boolean
  total: number
  completed: number
  hardening_score: number
  findings: Finding[]
  generated_utc?: string
  rollback_available_finding_ids?: string[]
}

export interface AdminStatus {
  is_admin: boolean
  version?: string
}

export interface AccessPolicy {
  pin_required: boolean
  session_timeout_s?: number
  setup_required?: boolean
}

export interface SessionInfo {
  remaining_s: number
  expired: boolean
}

export function isSessionExpired(res: unknown): boolean {
  const s = (res as { session?: { expired?: boolean } } | null | undefined)?.session
  return s?.expired === true
}

type DesktopBridge = {
  get_admin_status: () => Promise<AdminStatus>
  get_access_policy: () => Promise<AccessPolicy>
  verify_pin: (pin: string) => Promise<{ ok: boolean; retry_after_s?: number }>
  verify_login: (
    username: string,
    password: string,
  ) => Promise<{
    ok: boolean
    error?: string
    retry_after_s?: number
    session_timeout_s?: number
    setup_required?: boolean
  }>
  set_initial_login: (
    username: string,
    password: string,
  ) => Promise<{ ok: boolean; error?: string; session_timeout_s?: number }>
  change_login: (
    current_password: string,
    new_username: string,
    new_password: string,
  ) => Promise<{ ok: boolean; error?: string; session?: SessionInfo }>
  keep_session_alive: () => Promise<{ ok?: boolean; error?: string; session?: SessionInfo }>
  run_audit: () => Promise<AuditResult>
  start_audit: () => Promise<{ ok: boolean; already_running?: boolean; error?: string }>
  get_audit_progress: () => Promise<AuditProgress>
  fix_finding: (
    finding_id: string,
  ) => Promise<
    | { finding: Finding; hardening_score: number; session?: SessionInfo }
    | { error: string; session?: SessionInfo }
  >
  preview_fix: (finding_id: string) => Promise<{
    supported?: boolean
    is_admin?: boolean
    changes?: string[]
    rollback_supported?: boolean
    error?: string
    session?: SessionInfo
  }>
  rollback_fix: (
    finding_id: string,
  ) => Promise<
    | { finding: Finding; hardening_score: number; session?: SessionInfo }
    | { error: string; session?: SessionInfo }
  >
  cancel_audit: () => Promise<{ ok: boolean; message?: string }>
  sync_last_audit: () => Promise<{ queued?: boolean; message?: string; error?: string; warning?: string }>
  export_excel: () => Promise<{ saved_to: string | null; warning?: string; error?: string; session?: SessionInfo }>
  backup_registry: () => Promise<{ saved_to: string | null; error?: string }>
  open_updates_page: () => Promise<{ ok: boolean; error?: string; url?: string }>
  set_tray_score: (score: number) => Promise<{ ok: boolean }>
  exit_app: () => Promise<{ ok: boolean }>
}

declare global {
  interface Window {
    pywebview?: { api: DesktopBridge }
  }
}

function desktopApi(): DesktopBridge | null {
  return window.pywebview?.api ?? null
}

function isDesktopBridgeReady(d: DesktopBridge | null): d is DesktopBridge {
  return (
    !!d &&
    typeof (d as unknown as { get_admin_status?: unknown }).get_admin_status === 'function' &&
    typeof (d as unknown as { get_access_policy?: unknown }).get_access_policy === 'function' &&
    typeof (d as unknown as { verify_pin?: unknown }).verify_pin === 'function' &&
    typeof (d as unknown as { verify_login?: unknown }).verify_login === 'function' &&
    typeof (d as unknown as { set_initial_login?: unknown }).set_initial_login === 'function' &&
    typeof (d as unknown as { change_login?: unknown }).change_login === 'function' &&
    typeof (d as unknown as { run_audit?: unknown }).run_audit === 'function' &&
    typeof (d as unknown as { start_audit?: unknown }).start_audit === 'function' &&
    typeof (d as unknown as { get_audit_progress?: unknown }).get_audit_progress === 'function' &&
    typeof (d as unknown as { fix_finding?: unknown }).fix_finding === 'function' &&
    typeof (d as unknown as { preview_fix?: unknown }).preview_fix === 'function' &&
    typeof (d as unknown as { rollback_fix?: unknown }).rollback_fix === 'function' &&
    typeof (d as unknown as { export_excel?: unknown }).export_excel === 'function' &&
    typeof (d as unknown as { backup_registry?: unknown }).backup_registry === 'function' &&
    typeof (d as unknown as { open_updates_page?: unknown }).open_updates_page === 'function' &&
    typeof (d as unknown as { set_tray_score?: unknown }).set_tray_score === 'function' &&
    typeof (d as unknown as { exit_app?: unknown }).exit_app === 'function'
  )
}

async function waitForDesktopApi(timeoutMs = 6000): Promise<DesktopBridge> {
  const existing = desktopApi()
  if (isDesktopBridgeReady(existing)) return existing

  return await new Promise<DesktopBridge>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      cleanup()
      reject(new Error('Desktop bridge not ready (pywebview.api methods missing).'))
    }, timeoutMs)

    const interval = window.setInterval(() => {
      const d = desktopApi()
      if (isDesktopBridgeReady(d)) {
        cleanup()
        resolve(d)
      }
    }, 50)

    const onReady = () => {
      const d = desktopApi()
      if (isDesktopBridgeReady(d)) {
        cleanup()
        resolve(d)
      }
    }

    function cleanup() {
      window.clearTimeout(timeout)
      window.clearInterval(interval)
      window.removeEventListener('pywebviewready', onReady)
    }

    window.addEventListener('pywebviewready', onReady)
  })
}

export async function getAdminStatus(): Promise<AdminStatus> {
  return (await waitForDesktopApi()).get_admin_status()
}

export async function getAccessPolicy(): Promise<AccessPolicy> {
  return (await waitForDesktopApi()).get_access_policy()
}

export async function verifyPin(pin: string): Promise<{ ok: boolean; retry_after_s?: number }> {
  return (await waitForDesktopApi()).verify_pin(pin)
}

export async function verifyLogin(
  username: string,
  password: string,
): Promise<{
  ok: boolean
  error?: string
  retry_after_s?: number
  session_timeout_s?: number
  setup_required?: boolean
}> {
  return (await waitForDesktopApi()).verify_login(username, password)
}

export async function setInitialLogin(
  username: string,
  password: string,
): Promise<{ ok: boolean; error?: string; session_timeout_s?: number }> {
  return (await waitForDesktopApi()).set_initial_login(username, password)
}

export async function changeLogin(
  currentPassword: string,
  newUsername: string,
  newPassword: string,
): Promise<{ ok: boolean; error?: string; session?: SessionInfo }> {
  return (await waitForDesktopApi()).change_login(currentPassword, newUsername, newPassword)
}

export async function keepSessionAlive(): Promise<{ ok?: boolean; error?: string; session?: SessionInfo }> {
  return (await waitForDesktopApi()).keep_session_alive()
}

export async function runAudit(): Promise<AuditResult> {
  return (await waitForDesktopApi()).run_audit()
}

export async function startAudit(): Promise<{ ok: boolean; already_running?: boolean; error?: string }> {
  return (await waitForDesktopApi()).start_audit()
}

export async function getAuditProgress(): Promise<AuditProgress> {
  return (await waitForDesktopApi()).get_audit_progress()
}

type SessionError = { error: string; session?: SessionInfo }

export async function fixFinding(
  findingId: string,
): Promise<{ finding: Finding; hardening_score: number; session?: SessionInfo } | SessionError> {
  return (await waitForDesktopApi()).fix_finding(findingId)
}

export async function previewFix(findingId: string): Promise<{
  supported?: boolean
  is_admin?: boolean
  changes?: string[]
  rollback_supported?: boolean
  error?: string
  session?: SessionInfo
}> {
  return (await waitForDesktopApi()).preview_fix(findingId)
}

export async function rollbackFix(
  findingId: string,
): Promise<{ finding: Finding; hardening_score: number; session?: SessionInfo } | SessionError> {
  return (await waitForDesktopApi()).rollback_fix(findingId)
}

export async function exportExcel(): Promise<{ saved_to: string | null; warning?: string; error?: string; session?: SessionInfo }> {
  return (await waitForDesktopApi()).export_excel()
}

export async function backupRegistry(): Promise<{ saved_to: string | null; error?: string }> {
  return (await waitForDesktopApi()).backup_registry()
}

export async function openUpdatesPage(): Promise<{ ok: boolean; error?: string; url?: string }> {
  return (await waitForDesktopApi()).open_updates_page()
}

export async function setTrayScore(score: number): Promise<{ ok: boolean }> {
  return (await waitForDesktopApi()).set_tray_score(score)
}

export async function exitApp(): Promise<{ ok: boolean }> {
  return (await waitForDesktopApi()).exit_app()
}

export async function cancelAudit() { return (await waitForDesktopApi()).cancel_audit() }
export async function syncLastAudit() { return (await waitForDesktopApi()).sync_last_audit() }
