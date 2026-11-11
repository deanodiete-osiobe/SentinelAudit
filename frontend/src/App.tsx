import { motion, useReducedMotion } from 'motion/react'
import { ArrowClockwise, ArrowsClockwise, DotsThreeVertical, DownloadSimple, Eye, EyeSlash, Key, Lock, Wrench, X } from '@phosphor-icons/react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AdminOverlay } from './components/AdminOverlay'
import { Dialog } from './components/Dialog'
import { PasswordStrengthMeter } from './components/PasswordStrength'
import { ProgressGauge } from './components/ProgressGauge'
import { ResultsFeed } from './components/ResultsFeed'
import { pwStrengthError } from './lib/password'
import {
  backupRegistry,
  cancelAudit,
  syncLastAudit,
  changeLogin,
  exportExcel,
  exitApp,
  fixFinding,
  getAccessPolicy,
  getAdminStatus,
  getAuditProgress,
  isSessionExpired,
  keepSessionAlive,
  openUpdatesPage,
  previewFix,
  rollbackFix,
  startAudit,
  setTrayScore,
  setInitialLogin,
  verifyLogin,
  verifyPin,
  type AdminStatus,
  type AuditResult,
} from './lib/api'

function App() {
  const [adminStatus, setAdminStatus] = useState<AdminStatus | null>(null)
  const [loggedIn, setLoggedIn] = useState(false)
  const [loginSetupRequired, setLoginSetupRequired] = useState(false)
  const [loginUsername, setLoginUsername] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginPasswordVisible, setLoginPasswordVisible] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loginBusy, setLoginBusy] = useState(false)
  const [setupUsername, setSetupUsername] = useState('')
  const [setupPassword, setSetupPassword] = useState('')
  const [setupPassword2, setSetupPassword2] = useState('')
  const [setupPasswordVisible, setSetupPasswordVisible] = useState(false)
  const [setupPassword2Visible, setSetupPassword2Visible] = useState(false)
  const [setupError, setSetupError] = useState<string | null>(null)
  const [setupBusy, setSetupBusy] = useState(false)
  const [guideOpen, setGuideOpen] = useState(false)
  const [changeLoginOpen, setChangeLoginOpen] = useState(false)
  const [changeCurrentPassword, setChangeCurrentPassword] = useState('')
  const [changeNewUsername, setChangeNewUsername] = useState('Admin')
  const [changeNewPassword, setChangeNewPassword] = useState('')
  const [changeNewPassword2, setChangeNewPassword2] = useState('')
  const [changeCurrentVisible, setChangeCurrentVisible] = useState(false)
  const [changeNewVisible, setChangeNewVisible] = useState(false)
  const [changeNew2Visible, setChangeNew2Visible] = useState(false)
  const [changeLoginError, setChangeLoginError] = useState<string | null>(null)
  const [changeLoginBusy, setChangeLoginBusy] = useState(false)
  const [pinRequired, setPinRequired] = useState(false)
  const [remediationUnlocked, setRemediationUnlocked] = useState(true)
  const [accessDismissed, setAccessDismissed] = useState(false)
  const [pinInput, setPinInput] = useState('')
  const [pinError, setPinError] = useState<string | null>(null)
  const [sessionTimeoutS, setSessionTimeoutS] = useState(15 * 60)
  const lastActiveRef = useRef<number>(0)
  const [idleWarning, setIdleWarning] = useState<{ remainingS: number } | null>(null)
  const [audit, setAudit] = useState<AuditResult | null>(null)
  const [rollbackAvailableIds, setRollbackAvailableIds] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [busyFindingId, setBusyFindingId] = useState<string | null>(null)
  const [exportNotice, setExportNotice] = useState<{ title: string; detail: string } | null>(null)
  useEffect(() => {
    if (!exportNotice) return
    const timer = window.setTimeout(() => setExportNotice(null), 8000)
    return () => window.clearTimeout(timer)
  }, [exportNotice])
  const [exporting, setExporting] = useState(false)
  const [checkingUpdates, setCheckingUpdates] = useState(false)
  const [backupPending, setBackupPending] = useState(false)
  const [backupSavedPath, setBackupSavedPath] = useState<string | null>(null)
  const [bulkModal, setBulkModal] = useState<{
    items: Array<{
      findingId: string
      name: string
      supported: boolean
      changes: string[]
      applied?: boolean
      error?: string
    }>
    applying: boolean
    errors: string[]
  } | null>(null)
  const bulkCancelRef = useRef(false)
  const [auditProgress, setAuditProgress] = useState<{ completed: number; total: number } | null>(null)
  const [scanInterrupted, setScanInterrupted] = useState<'cancelled' | 'failed' | null>(null)
  const [currentCheck,setCurrentCheck] = useState('')
  const [cancelling,setCancelling] = useState(false)
  const [syncPending,setSyncPending] = useState(false)
  const [syncMessage,setSyncMessage] = useState('')
  const auditPollingRef = useRef(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [disclaimerAccepted, setDisclaimerAccepted] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem('sentinelaudit.disclaimer.v1') === 'accepted'
    } catch {
      return false
    }
  })
  const [exitConfirmOpen, setExitConfirmOpen] = useState(false)
  const [previewModal, setPreviewModal] = useState<{
    findingId: string
    supported: boolean
    changes: string[]
    rollbackSupported: boolean
    error?: string
  } | null>(null)
  const [rollbackConfirmId, setRollbackConfirmId] = useState<string | null>(null)

  const reduceMotion = useReducedMotion()

  // Elevated runs require the app login before any audit data is shown;
  // non-elevated runs have no login (AdminOverlay covers that mode).
  const authenticated = Boolean(adminStatus && (!adminStatus.is_admin || loggedIn))
  const [findingFilter, setFindingFilter] = useState("all")
  const score = useMemo(() => (audit ? audit.hardening_score : 0), [audit])
  const canRemediate = Boolean(adminStatus?.is_admin) && loggedIn && remediationUnlocked
  const fixableFailures = useMemo(
    () => (audit ? audit.findings.filter((f) => f.status === 'Fail' && f.fix_available) : []),
    [audit],
  )

  // Streams audit results: kicks off the backend worker, then polls progress
  // so findings render as each check completes instead of one big blob.
  async function runAuditNow() {
    if (auditPollingRef.current) return
    auditPollingRef.current = true
    setLoading(true)
    setError(null)
    try {
      setScanInterrupted(null); setCancelling(false); setSyncMessage('')
      const started = await startAudit()
      if (started.error || !started.ok) throw new Error(started.error || 'Audit could not start. Please retry.')
      for (;;) {
        const p = await getAuditProgress()
        setCurrentCheck(p.current_check || '')
        setCancelling(Boolean(p.cancelling))
        setAuditProgress({ completed: p.completed ?? 0, total: p.total ?? 0 })
        if ((p.findings?.length ?? 0) > 0 || p.done) {
          setAudit({
            hardening_score: p.hardening_score ?? 0,
            findings: p.findings ?? [],
            generated_utc: p.generated_utc ?? new Date().toISOString(),
          })
        }
        if (p.done) {
          if (p.cancelled) { setScanInterrupted('cancelled'); setError('Scan cancelled. Displayed findings are partial; run a complete audit before export or sync.') }
          else if (p.error) { setScanInterrupted('failed'); setError(p.error) }
          setRollbackAvailableIds(new Set(p.rollback_available_finding_ids ?? []))
          void setTrayScore(p.hardening_score ?? 0).catch(() => {})
          break
        }
        await new Promise((resolve) => window.setTimeout(resolve, 300))
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setAuditProgress(null); setCurrentCheck(''); setCancelling(false)
      setLoading(false)
      auditPollingRef.current = false
    }
  }

  async function submitLogin() {
    setLoginBusy(true)
    setLoginError(null)
    try {
      const res = await verifyLogin(loginUsername, loginPassword)
      if (!res.ok) {
        if (res.setup_required) {
          setLoginSetupRequired(true)
          setLoginError('Admin login is not configured yet. Set it up to continue.')
          return
        }
        if (typeof res.retry_after_s === 'number' && res.retry_after_s > 0) {
          setLoginError(`Locked out. Try again in ${res.retry_after_s}s.`)
        } else {
          setLoginError(res.error ?? 'Invalid login.')
        }
        return
      }
      if (typeof res.session_timeout_s === 'number' && res.session_timeout_s > 0) {
        setSessionTimeoutS(res.session_timeout_s)
      }
      setLoggedIn(true)
      lastActiveRef.current = Date.now()
      setIdleWarning(null)
      setLoginPassword('')
      setLoginError(null)
      // The audit is deferred until authentication so results never load
      // behind the login overlay.
      void runAuditNow()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setLoginError(msg)
    } finally {
      setLoginBusy(false)
    }
  }

  async function submitInitialSetup() {
    setSetupBusy(true)
    setSetupError(null)
    try {
      const pwErr = pwStrengthError(setupPassword)
      if (pwErr) { setSetupError(pwErr); return }
      if (setupPassword !== setupPassword2) {
        setSetupError('Passwords do not match.')
        return
      }
      const res = await setInitialLogin(setupUsername, setupPassword)
      if (!res.ok) {
        setSetupError(res.error ?? 'Setup failed.')
        return
      }
      if (typeof res.session_timeout_s === 'number' && res.session_timeout_s > 0) {
        setSessionTimeoutS(res.session_timeout_s)
      }
      setLoginSetupRequired(false)
      setLoggedIn(true)
      setGuideOpen(true)
      setLoginUsername(setupUsername.trim() || 'Admin')
      setLoginPassword('')
      setSetupPassword('')
      setSetupPassword2('')
      setSetupError(null)
      lastActiveRef.current = Date.now()
      setIdleWarning(null)
      void runAuditNow()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setSetupError(msg)
    } finally {
      setSetupBusy(false)
    }
  }

  async function submitChangeLogin() {
    setChangeLoginBusy(true)
    setChangeLoginError(null)
    try {
      const pwErr = pwStrengthError(changeNewPassword)
      if (pwErr) { setChangeLoginError(pwErr); return }
      if (changeNewPassword !== changeNewPassword2) {
        setChangeLoginError('New passwords do not match.')
        return
      }
      const res = await changeLogin(changeCurrentPassword, changeNewUsername, changeNewPassword)
      if (!res.ok) {
        if (isSessionExpired(res)) {
          setLoggedIn(false)
          setLoginError('Session expired. Please login again.')
          setChangeLoginOpen(false)
          return
        }
        setChangeLoginError(res.error ?? 'Change failed.')
        return
      }
      setLoginUsername(changeNewUsername.trim() || 'Admin')
      setChangeCurrentPassword('')
      setChangeNewPassword('')
      setChangeNewPassword2('')
      setChangeLoginError(null)
      setChangeLoginOpen(false)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setChangeLoginError(msg)
    } finally {
      setChangeLoginBusy(false)
    }
  }

  async function openPreview(findingId: string) {
    if (!audit) return
    setBusyFindingId(findingId)
    setError(null)
    try {
      const preview = await previewFix(findingId)
      if (isSessionExpired(preview)) {
        setLoggedIn(false)
        setLoginError('Session expired. Please login again.')
        return
      }
      setPreviewModal({
        findingId,
        supported: preview?.supported !== false,
        changes: Array.isArray(preview?.changes) ? preview.changes : [],
        rollbackSupported: preview?.rollback_supported === true,
        error: preview?.error,
      })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setBusyFindingId(null)
    }
  }

  async function doBackupRegistry() {
    setExportNotice(null)
    setBackupPending(true)
    try {
      const res = await backupRegistry()
      if (res.saved_to) {
        setBackupSavedPath(res.saved_to)
        setExportNotice({ title: "Data exported successfully", detail: `Registry backup saved to ${res.saved_to}` })
      } else if (res.error) {
        setError(`Registry backup failed: ${res.error}`)
      }
    } catch (e) {
      setError(`Registry backup failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setBackupPending(false)
    }
  }

  async function applyFix(findingId: string) {
    if (!audit) return
    setBusyFindingId(findingId)
    setError(null)
    try {
      const res = await fixFinding(findingId)
      if ('error' in res) {
        if (isSessionExpired(res)) {
          setLoggedIn(false)
          setLoginError('Session expired. Please login again.')
          return
        }
        throw new Error(res.error ?? 'Unable to apply fix.')
      }
      applyFixResult(findingId, res)
      setPreviewModal(null)
      setBackupSavedPath(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setBusyFindingId(null)
    }
  }

  async function openBulkRemediation() {
    if (!audit) return
    if (!canRemediate) return
    if (fixableFailures.length === 0) return

    setError(null)
    setBulkModal({
      items: [],
      applying: false,
      errors: [],
    })

    try {
      const items = await Promise.all(
        fixableFailures.map(async (f) => {
          try {
            const preview = await previewFix(f.finding_id)
            return {
              findingId: f.finding_id,
              name: f.name,
              supported: preview?.supported !== false,
              changes: Array.isArray(preview?.changes) ? preview.changes : [],
              error: preview?.error,
            }
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e)
            return {
              findingId: f.finding_id,
              name: f.name,
              supported: false,
              changes: [],
              error: msg,
            }
          }
        }),
      )
      setBulkModal({
        items,
        applying: false,
        errors: [],
      })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
      setBulkModal(null)
    }
  }

  function applyFixResult(findingId: string, res: { finding: AuditResult['findings'][number]; hardening_score: number }) {
    setAudit((prev) =>
      prev
        ? {
            ...prev,
            hardening_score: res.hardening_score,
            findings: prev.findings.map((f) => (f.finding_id === findingId ? res.finding : f)),
          }
        : prev,
    )
    setRollbackAvailableIds((prev) => {
      const next = new Set(prev)
      next.add(findingId)
      return next
    })
    void setTrayScore(res.hardening_score).catch(() => {})
  }

  function markBulkItem(findingId: string, patch: { applied?: boolean; error?: string }) {
    setBulkModal((prev) =>
      prev
        ? {
            ...prev,
            items: prev.items.map((it) => (it.findingId === findingId ? { ...it, ...patch } : it)),
          }
        : prev,
    )
  }

  async function applyBulkItem(findingId: string) {
    setBusyFindingId(findingId)
    try {
      const res = await fixFinding(findingId)
      if ('error' in res) {
        if (isSessionExpired(res)) {
          setLoggedIn(false)
          setLoginError('Session expired. Please login again.')
          setBulkModal(null)
          return
        }
        markBulkItem(findingId, { error: res.error ?? 'Unable to apply fix.' })
        return
      }
      applyFixResult(findingId, res)
      markBulkItem(findingId, { applied: true, error: undefined })
    } catch (e) {
      markBulkItem(findingId, { error: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusyFindingId(null)
    }
  }

  async function applyBulkRemediation() {
    if (!bulkModal) return
    const pending = bulkModal.items.filter((it) => !it.applied)
    if (pending.length === 0) return

    bulkCancelRef.current = false
    setBulkModal((prev) => (prev ? { ...prev, applying: true, errors: [] } : prev))

    const errs: string[] = []
    for (const it of pending) {
      if (bulkCancelRef.current) break
      setBusyFindingId(it.findingId)
      try {
        const res = await fixFinding(it.findingId)
        if ('error' in res) {
          if (isSessionExpired(res)) {
            setLoggedIn(false)
            setLoginError('Session expired. Please login again.')
            break
          }
          throw new Error(res.error ?? 'Unable to apply fix.')
        }
        applyFixResult(it.findingId, res)
        markBulkItem(it.findingId, { applied: true, error: undefined })
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e)
        errs.push(`${it.findingId}: ${msg}`)
        markBulkItem(it.findingId, { error: msg })
      }
    }
    setBusyFindingId(null)
    setBulkModal((prev) => (prev ? { ...prev, applying: false, errors: errs } : prev))
  }

  function rollbackOne(findingId: string) {
    setRollbackConfirmId(findingId)
  }

  async function confirmRollback(findingId: string) {
    setRollbackConfirmId(null)
    if (!audit) return
    setBusyFindingId(findingId)
    setError(null)
    try {
      const res = await rollbackFix(findingId)
      if ('error' in res) {
        if (isSessionExpired(res)) {
          setLoggedIn(false)
          setLoginError('Session expired. Please login again.')
          return
        }
        throw new Error(res.error ?? 'Unable to rollback fix.')
      }
      setAudit((prev) =>
        prev
          ? {
              ...prev,
              hardening_score: res.hardening_score,
              findings: prev.findings.map((f) => (f.finding_id === findingId ? res.finding : f)),
            }
          : prev,
      )
      setRollbackAvailableIds((prev) => {
        if (!prev.has(findingId)) return prev
        const next = new Set(prev)
        next.delete(findingId)
        return next
      })
      void setTrayScore(res.hardening_score).catch(() => {})
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setBusyFindingId(null)
    }
  }

  async function exportReport() {
    setExportNotice(null)
    setExporting(true)
    setError(null)
    try {
      const res = await exportExcel()
      if (isSessionExpired(res)) {
        setLoggedIn(false)
        setLoginError('Session expired. Please login again.')
        return
      }
      if (res.error) {
        setError(String(res.error))
        return
      }
      if (!res.saved_to) {
        setExportNotice({ title: 'Export cancelled', detail: 'No file was saved.' })
        return
      }
      setError(null)
      setExportNotice({ title: 'Data exported successfully', detail: `Excel report saved to ${res.saved_to}${res.warning ? '. ' + res.warning : ''}` })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setExporting(false)
    }
  }

  async function checkForUpdates() {
    setCheckingUpdates(true)
    setError(null)
    try {
      const res = await openUpdatesPage()
      if (!res.ok) {
        setError(res.error ?? 'Unable to open updates page.')
        return
      }
      setError(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setCheckingUpdates(false)
    }
  }

  async function confirmExit() {
    setError(null)
    try {
      const res = await exitApp()
      if (!res.ok) {
        window.close()
      }
    } catch {
      window.close()
    }
  }

  async function unlockRemediation() {
    setPinError(null)
    try {
      const res = await verifyPin(pinInput)
      if (!res.ok) {
        if (typeof res.retry_after_s === 'number' && res.retry_after_s > 0) {
          setPinError(`Too many failed attempts. Try again in ${res.retry_after_s}s.`)
        } else {
          setPinError('Invalid access code.')
        }
        return
      }
      setRemediationUnlocked(true)
      setPinInput('')
      setPinError(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setPinError(msg)
    }
  }

  useEffect(() => {
    let cancelled = false
    lastActiveRef.current = Date.now()

    async function boot() {
      try {
        const [adminRes, policyRes] = await Promise.all([getAdminStatus(), getAccessPolicy()])
        if (cancelled) return
        setAdminStatus(adminRes)
        setPinRequired(Boolean(policyRes.pin_required))
        setRemediationUnlocked(!policyRes.pin_required)
        setLoginSetupRequired(Boolean(policyRes.setup_required))
        if (typeof policyRes.session_timeout_s === 'number' && policyRes.session_timeout_s > 0) {
          setSessionTimeoutS(policyRes.session_timeout_s)
        }
        setAccessDismissed(false)
        if (adminRes.is_admin) {
          // Elevated runs require the app login; the audit starts after a
          // successful login/setup so no data loads behind the auth overlay.
          setLoading(false)
        } else {
          void runAuditNow()
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e)
        if (!cancelled) {
          setError(msg)
          setLoading(false)
        }
      }
    }

    void boot()

    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!loggedIn) return
    const warnAtS = 120
    const bump = () => {
      lastActiveRef.current = Date.now()
    }
    const evs: Array<keyof WindowEventMap> = ['mousemove', 'mousedown', 'keydown', 'touchstart']
    evs.forEach((e) => window.addEventListener(e, bump, { passive: true }))
    const timer = window.setInterval(() => {
      const idleMs = Date.now() - lastActiveRef.current
      const remainingS = Math.ceil((sessionTimeoutS * 1000 - idleMs) / 1000)
      if (remainingS <= 0) {
        setLoggedIn(false)
        setLoginError('Session timed out due to inactivity.')
        setIdleWarning(null)
        return
      }
      setIdleWarning((prev) => {
        if (remainingS <= warnAtS) {
          if (prev && prev.remainingS === remainingS) return prev
          return { remainingS }
        }
        return prev === null ? prev : null
      })
    }, 1000)
    return () => {
      evs.forEach((e) => window.removeEventListener(e, bump))
      window.clearInterval(timer)
    }
  }, [loggedIn, sessionTimeoutS])

  async function stayInSession() {
    try {
      const res = await keepSessionAlive()
      if (isSessionExpired(res)) {
        setLoggedIn(false)
        setLoginError('Session expired. Please login again.')
        setIdleWarning(null)
        return
      }
      lastActiveRef.current = Date.now()
      setIdleWarning(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    }
  }

  return (
    <div className="h-full">
      <div className="export-notice-region" aria-live="polite" aria-atomic="true">
        {exportNotice && <div className="export-notice"><div><strong>{exportNotice.title}</strong><p>{exportNotice.detail}</p></div><button type="button" aria-label="Dismiss export notification" onClick={() => setExportNotice(null)}><X size={18} /></button></div>}
      </div>
      <Dialog
        open={!disclaimerAccepted}
        onClose={() => {}}
        closeOnEsc={false}
        labelledBy="disclaimer-title"
      >
        <div className="w-[min(680px,92vw)] rounded-2xl border border-neon-amber/25 bg-bg-1/80 p-6 shadow-neon">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-sm font-mono tracking-widest text-neon-amber/80">
                DISCLAIMER
              </div>
              <h1 id="disclaimer-title" className="mt-2 text-2xl font-semibold text-white">Read before continuing</h1>
              <p className="mt-3 text-sm leading-6 text-white/75">
                SentinelAudit audits local Windows security settings. If you choose to apply fixes,
                it may change system configuration. Some checks and all remediation actions require
                administrator privileges.
              </p>
            </div>
            <div className="select-none rounded-xl border border-neon-amber/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-amber/80">
              SAFETY
            </div>
          </div>

          <div className="mt-5 flex flex-wrap justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                try { window.localStorage.setItem('sentinelaudit.disclaimer.v1', 'accepted') } catch { /* ignore */ }
                setDisclaimerAccepted(true)
              }}
              className="rounded-xl border border-neon-amber/30 bg-neon-amber/10 px-4 py-2 text-sm font-semibold text-neon-amber hover:bg-neon-amber/15"
            >
              I Understand
            </button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={previewModal !== null}
        onClose={() => setPreviewModal(null)}
        labelledBy="preview-title"
      >
        {previewModal ? (
        <div className="w-[min(760px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-cyan/80">PREVIEW CHANGE</div>
                <h2 id="preview-title" className="mt-2 text-xl font-semibold text-white">Proposed remediation</h2>
                <div className="mt-2 text-xs font-mono text-white/70">{previewModal.findingId}</div>
              </div>
              <button
                type="button"
                onClick={() => setPreviewModal(null)}
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/70 hover:bg-white/10"
              >
                Close
              </button>
            </div>

            {previewModal.error ? (
              <div className="mt-4 rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                {previewModal.error}
              </div>
            ) : null}

            {!previewModal.supported ? (
              <div className="mt-4 rounded-xl border border-neon-amber/25 bg-neon-amber/10 px-4 py-3 text-sm text-white/85">
                Preview is not available for this check. You can still apply the fix if you understand the risk.
              </div>
            ) : null}

            <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">
              {previewModal.changes.length > 0 ? (
                <ul className="list-disc space-y-2 pl-5 text-sm text-white/80">
                  {previewModal.changes.map((c, idx) => (
                    <li key={idx}>{c}</li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-white/70">No change details were provided.</div>
              )}
            </div>

            <div className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/5 px-4 py-3">
              <div className="text-sm">
                {backupSavedPath ? (
                  <span className="font-mono text-neon-green text-xs">✓ Backed up → {backupSavedPath}</span>
                ) : (
                  <span className="text-white/60">Back up affected registry keys before applying <span className="text-white/65">(recommended)</span></span>
                )}
              </div>
              <button
                type="button"
                disabled={backupPending}
                onClick={() => void doBackupRegistry()}
                className="shrink-0 rounded-xl border border-white/15 bg-white/5 px-3 py-1.5 text-xs font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10 disabled:opacity-50"
              >
                {backupPending ? 'Saving…' : backupSavedPath ? 'Save Again' : 'Save Backup…'}
              </button>
            </div>

            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => { setPreviewModal(null); setBackupSavedPath(null) }}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 hover:bg-white/10"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={busyFindingId === previewModal.findingId}
                onClick={() => void applyFix(previewModal.findingId)}
                className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan shadow-neon disabled:opacity-50"
              >
                {busyFindingId === previewModal.findingId ? 'Applying…' : 'Apply'}
              </button>
            </div>
          </div>
        ) : null}
      </Dialog>

      <Dialog
        open={!!(disclaimerAccepted && adminStatus?.is_admin && !loggedIn && loginSetupRequired)}
        onClose={() => {}}
        closeOnEsc={false}
        labelledBy="setup-title"
      >
        <form
          onSubmit={(e) => { e.preventDefault(); if (!setupBusy) void submitInitialSetup() }}
          className="w-[min(720px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon"
        >
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-cyan/80">INITIAL SETUP</div>
                <h2 id="setup-title" className="mt-2 text-xl font-semibold text-white">Create your free local account</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  Choose your own username and password. No payment, email or cloud registration is needed.
                  Your application credential is stored in Windows Credential Manager for this Windows profile.
                  This account protects elevated access to SentinelAudit; it does not create a Windows account.
                </p>
              </div>
              <div className="select-none rounded-xl border border-neon-cyan/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-cyan/80">
                SECURE
              </div>
            </div>

            <div className="mt-5 grid gap-3">
              <div>
                <label className="text-xs font-mono text-white/70">USERNAME</label>
                <input
                  value={setupUsername}
                  onChange={(e) => setSetupUsername(e.target.value)}
                  className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                  placeholder="Your username"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-white/70">PASSWORD</label>
                <div className="relative mt-2">
                  <input
                    value={setupPassword}
                    onChange={(e) => setSetupPassword(e.target.value)}
                    type={setupPasswordVisible ? 'text' : 'password'}
                    className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                    placeholder="12+ chars, upper, lower, number, symbol"
                  />
                  <button
                    type="button"
                    onClick={() => setSetupPasswordVisible((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                    aria-label={setupPasswordVisible ? 'Hide password' : 'Show password'}
                  >
                    {setupPasswordVisible ? <EyeSlash size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                <PasswordStrengthMeter password={setupPassword} />
              </div>
              <div>
                <label className="text-xs font-mono text-white/70">CONFIRM PASSWORD</label>
                <div className="relative mt-2">
                  <input
                    value={setupPassword2}
                    onChange={(e) => setSetupPassword2(e.target.value)}
                    type={setupPassword2Visible ? 'text' : 'password'}
                    className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                    placeholder="Repeat password"
                  />
                  <button
                    type="button"
                    onClick={() => setSetupPassword2Visible((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                    aria-label={setupPassword2Visible ? 'Hide password' : 'Show password'}
                  >
                    {setupPassword2Visible ? <EyeSlash size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {setupError ? (
                <div className="rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                  {setupError}
                </div>
              ) : null}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => void confirmExit()}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Exit
              </button>
              <button
                type="submit"
                disabled={setupBusy}
                className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan transition-all duration-200 hover:bg-neon-cyan/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:opacity-50"
              >
                {setupBusy ? 'Creating…' : 'Create account & get started'}
              </button>
            </div>
          </form>
      </Dialog>

      <Dialog
        open={!!(disclaimerAccepted && adminStatus?.is_admin && !loggedIn && !loginSetupRequired)}
        onClose={() => {}}
        closeOnEsc={false}
        labelledBy="login-title"
      >
        <form
          onSubmit={(e) => { e.preventDefault(); if (!loginBusy) void submitLogin() }}
          className="w-[min(680px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon"
        >
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-cyan/80">ADMIN LOGIN</div>
                <h2 id="login-title" className="mt-2 text-xl font-semibold text-white">Sign in to continue</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  SentinelAudit is running elevated. Enter the SentinelAudit admin login to access the hardening dashboard and remediation tools.
                </p>
              </div>
              <div className="select-none rounded-xl border border-neon-cyan/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-cyan/80">
                SECURE
              </div>
            </div>

            <div className="mt-5 grid gap-3">
              <div>
                <label className="text-xs font-mono text-white/70">USERNAME</label>
                <input
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                  placeholder="Your username"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-white/70">PASSWORD</label>
                <div className="relative mt-2">
                  <input
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    type={loginPasswordVisible ? 'text' : 'password'}
                    className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                    placeholder="Password"
                  />
                  <button
                    type="button"
                    onClick={() => setLoginPasswordVisible((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                    aria-label={loginPasswordVisible ? 'Hide password' : 'Show password'}
                  >
                    {loginPasswordVisible ? <EyeSlash size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
              {loginError ? (
                <div className="rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                  {loginError}
                </div>
              ) : null}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => void confirmExit()}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Exit
              </button>
              <button
                type="submit"
                disabled={loginBusy}
                className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan transition-all duration-200 hover:bg-neon-cyan/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:opacity-50"
              >
                {loginBusy ? 'Verifying…' : 'Login'}
              </button>
            </div>
          </form>
      </Dialog>

      <Dialog
        open={changeLoginOpen}
        onClose={() => setChangeLoginOpen(false)}
        labelledBy="change-login-title"
      >
        <form
          onSubmit={(e) => { e.preventDefault(); if (!changeLoginBusy) void submitChangeLogin() }}
          className="w-[min(720px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon"
        >
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-cyan/80">CREDENTIALS</div>
                <h2 id="change-login-title" className="mt-2 text-xl font-semibold text-white">Change admin login</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  Set the SentinelAudit admin username and password used to access this application on the client system.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setChangeLoginOpen(false)}
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10"
              >
                Close
              </button>
            </div>

            <div className="mt-5 grid gap-3">
              <div>
                <label className="text-xs font-mono text-white/70">CURRENT PASSWORD</label>
                <div className="relative mt-2">
                  <input
                    value={changeCurrentPassword}
                    onChange={(e) => setChangeCurrentPassword(e.target.value)}
                    type={changeCurrentVisible ? 'text' : 'password'}
                    className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                    placeholder="Current password"
                  />
                  <button
                    type="button"
                    onClick={() => setChangeCurrentVisible((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                    aria-label={changeCurrentVisible ? 'Hide password' : 'Show password'}
                  >
                    {changeCurrentVisible ? <EyeSlash size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-mono text-white/70">NEW USERNAME</label>
                <input
                  value={changeNewUsername}
                  onChange={(e) => setChangeNewUsername(e.target.value)}
                  className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                  placeholder="Your username"
                />
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <label className="text-xs font-mono text-white/70">NEW PASSWORD</label>
                  <div className="relative mt-2">
                    <input
                      value={changeNewPassword}
                      onChange={(e) => setChangeNewPassword(e.target.value)}
                      type={changeNewVisible ? 'text' : 'password'}
                      className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                      placeholder="12+ chars, upper, lower, number, symbol"
                    />
                    <button
                      type="button"
                      onClick={() => setChangeNewVisible((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                      aria-label={changeNewVisible ? 'Hide password' : 'Show password'}
                    >
                      {changeNewVisible ? <EyeSlash size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  <PasswordStrengthMeter password={changeNewPassword} />
                </div>

                <div>
                  <label className="text-xs font-mono text-white/70">CONFIRM PASSWORD</label>
                  <div className="relative mt-2">
                    <input
                      value={changeNewPassword2}
                      onChange={(e) => setChangeNewPassword2(e.target.value)}
                      type={changeNew2Visible ? 'text' : 'password'}
                      className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 pr-12 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-cyan/35"
                      placeholder="Confirm password"
                    />
                    <button
                      type="button"
                      onClick={() => setChangeNew2Visible((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 p-2 text-white/70 transition-colors duration-200 hover:bg-white/10"
                      aria-label={changeNew2Visible ? 'Hide password' : 'Show password'}
                    >
                      {changeNew2Visible ? <EyeSlash size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>
              </div>

              {changeLoginError ? (
                <div className="rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                  {changeLoginError}
                </div>
              ) : null}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setChangeLoginOpen(false)}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={changeLoginBusy}
                className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan transition-all duration-200 hover:bg-neon-cyan/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:opacity-50"
              >
                {changeLoginBusy ? 'Saving…' : 'Save'}
              </button>
            </div>
          </form>
      </Dialog>

      <Dialog
        open={bulkModal !== null}
        onClose={() => { if (bulkModal && !bulkModal.applying) setBulkModal(null) }}
        closeOnEsc={!bulkModal?.applying}
        labelledBy="bulk-title"
      >
        {bulkModal ? (
        <div className="w-[min(860px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-cyan/80">BULK REMEDIATION</div>
                <h2 id="bulk-title" className="mt-2 text-xl font-semibold text-white">Apply recommended fixes</h2>
                <div className="mt-2 text-sm text-white/70">
                  {bulkModal.items.length > 0
                    ? `${bulkModal.items.length} fixes detected`
                    : 'Collecting previews…'}
                </div>
              </div>
              <button
                type="button"
                disabled={bulkModal.applying}
                onClick={() => setBulkModal(null)}
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10 disabled:opacity-50"
              >
                Close
              </button>
            </div>

            {bulkModal.items.length > 0 ? (
              <div className="mt-4 max-h-[52vh] overflow-auto rounded-xl border border-white/10 bg-black/30 p-4">
                <div className="space-y-3">
                  {bulkModal.items.map((it) => (
                    <div
                      key={it.findingId}
                      className={`rounded-xl border p-4 ${it.applied ? 'border-neon-green/30 bg-neon-green/[0.05]' : 'border-white/10 bg-white/5'}`}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="text-xs font-mono text-white/70">{it.findingId}</div>
                          <div className="mt-1 text-sm font-semibold text-white">{it.name}</div>
                        </div>
                        {it.applied ? (
                          <span className="rounded-full border border-neon-green/25 bg-neon-green/15 px-2.5 py-1 text-xs font-mono text-neon-green">
                            <span aria-hidden="true" className="mr-1 font-bold">✓</span>FIXED
                          </span>
                        ) : (
                          <button
                            type="button"
                            disabled={bulkModal.applying || busyFindingId !== null}
                            onClick={() => void applyBulkItem(it.findingId)}
                            className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-3 py-1.5 text-xs font-semibold text-neon-cyan transition-colors duration-200 hover:bg-neon-cyan/15 disabled:opacity-50"
                          >
                            {busyFindingId === it.findingId ? 'Applying…' : 'Apply This Fix'}
                          </button>
                        )}
                      </div>
                      {it.error ? (
                        <div className="mt-3 rounded-lg border border-neon-red/25 bg-neon-red/10 px-3 py-2 text-sm text-white/85">
                          {it.error}
                        </div>
                      ) : null}
                      <div className="mt-3">
                        {it.supported && it.changes.length > 0 ? (
                          <ul className="list-disc space-y-1 pl-5 text-sm text-white/75">
                            {it.changes.map((c, cIdx) => (
                              <li key={cIdx}>{c}</li>
                            ))}
                          </ul>
                        ) : (
                          <div className="text-sm text-white/60">
                            {it.supported ? 'No change details were provided.' : 'Preview not available for this fix.'}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {bulkModal.errors.length > 0 ? (
              <div className="mt-4 rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                <div className="text-xs font-mono text-neon-red/80">ERRORS</div>
                <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-xs text-white/80">
                  {bulkModal.errors.join('\n')}
                </pre>
              </div>
            ) : null}

            <div className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/5 px-4 py-3">
              <div className="text-sm">
                {backupSavedPath ? (
                  <span className="font-mono text-neon-green text-xs">✓ Backed up → {backupSavedPath}</span>
                ) : (
                  <span className="text-white/60">Back up registry before applying all fixes <span className="text-white/65">(recommended)</span></span>
                )}
              </div>
              <button
                type="button"
                disabled={backupPending || bulkModal.applying}
                onClick={() => void doBackupRegistry()}
                className="shrink-0 rounded-xl border border-white/15 bg-white/5 px-3 py-1.5 text-xs font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10 disabled:opacity-50"
              >
                {backupPending ? 'Saving…' : backupSavedPath ? 'Save Again' : 'Save Backup…'}
              </button>
            </div>

            <div className="mt-4 flex flex-wrap justify-end gap-2">
              {bulkModal.applying ? (
                <button
                  type="button"
                  onClick={() => { bulkCancelRef.current = true }}
                  className="rounded-xl border border-neon-amber/30 bg-neon-amber/10 px-4 py-2 text-sm font-semibold text-neon-amber transition-all duration-200 hover:bg-neon-amber/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
                >
                  Stop After Current Fix
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => { setBulkModal(null); setBackupSavedPath(null) }}
                  className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
                >
                  Close
                </button>
              )}
              <button
                type="button"
                disabled={bulkModal.applying || bulkModal.items.every((it) => it.applied)}
                onClick={() => void applyBulkRemediation()}
                className="rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan transition-all duration-200 hover:bg-neon-cyan/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:opacity-50"
              >
                {bulkModal.applying
                  ? 'Applying…'
                  : `Apply All (${bulkModal.items.filter((it) => !it.applied).length})`}
              </button>
            </div>
          </div>
        ) : null}
      </Dialog>

      <Dialog
        open={!!(disclaimerAccepted && pinRequired && !remediationUnlocked && !accessDismissed)}
        onClose={() => setAccessDismissed(true)}
        labelledBy="access-title"
      >
        <form
          onSubmit={(e) => { e.preventDefault(); void unlockRemediation() }}
          className="w-[min(680px,92vw)] rounded-2xl border border-neon-purple/25 bg-bg-1/80 p-6 shadow-neon"
        >
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-purple/80">ACCESS CONTROL</div>
                <h2 id="access-title" className="mt-2 text-xl font-semibold text-white">Unlock remediation</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  This client requires an access code before allowing system changes. Viewing audit results and exporting reports is still
                  available without unlocking.
                </p>
              </div>
              <div className="select-none rounded-xl border border-neon-purple/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-purple/80">
                LOCKED
              </div>
            </div>

            <div className="mt-5">
              <label className="text-xs font-mono text-white/70">ACCESS CODE</label>
              <input
                value={pinInput}
                onChange={(e) => setPinInput(e.target.value)}
                type="password"
                className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white/85 outline-none transition-colors duration-200 focus:border-neon-purple/35"
                placeholder="Enter access code"
              />
              {pinError ? (
                <div className="mt-3 rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
                  {pinError}
                </div>
              ) : null}
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setAccessDismissed(true)}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Continue read-only
              </button>
              <button
                type="submit"
                className="rounded-xl border border-neon-purple/30 bg-neon-purple/10 px-4 py-2 text-sm font-semibold text-neon-purple transition-all duration-200 hover:bg-neon-purple/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Unlock
              </button>
            </div>
          </form>
      </Dialog>

      <Dialog
        open={exitConfirmOpen}
        onClose={() => setExitConfirmOpen(false)}
        labelledBy="exit-title"
      >
        <div className="w-[min(560px,92vw)] rounded-2xl border border-neon-red/25 bg-bg-1/80 p-6 shadow-neon">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-red/80">EXIT</div>
                <h2 id="exit-title" className="mt-2 text-xl font-semibold text-white">Exit SentinelAudit?</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  Any in-progress actions will be interrupted. Exports that are currently running may not finish.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setExitConfirmOpen(false)}
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10"
              >
                Close
              </button>
            </div>

            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setExitConfirmOpen(false)}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                No
              </button>
              <button
                type="button"
                onClick={() => void confirmExit()}
                className="rounded-xl border border-neon-red/30 bg-neon-red/10 px-4 py-2 text-sm font-semibold text-neon-red transition-all duration-200 hover:bg-neon-red/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Yes, Exit
              </button>
            </div>
          </div>
      </Dialog>

      <Dialog
        open={rollbackConfirmId !== null}
        onClose={() => setRollbackConfirmId(null)}
        labelledBy="rollback-title"
      >
        {rollbackConfirmId ? (
        <div className="w-[min(560px,92vw)] rounded-2xl border border-neon-amber/25 bg-bg-1/80 p-6 shadow-neon">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-amber/80">ROLLBACK</div>
                <h2 id="rollback-title" className="mt-2 text-xl font-semibold text-white">Undo last change?</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  This will restore the previous registry state for this check. The rollback itself cannot be undone.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setRollbackConfirmId(null)}
                className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-semibold text-white/70 transition-colors duration-200 hover:bg-white/10"
              >
                Close
              </button>
            </div>
            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setRollbackConfirmId(null)}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void confirmRollback(rollbackConfirmId)}
                className="rounded-xl border border-neon-amber/30 bg-neon-amber/10 px-4 py-2 text-sm font-semibold text-neon-amber transition-all duration-200 hover:bg-neon-amber/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                Rollback
              </button>
            </div>
          </div>
        ) : null}
      </Dialog>

      <Dialog
        open={loggedIn && idleWarning !== null}
        onClose={() => void stayInSession()}
        labelledBy="idle-title"
      >
        {idleWarning ? (
          <div className="w-[min(520px,92vw)] rounded-2xl border border-neon-amber/25 bg-bg-1/80 p-6 shadow-neon">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono tracking-widest text-neon-amber/80">SESSION</div>
                <h2 id="idle-title" className="mt-2 text-xl font-semibold text-white">Still there?</h2>
                <p className="mt-3 text-sm leading-6 text-white/75">
                  Your session will expire in{' '}
                  <span className="font-semibold text-white tabular-nums">{idleWarning.remainingS}s</span> due to inactivity.
                </p>
              </div>
              <div
                className="select-none rounded-xl border border-neon-amber/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-amber/80"
                aria-hidden="true"
              >
                IDLE
              </div>
            </div>
            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setIdleWarning(null)
                  setLoggedIn(false)
                  setLoginError('Signed out.')
                }}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/80 hover:bg-white/10"
              >
                Sign out now
              </button>
              <button
                type="button"
                onClick={() => void stayInSession()}
                className="rounded-xl border border-neon-amber/30 bg-neon-amber/10 px-4 py-2 text-sm font-semibold text-neon-amber hover:bg-neon-amber/15"
              >
                Stay signed in
              </button>
            </div>
          </div>
        ) : null}
      </Dialog>

      <Dialog open={guideOpen && loggedIn} onClose={() => setGuideOpen(false)} labelledBy="guide-title">
        <div className="w-[min(760px,92vw)] max-h-[85vh] overflow-y-auto rounded-2xl border border-neon-cyan/25 bg-bg-1 p-6 shadow-neon">
          <div className="text-xs font-mono tracking-widest text-neon-cyan">QUICK START</div>
          <h2 id="guide-title" className="mt-2 text-2xl font-semibold text-white">How to use SentinelAudit</h2>
          <p className="mt-3 text-sm text-white/70">Assess Windows security settings, inspect evidence and choose changes deliberately. An audit is an assessment, not an antivirus scan or a guarantee of security.</p>
          <ol className="mt-5 grid gap-4 text-sm text-white/80 list-decimal pl-5">
            <li><strong>Run an audit.</strong> The first scan starts after sign-in. Use Run Audit for a fresh assessment; wait for the scan to finish.</li>
            <li><strong>Read the findings.</strong> Filter by category or severity and inspect the evidence. Pass means the check passed; fail needs attention; unknown means there was not enough evidence. Coverage matters alongside the score.</li>
            <li><strong>Review before fixing.</strong> Unlock remediation, open a finding and preview the change. Only apply fixes you understand and are authorized to make. Some changes need a restart.</li>
            <li><strong>Keep a recovery path.</strong> Save a registry backup before registry changes. Use available rollback controls for supported changes; a registry backup is not a full system backup.</li>
            <li><strong>Export and verify.</strong> Export the Excel report and choose a save location. “Data exported successfully” confirms a saved file. Canceling the picker does not export data.</li>
            <li><strong>Recheck and secure access.</strong> Run another audit after changes. Change your application login from the account controls and sign out when finished. Existing accounts require their current password; setup cannot overwrite them.</li>
          </ol>
          <p className="mt-5 text-sm text-white/60">Use Cancel scan to stop after the current Windows check finishes. Partial results cannot be exported or synced as a complete audit. Use Sync last scan to Admin to queue a completed read-only report through an enrolled Client on this PC; credentials and raw evidence are not copied. Queued does not confirm Admin receipt. Fleet monitoring is separate: install System Agent Client on an authorized endpoint and enroll it with System Agent Admin. The standalone audit account is not a fleet account.</p>
          <button type="button" onClick={() => setGuideOpen(false)} className="mt-5 rounded-xl border border-neon-cyan/30 bg-neon-cyan/10 px-4 py-2 text-sm font-semibold text-neon-cyan">Got it — view my audit</button>
        </div>
      </Dialog>

      {adminStatus && !adminStatus.is_admin ? <AdminOverlay /> : null}

      {!authenticated && error ? (
        <div className="flex h-full items-center justify-center px-6">
          <div
            role="alert"
            className="w-full max-w-xl rounded-2xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85"
          >
            {error}
          </div>
        </div>
      ) : null}

      {authenticated ? (
      <div className="sentinel-shell mx-auto flex min-h-full max-w-7xl flex-col gap-6 px-6 py-8">
        <header className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="text-xs font-mono tracking-widest text-neon-cyan/70">SENTINELAUDIT</div>
            <h1 className="mt-1 text-4xl font-bold tracking-tight text-white">Your endpoint. Clearly assessed.</h1>
            <p className="mt-2 text-sm leading-6 text-white/60">
              Windows security checks, evidence and guided remediation.
            </p>
            <div className="mt-1.5 text-xs font-mono text-white/30">
              v{adminStatus?.version ?? '-'}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => setGuideOpen(true)} className="h-10 rounded-xl border border-neon-cyan/25 bg-neon-cyan/10 px-4 text-sm font-semibold text-neon-cyan">How to use</button>
            <button
              type="button"
              disabled={loading || exporting}
              onClick={() => void runAuditNow()}
              className="h-10 rounded-xl border border-white/10 bg-white/5 px-4 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span className="inline-flex items-center gap-2">
                <ArrowClockwise size={16} />
                {loading ? 'Scanning…' : 'Run Audit'}
              </span>
            </button>
            {loading && <button type="button" disabled={cancelling} onClick={() => {
              setCancelling(true); void cancelAudit().catch(e => {setError(String(e));setCancelling(false)})
            }} className="h-10 rounded-xl border border-white/20 px-4 text-sm">{cancelling ? 'Cancelling…' : 'Cancel scan'}</button>}
            <button type="button" disabled={loading || !audit || Boolean(scanInterrupted) || syncPending} onClick={() => {
              setSyncPending(true);setSyncMessage('')
              void syncLastAudit().then(result => setSyncMessage(result.error || `${result.message || 'Queued locally.'}${result.warning ? ' ' + result.warning : ''}`))
                .catch(e => setSyncMessage(String(e))).finally(() => setSyncPending(false))
            }} className="h-10 rounded-xl border border-neon-cyan/30 px-4 text-sm disabled:opacity-50">{syncPending ? 'Queuing…' : 'Sync last scan to Admin'}</button>
            {canRemediate && fixableFailures.length > 0 ? (
              <button
                type="button"
                disabled={loading || busyFindingId !== null}
                onClick={() => void openBulkRemediation()}
                className="h-10 rounded-xl border border-neon-cyan/25 bg-neon-cyan/10 px-4 text-sm font-semibold text-neon-cyan transition-all duration-200 hover:bg-neon-cyan/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <span className="inline-flex items-center gap-2">
                  <Wrench size={16} />
                  Fix All ({fixableFailures.length})
                </span>
              </button>
            ) : null}
            <button
              type="button"
              disabled={exporting || loading || Boolean(scanInterrupted)}
              onClick={() => void exportReport()}
              className="h-10 rounded-xl border border-neon-purple/25 bg-neon-purple/10 px-4 text-sm font-semibold text-neon-purple transition-all duration-200 hover:bg-neon-purple/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span className="inline-flex items-center gap-2">
                <DownloadSimple size={16} />
                {exporting ? 'Exporting…' : 'Export Report'}
              </span>
            </button>
            {pinRequired && !remediationUnlocked ? (
              <button
                type="button"
                onClick={() => setAccessDismissed(false)}
                className="h-10 rounded-xl border border-neon-purple/25 bg-neon-purple/10 px-4 text-sm font-semibold text-neon-purple transition-all duration-200 hover:bg-neon-purple/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                <span className="inline-flex items-center gap-2">
                  <Lock size={16} />
                  Unlock
                </span>
              </button>
            ) : null}
            <div className="relative">
              <button
                type="button"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                aria-label="More actions"
                onClick={() => setMenuOpen((v) => !v)}
                className="h-10 rounded-xl border border-white/10 bg-white/5 px-3 text-sm font-semibold text-white/80 transition-all duration-200 hover:bg-white/10 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
              >
                <DotsThreeVertical size={20} weight="bold" />
              </button>
              {menuOpen ? (
                <>
                  <div className="fixed inset-0 z-30" onClick={() => setMenuOpen(false)} />
                  <div
                    role="menu"
                    className="absolute right-0 top-12 z-40 w-56 rounded-xl border border-white/10 bg-bg-1/95 p-1.5 shadow-neon backdrop-blur"
                  >
                    <button
                      type="button"
                      role="menuitem"
                      disabled={checkingUpdates}
                      onClick={() => {
                        setMenuOpen(false)
                        void checkForUpdates()
                      }}
                      className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm font-semibold text-white/80 transition-colors duration-200 hover:bg-white/10 disabled:opacity-50"
                    >
                      <ArrowsClockwise size={16} />
                      {checkingUpdates ? 'Checking…' : 'Check Updates'}
                    </button>
                    {loggedIn ? (
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          setMenuOpen(false)
                          setChangeNewUsername(loginUsername)
                          setChangeLoginError(null)
                          setChangeLoginOpen(true)
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm font-semibold text-white/80 transition-colors duration-200 hover:bg-white/10"
                      >
                        <Key size={16} />
                        Change Login
                      </button>
                    ) : null}
                  </div>
                </>
              ) : null}
            </div>
            <button
              type="button"
              onClick={() => setExitConfirmOpen(true)}
              className="h-10 rounded-xl border border-neon-red/25 bg-neon-red/10 px-4 text-sm font-semibold text-neon-red transition-all duration-200 hover:bg-neon-red/15 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0"
            >
              <span className="inline-flex items-center gap-2">
                <X size={16} />
                Exit
              </span>
            </button>
          </div>
        </header>

        <div role="alert" aria-live="assertive" aria-atomic="true">
          {error ? (
            <div className="rounded-2xl border border-neon-red/25 bg-neon-red/10 px-4 py-3 text-sm text-white/85">
              {error}
            </div>
          ) : null}
        </div>

        <div className="sentinel-overview" aria-label="Audit summary">
          <button onClick={()=>setFindingFilter('Fail')}><span>Needs attention</span><strong>{audit ? audit.findings.filter(f=>f.status==='Fail').length : '—'}</strong><small>Review failed checks →</small></button>
          <button onClick={()=>setFindingFilter('Unknown')}><span>Unverified checks</span><strong>{audit ? audit.findings.filter(f=>f.status==='Unknown').length : '—'}</strong><small>Investigate missing evidence →</small></button>
          <button onClick={()=>setFindingFilter('Pass')}><span>Passed checks</span><strong>{audit ? audit.findings.filter(f=>f.status==='Pass').length : '—'}</strong><small>Inspect assessed controls →</small></button>
          <div><span>Collection state</span><strong className="sentinel-state">{loading ? (cancelling ? 'Cancelling scan' : 'Audit running') : scanInterrupted ? (scanInterrupted === 'cancelled' ? 'Audit cancelled' : 'Audit failed') : audit ? 'Audit completed' : 'Ready to audit'}</strong><small>Offline results · optional sync through your enrolled Client</small></div>
        </div>
        <motion.section
          {...(reduceMotion ? {} : { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 } })}
          className="grid grid-cols-1 gap-6 lg:grid-cols-[260px_1fr]"
        >
          <div className="rounded-2xl border border-white/10 bg-bg-1/60 p-5 shadow-neon">
            <div className="text-sm font-mono tracking-widest text-white/70">AUDIT OVERVIEW</div>
            <p className="mt-2 text-sm leading-6 text-white/65">Local Windows security checks</p>
            <div className="sentinel-score-panel">
              <ProgressGauge score={score} />
            </div>
            {loading && <div className="sentinel-scan-progress" role="status">
              <strong>{cancelling ? 'Cancelling scan' : `Scanning · ${auditProgress?.completed ?? 0} of ${auditProgress?.total ?? 0} checks`}</strong>
              <progress aria-label="Scan progress" value={auditProgress?.completed ?? 0} max={Math.max(1, auditProgress?.total ?? 1)} />
              <p>{cancelling ? 'Waiting for the current Windows check to finish…' : currentCheck ? `Checking: ${currentCheck}` : 'Preparing next check…'}</p>
              <small>Score is provisional until the scan completes.</small>
            </div>}
            {syncMessage && <p role="status" className="sentinel-sync-status">{syncMessage}</p>}
            <div className="mt-3 text-sm text-white/70">
              Score covers assessed checks only. Coverage: {audit && audit.findings.length ? Math.round(100 * audit.findings.filter(f => f.status !== 'Unknown').length / audit.findings.length) : 0}%.
              Unknown results require investigation.
            </div>

          </div>

          <div className="min-h-[520px]">
            <ResultsFeed
              findings={audit?.findings ?? []}
              statusFilter={findingFilter}
              onStatusFilter={setFindingFilter}
              loading={loading}
              progress={auditProgress}
              busyFindingId={busyFindingId}
              isAdmin={adminStatus?.is_admin ?? false}
              canRemediate={canRemediate}
              rollbackAvailableIds={rollbackAvailableIds}
              onFix={(id) => void openPreview(id)}
              onRollback={(id) => void rollbackOne(id)}
            />
          </div>
        </motion.section>
      </div>
      ) : null}
    </div>
  )
}

export default App
