import { useDeferredValue, useMemo, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { ArrowCounterClockwise, CaretDown, Wrench } from '@phosphor-icons/react'

import type { Finding } from '../lib/api'

function riskColor(risk: Finding['risk_level']) {
  if (risk === 'High') return 'border-neon-red/35 text-neon-red'
  if (risk === 'Medium') return 'border-neon-amber/35 text-neon-amber'
  return 'border-neon-green/35 text-neon-green'
}

function cardStyle(status: Finding['status']) {
  if (status === 'Pass') return 'border-neon-green/40 border-l-4 border-l-neon-green bg-neon-green/[0.06]'
  if (status === 'Fail') return 'border-neon-red/50 border-l-4 border-l-neon-red bg-neon-red/[0.08]'
  return 'border-neon-amber/30 border-l-4 border-l-neon-amber/80 bg-neon-amber/[0.04]'
}

function statusPill(status: Finding['status']) {
  if (status === 'Pass') return 'bg-neon-green/15 text-neon-green border-neon-green/25'
  if (status === 'Fail') return 'bg-neon-red/15 text-neon-red border-neon-red/25'
  return 'bg-white/10 text-white/70 border-white/15'
}

function statusGlyph(status: Finding['status']) {
  if (status === 'Pass') return '✓'
  if (status === 'Fail') return '✕'
  return '?'
}

function formatUtc(ts: string | null | undefined) {
  if (!ts) return '-'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(
    d.getUTCMinutes(),
  )}:${pad(d.getUTCSeconds())} UTC`
}

export function ResultsFeed({
  findings,
  statusFilter = "all",
  onStatusFilter,
  loading,
  progress,
  busyFindingId,
  isAdmin,
  canRemediate,
  rollbackAvailableIds,
  onFix,
  onRollback,
}: {
  findings: Finding[]
  statusFilter?: string
  onStatusFilter?: (value: string) => void
  loading: boolean
  progress?: { completed: number; total: number } | null
  busyFindingId: string | null
  isAdmin: boolean
  canRemediate: boolean
  rollbackAvailableIds: Set<string>
  onFix: (findingId: string) => void
  onRollback: (findingId: string) => void
}) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [query, setQuery] = useState('')
  const [risk, setRisk] = useState('all')
  const [sort, setSort] = useState('risk')
  const search = useDeferredValue(query.toLowerCase())
  const visible = useMemo(() => findings.filter(f =>
    (statusFilter === 'all' || f.status === statusFilter) && (risk === 'all' || f.risk_level === risk) &&
    `${f.name} ${f.description} ${f.finding_id}`.toLowerCase().includes(search))
    .sort((a,b) => sort === 'name' ? a.name.localeCompare(b.name) :
      ({High:0, Medium:1, Low:2}[a.risk_level] - {High:0, Medium:1, Low:2}[b.risk_level])), [findings,statusFilter,risk,sort,search])
  const reduceMotion = useReducedMotion()

  const expandedIds = useMemo(() => new Set(Object.keys(expanded).filter((k) => expanded[k])), [expanded])
  const chipBase = 'inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-mono'
  const actionBase =
    'h-10 rounded-xl border px-4 text-sm font-semibold transition-all duration-200 hover:-translate-y-0.5 active:scale-[0.98] active:translate-y-0 disabled:opacity-50'
  const skeletonRows = useMemo(() => Array.from({ length: 6 }, (_, i) => i), [])

  return (
    <div className="sentinel-feed w-full overflow-auto rounded-2xl border border-white/10 bg-bg-1/60 shadow-neon">
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-bg-1/80 px-5 py-4 backdrop-blur">
        <div className="text-sm font-mono tracking-widest text-white/70">FINDINGS WORKSPACE</div>
        <div className="text-xs font-mono text-white/70" aria-live="polite">
          {loading
            ? progress && progress.total > 0
              ? `Scanning… ${progress.completed}/${progress.total}`
              : 'Scanning…'
            : `${findings.length} checks`}
        </div>
      </div>

      <div className="sentinel-filters">
        <label className="sentinel-search">Search findings<input aria-label="Search local findings" placeholder="Search checks or descriptions…" value={query} onChange={e=>setQuery(e.target.value)} /></label>
        <label>Result<select value={statusFilter} onChange={e=>onStatusFilter?.(e.target.value)}><option value="all">All results</option><option>Fail</option><option>Unknown</option><option>Pass</option></select></label>
        <label>Risk<select value={risk} onChange={e=>setRisk(e.target.value)}><option value="all">All risks</option><option>High</option><option>Medium</option><option>Low</option></select></label>
        <label>Sort<select value={sort} onChange={e=>setSort(e.target.value)}><option value="risk">Highest risk</option><option value="name">Check name</option></select></label>
      </div>
      {!loading && findings.length > 0 && visible.length === 0 && <div className="p-8 text-center text-white/70">No matching checks. Adjust your filters or search.</div>}
      <div className="space-y-3 p-5">
        {loading && findings.length === 0 ? (
          <div className="space-y-3">
            {skeletonRows.map((i) => (
              <div key={i} className="animate-pulse rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="sentinel-finding-layout flex flex-wrap items-start justify-between gap-3">
                  <div className="sentinel-finding-copy min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <div className="h-6 w-16 rounded-full bg-white/10" />
                      <div className="h-6 w-16 rounded-full bg-white/10" />
                      <div className="h-4 w-48 rounded bg-white/10" />
                    </div>
                    <div className="mt-3 h-5 w-[min(520px,85%)] rounded bg-white/10" />
                    <div className="mt-3 h-4 w-[min(720px,95%)] rounded bg-white/10" />
                    <div className="mt-2 h-4 w-[min(640px,90%)] rounded bg-white/10" />
                    <div className="mt-3 h-4 w-56 rounded bg-white/10" />
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="h-10 w-28 rounded-xl bg-white/10" />
                    <div className="h-10 w-28 rounded-xl bg-white/10" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : findings.length === 0 ? (
          <div className="flex h-[420px] items-center justify-center px-6">
            <div className="w-full max-w-xl rounded-2xl border border-white/10 bg-black/20 p-6 text-center">
              <div className="text-sm font-mono tracking-widest text-white/60">NO RESULTS</div>
              <div className="mt-3 text-lg font-semibold text-white">Run an audit to populate findings</div>
              <div className="mt-2 text-sm leading-6 text-white/70">
                SentinelAudit shows per-check evidence, references, and recommendations. Remediation actions are available when running elevated and
                logged in.
              </div>
            </div>
          </div>
        ) : (
          visible.map((f) => (
            <motion.div
              key={f.finding_id}
              layout={!reduceMotion}
              {...(reduceMotion ? {} : { initial: { opacity: 0, y: 6 }, animate: { opacity: 1, y: 0 } })}
              transition={reduceMotion ? { duration: 0 } : { layout: { duration: 0.25, ease: 'easeOut' } }}
              className={`rounded-xl border p-4 ${cardStyle(f.status)}`}
            >
              <div className="sentinel-finding-layout flex flex-wrap items-start justify-between gap-3">
                <div className="sentinel-finding-copy min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <div className={`${chipBase} ${riskColor(f.risk_level)}`}>
                      <span className="mr-2 inline-block h-2 w-2 rounded-full bg-current opacity-70" />
                      {f.risk_level.toUpperCase()}
                    </div>
                    <div className={`${chipBase} ${statusPill(f.status)}`}>
                      <span aria-hidden="true" className="mr-1.5 font-bold">{statusGlyph(f.status)}</span>
                      {f.status.toUpperCase()}
                    </div>
                    <div className="truncate text-xs font-mono text-white/65">{f.finding_id}</div>
                  </div>
                  <div className="mt-2 text-base font-semibold text-white">{f.name}</div>
                  <div className="mt-2 text-sm leading-6 text-white/70">{f.description}</div>
                  <div className="mt-2 text-xs font-mono text-white/65">Last checked: {formatUtc(f.last_checked_utc)}</div>
                </div>

                <div className="flex items-center gap-2">
                  {f.status === 'Fail' && f.fix_available && canRemediate ? (
                    <button
                      type="button"
                      disabled={busyFindingId === f.finding_id}
                      onClick={() => onFix(f.finding_id)}
                      className={`${actionBase} inline-flex items-center gap-2 border-neon-cyan/30 bg-neon-cyan/10 text-neon-cyan hover:bg-neon-cyan/15`}
                    >
                      <Wrench size={16} />
                      {busyFindingId === f.finding_id ? 'Working…' : 'Preview fix'}
                    </button>
                  ) : (
                    <div
                      className={`${actionBase} inline-flex items-center border-white/10 bg-white/5 text-white/70 hover:bg-white/10`}
                    >
                      {f.status === 'Pass'
                        ? 'Passed'
                        : f.status === 'Unknown'
                          ? 'Check unavailable'
                          : f.fix_available && !isAdmin
                            ? 'Run as admin to fix'
                            : f.fix_available && isAdmin && !canRemediate
                              ? 'Unlock remediation'
                              : 'Recommendation'}
                    </div>
                  )}

                  {canRemediate && rollbackAvailableIds.has(f.finding_id) ? (
                    <button
                      type="button"
                      disabled={busyFindingId === f.finding_id}
                      onClick={() => onRollback(f.finding_id)}
                      className={`${actionBase} inline-flex items-center gap-2 border-white/10 bg-white/5 text-white/80 hover:bg-white/10`}
                    >
                      <ArrowCounterClockwise size={16} />
                      {busyFindingId === f.finding_id ? 'Working…' : 'Rollback'}
                    </button>
                  ) : null}

                  <button
                    type="button"
                    onClick={() => setExpanded((prev) => ({ ...prev, [f.finding_id]: !prev[f.finding_id] }))}
                    className={`${actionBase} inline-flex items-center gap-2 border-white/10 bg-white/5 text-white/80 hover:bg-white/10`}
                  >
                    <CaretDown
                      size={16}
                      className={`transition-transform duration-200 ${expandedIds.has(f.finding_id) ? 'rotate-180' : ''}`}
                    />
                    {expandedIds.has(f.finding_id) ? 'Hide Details' : 'Details'}
                  </button>
                </div>
              </div>

              <AnimatePresence initial={false}>
                {expandedIds.has(f.finding_id) ? (
                  <motion.div
                    key="details"
                    layout={!reduceMotion}
                    {...(reduceMotion
                      ? {}
                      : {
                          initial: { opacity: 0, y: -6 },
                          animate: { opacity: 1, y: 0 },
                          exit: { opacity: 0, y: -6 },
                        })}
                    transition={reduceMotion ? { duration: 0 } : { duration: 0.22, ease: 'easeOut' }}
                    className="mt-4 overflow-hidden rounded-xl border border-white/10 bg-white/5"
                  >
                    <div className="p-4">
                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                        <div className="space-y-1">
                          <div className="text-xs font-mono text-white/70">WHY IT MATTERS</div>
                          <div className="text-sm text-white/80">
                            {String((f.details as Record<string, unknown>).why_it_matters ?? '') || '-'}
                          </div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs font-mono text-white/70">RISK</div>
                          <div className="text-sm text-white/80">
                            {String((f.details as Record<string, unknown>).risk ?? '') || '-'}
                          </div>
                        </div>
                        <div className="space-y-1 md:col-span-2">
                          <div className="text-xs font-mono text-white/70">RECOMMENDATION</div>
                          <div className="text-sm text-white/80">
                            {String((f.details as Record<string, unknown>).recommendation ?? '') || '-'}
                          </div>
                        </div>
                        <div className="space-y-1 md:col-span-2">
                          <div className="text-xs font-mono text-white/70">REFERENCES</div>
                          <pre className="max-h-40 overflow-auto rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-white/70">
                            {JSON.stringify((f.details as Record<string, unknown>).references ?? [], null, 2)}
                          </pre>
                        </div>
                        <div className="space-y-1 md:col-span-2">
                          <div className="text-xs font-mono text-white/70">EVIDENCE</div>
                          <pre className="max-h-64 overflow-auto rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-white/70">
                            {JSON.stringify(f.details, null, 2)}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ) : null}
              </AnimatePresence>
            </motion.div>
          ))
        )}
      </div>
    </div>
  )
}
