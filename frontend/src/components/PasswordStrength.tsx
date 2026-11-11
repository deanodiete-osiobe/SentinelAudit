import { PASSWORD_RULES } from '../lib/password'

const BAR_COLORS = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#4ade80']
const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']

export function PasswordStrengthMeter({ password }: { password: string }) {
  if (!password) return null
  const results = PASSWORD_RULES.map((r) => ({ label: r.label, ok: r.test(password) }))
  const score = results.filter((r) => r.ok).length
  const barColor = BAR_COLORS[score - 1] ?? BAR_COLORS[0]
  const strengthLabel = STRENGTH_LABELS[score - 1] ?? STRENGTH_LABELS[0]
  return (
    <div className="mt-2 space-y-1.5" role="status" aria-live="polite">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono text-white/70">Strength</span>
        <span className="text-xs font-semibold" style={{ color: barColor }}>{strengthLabel}</span>
      </div>
      <div className="h-1 w-full overflow-hidden rounded-full bg-white/10">
        <div
          className="h-full rounded-full transition-all duration-200"
          style={{ width: `${(score / PASSWORD_RULES.length) * 100}%`, background: barColor }}
        />
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {results.map((r) => (
          <span key={r.label} className={`text-xs font-mono ${r.ok ? 'text-neon-green' : 'text-white/65'}`}>
            <span aria-hidden="true">{r.ok ? '✓' : '○'}</span> {r.label}
          </span>
        ))}
      </div>
    </div>
  )
}
