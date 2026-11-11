export const PASSWORD_RULES: Array<{ label: string; test: (p: string) => boolean; error: string }> = [
  { label: '12+ chars', test: (p) => p.length >= 12, error: 'At least 12 characters required.' },
  { label: 'Uppercase', test: (p) => /[A-Z]/.test(p), error: 'Must include an uppercase letter.' },
  { label: 'Lowercase', test: (p) => /[a-z]/.test(p), error: 'Must include a lowercase letter.' },
  { label: 'Number', test: (p) => /\d/.test(p), error: 'Must include a number.' },
  { label: 'Symbol', test: (p) => /[^A-Za-z0-9]/.test(p), error: 'Must include a special character.' },
]

/** Mirrors the backend's _validate_password_strength rules. */
export function pwStrengthError(p: string): string | null {
  for (const rule of PASSWORD_RULES) {
    if (!rule.test(p)) return rule.error
  }
  return null
}
