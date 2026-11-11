import { useEffect, useRef } from 'react'
import { motion, useReducedMotion } from 'motion/react'

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export interface DialogProps {
  open: boolean
  onClose: () => void
  labelledBy: string
  describedBy?: string
  closeOnEsc?: boolean
  closeOnBackdrop?: boolean
  children: React.ReactNode
}

export function Dialog({
  open,
  onClose,
  labelledBy,
  describedBy,
  closeOnEsc = true,
  closeOnBackdrop = false,
  children,
}: DialogProps) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const lastFocusedRef = useRef<HTMLElement | null>(null)
  const reduceMotion = useReducedMotion()

  // Callers pass inline closures for onClose; route them through refs so the
  // focus-management effect only runs on open/close transitions. If it re-ran
  // on every parent render, the initial-focus rAF would steal focus from
  // whatever field the user is typing in.
  const onCloseRef = useRef(onClose)
  const closeOnEscRef = useRef(closeOnEsc)
  useEffect(() => {
    onCloseRef.current = onClose
    closeOnEscRef.current = closeOnEsc
  }, [onClose, closeOnEsc])

  useEffect(() => {
    if (!open) return
    lastFocusedRef.current = (document.activeElement as HTMLElement | null) ?? null

    const focusInitial = () => {
      const root = containerRef.current
      if (!root) return
      const first = root.querySelector<HTMLElement>(FOCUSABLE_SELECTOR)
      ;(first ?? root).focus()
    }
    const raf = window.requestAnimationFrame(focusInitial)

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && closeOnEscRef.current) {
        e.preventDefault()
        onCloseRef.current()
        return
      }
      if (e.key !== 'Tab') return
      const root = containerRef.current
      if (!root) return
      const focusable = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      )
      if (focusable.length === 0) {
        e.preventDefault()
        root.focus()
        return
      }
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement as HTMLElement | null
      if (e.shiftKey) {
        if (active === first || !root.contains(active)) {
          e.preventDefault()
          last.focus()
        }
      } else if (active === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      window.cancelAnimationFrame(raf)
      document.removeEventListener('keydown', onKeyDown)
      const prev = lastFocusedRef.current
      lastFocusedRef.current = null
      if (prev && typeof prev.focus === 'function') {
        try {
          prev.focus()
        } catch {
          /* element may have unmounted */
        }
      }
    }
  }, [open])

  if (!open) return null

  const motionProps = reduceMotion ? {} : { initial: { opacity: 0 }, animate: { opacity: 1 } }

  return (
    <motion.div
      {...motionProps}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur"
      onMouseDown={(e) => {
        if (!closeOnBackdrop) return
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        className="outline-none"
      >
        {children}
      </div>
    </motion.div>
  )
}
