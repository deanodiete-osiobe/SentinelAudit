import { motion } from 'motion/react'

export function AdminOverlay() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur"
    >
      <div className="w-[min(640px,92vw)] rounded-2xl border border-neon-cyan/25 bg-bg-1/80 p-6 shadow-neon">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-sm font-mono tracking-widest text-neon-cyan/80">
              ELEVATED ACCESS REQUIRED
            </div>
            <h1 className="mt-2 text-2xl font-semibold text-white">
              Locked: Administrator privileges missing
            </h1>
            <p className="mt-3 text-sm leading-6 text-white/75">
              SentinelAudit can safely read many settings without elevation, but applying fixes and
              auditing certain controls requires an elevated token.
            </p>
          </div>
          <div className="select-none rounded-xl border border-neon-cyan/20 bg-bg-2/70 px-3 py-2 font-mono text-xs text-neon-cyan/80">
            UAC
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-white/10 bg-black/30 p-4">
          <div className="text-xs font-mono text-white/60">How to relaunch elevated</div>
          <div className="mt-2 text-sm text-white/80">
            - Close the app
            <br />- Right-click SentinelAudit → Run as administrator
          </div>
        </div>
      </div>
    </motion.div>
  )
}
