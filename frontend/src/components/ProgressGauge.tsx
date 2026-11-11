import 'react-circular-progressbar/dist/styles.css'

import { CircularProgressbarWithChildren, buildStyles } from 'react-circular-progressbar'

export function ProgressGauge({ score }: { score: number }) {
  const color = score >= 80 ? '#22c55e' : score >= 50 ? '#fbbf24' : '#fb7185'

  return (
    <div className="sentinel-score-gauge" role="img" aria-label={`Hardening score ${score} out of 100`}>
      <div className="sentinel-score-title">Hardening score</div>
      <CircularProgressbarWithChildren
        value={score}
        styles={buildStyles({
          pathColor: color,
          trailColor: 'rgba(255,255,255,0.08)',
          strokeLinecap: 'round',
        })}
      >
        <div className="flex flex-col items-center">
          <div className="mt-1 text-4xl font-semibold text-white">{score}</div>
          <div className="mt-1 text-xs font-mono tracking-widest text-white/55">OUT OF 100</div>
        </div>
      </CircularProgressbarWithChildren>
    </div>
  )
}
