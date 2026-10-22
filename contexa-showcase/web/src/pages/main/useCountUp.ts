import { useEffect, useState } from 'react';

/** Whether the visitor asked for less motion; read where it is used, so a change shows on the next render. */
function reducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false)
  );
}

/**
 * A number that counts up from 0 to its value when it arrives (설계서 모션: 유출 카운터 1.2초, 정리 숫자 0.9초); the value
 * at once with reduced motion. Only the frames between are drawn here; the value itself is the server's.
 */
export function useCountUp(target: number | null, durationMs = 1200): number | null {
  const reduced = reducedMotion();
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (target === null || reduced || target === 0) {
      return;
    }
    const start = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      setShown(Math.round(target * (1 - (1 - progress) ** 3)));
      if (progress < 1) {
        frame = requestAnimationFrame(tick);
      }
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, durationMs, reduced]);
  if (target === null) {
    return null;
  }
  return reduced || target === 0 ? target : Math.min(shown, target);
}
