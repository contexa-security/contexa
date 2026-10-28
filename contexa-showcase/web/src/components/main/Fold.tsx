import { useState, type ReactNode } from 'react';
import styles from './Fold.module.css';

interface FoldProps {
  /** Names the fold for the automatic checks (data-fold). */
  readonly name: string;
  /** The one line that opens it: what is behind it, in words of its own. */
  readonly summary: ReactNode;
  readonly children: ReactNode;
  /** True while what it holds is live (a run going on): it opens, and the visitor may still close it. */
  readonly open?: boolean;
}

/**
 * What a screen keeps one press away (구현계획 R-N2, AC-N2): the first view says what the screen is and asks one
 * thing; the rest of the facts wait behind a line that names them. The line is a whole 44 px target for a finger, and
 * the facts stay in the page for screen readers and search, so nothing is dropped, only put in a layer.
 */
export function Fold({ name, summary, children, open = false }: FoldProps) {
  const [shown, setShown] = useState(open);
  // Told to open (a run going on), it opens once; the visitor's own press decides after that.
  const [told, setTold] = useState(open);
  if (open !== told) {
    setTold(open);
    if (open) {
      setShown(true);
    }
  }
  return (
    <details
      className={styles.fold}
      data-fold={name}
      open={shown}
      onToggle={(event) => setShown(event.currentTarget.open)}
    >
      <summary className={styles.line}>{summary}</summary>
      {children}
    </details>
  );
}
