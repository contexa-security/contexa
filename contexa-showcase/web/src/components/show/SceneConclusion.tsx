import styles from './SceneConclusion.module.css';

export type ConclusionTone = 'contexa' | 'safe' | 'loss' | 'halt' | 'idle';

export interface ConclusionLine {
  readonly text: string;
  readonly tone?: ConclusionTone;
}

interface SceneConclusionProps {
  /** The scene's one L1 line; null while the answer is still coming, when the waiting text holds its place. */
  readonly headline: ConclusionLine | null;
  readonly waiting: string;
  readonly details?: readonly ConclusionLine[];
}

/**
 * The scene's conclusion (docs/showcase/화면설계서.md 1.2): one sentence with its subject and number, in the colour of
 * what it means, and at most a few short lines under it. The place is kept while the answer comes so nothing moves.
 */
export function SceneConclusion({ headline, waiting, details = [] }: SceneConclusionProps) {
  return (
    <div className={styles.conclusion} aria-live="polite">
      {headline ? (
        <p className={styles.headline} data-tone={headline.tone ?? 'contexa'}>
          {headline.text}
        </p>
      ) : (
        <p className={styles.waiting}>{waiting}</p>
      )}
      {headline
        ? details.map((line) => (
            <p key={line.text} className={styles.detail} data-tone={line.tone ?? 'idle'}>
              {line.text}
            </p>
          ))
        : null}
    </div>
  );
}
