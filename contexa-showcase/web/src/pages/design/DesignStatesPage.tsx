import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { StreamProgress, StreamSample } from '../../api/types';
import { AppHeader } from '../../components/AppHeader';
import { StreamMeter } from '../../components/StreamMeter';
import type { StateKind } from '../../components/StateScreen';
import { StateScreen } from '../../components/StateScreen';
import styles from './DesignStatesPage.module.css';

/** Development-only gallery of the state screens (deck p.20), with sample values marked as samples. */
const SAMPLE_CAUSE = {
  ko: '예시: 본인 확인 뒤 원래 요청을 15초 안에 다시 보내지 못했습니다.',
  en: 'Sample: the original request could not be sent again within 15 seconds after the identity check.',
} as const;

const KINDS: readonly StateKind[] = [
  'loading',
  'error',
  'notReady',
  'queued',
  'waiting',
  'outage',
  'challengeCancelled',
  'challengeExpired',
  'dailyLimit',
  'paused',
  'recoveryFailed',
];

function noop() {
  return undefined;
}

/** Sample pace of the business stream (8 items every 50 ms), cut by the engine or not. */
function sampleStream(delivered: number, total: number, cut: boolean, interrupted: boolean): StreamProgress {
  const samples: StreamSample[] = [];
  for (let at = 40; ; at += 100) {
    const items = Math.min(delivered, Math.floor(((at - 40) / 50) * 8) + 1);
    samples.push([at, items]);
    if (items >= delivered) {
      return { total, delivered, firstLineMs: 40, endMs: at, cut, interrupted, samples };
    }
  }
}

const SAMPLE_STREAMS: readonly { readonly key: string; readonly stream: StreamProgress }[] = [
  { key: 'stream-cut', stream: sampleStream(412, 4831, true, false) },
  { key: 'stream-done', stream: sampleStream(600, 600, false, false) },
  { key: 'stream-interrupted', stream: sampleStream(96, 4831, false, true) },
];

export default function DesignStatesPage() {
  const { i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [replay, setReplay] = useState(0);
  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <h1 className="visually-hidden">State screens</h1>
        {KINDS.map((kind) => (
          <section key={kind} className={styles.item} aria-label={kind}>
            <h2 className={styles.code}>{kind}</h2>
            <StateScreen
              kind={kind}
              onRetry={noop}
              recordTo="/replay/A3"
              onSignIn={noop}
              onNotify={noop}
              cause={SAMPLE_CAUSE[language]}
              remainingSeconds={12}
              queuePosition={3}
            />
          </section>
        ))}
        {SAMPLE_STREAMS.map(({ key, stream }) => (
          <section key={key} className={styles.item} aria-label={key} data-sample={key}>
            <h2 className={styles.code}>{key}</h2>
            <StreamMeter key={replay} stream={stream} play={replay > 0} />
          </section>
        ))}
        <button type="button" className={styles.replay} onClick={() => setReplay((value) => value + 1)}>
          replay streams
        </button>
      </main>
    </>
  );
}
