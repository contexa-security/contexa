import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HttpError, postJson } from '../../api/http';
import { useLabOptions } from '../../api/lab';
import { useLiveConfig, useRuleCases, useVisitor } from '../../api/queries';
import { contexaBetter } from '../../domain/rules';
import { SCENARIO, sceneRequest } from '../../domain/show';
import type { LiveRunView } from '../../api/types';
import { AppHeader } from '../../components/AppHeader';
import { StateScreen } from '../../components/StateScreen';
import { ActBar } from '../../components/show/ActBar';
import { AdoptScene } from './AdoptScene';
import { RulesScene } from './RulesScene';
import { StartScene } from './StartScene';
import { StreamScene } from './StreamScene';
import styles from './ShowPage.module.css';

type Scene = 'start' | 'attacker' | 'owner' | 'rules' | 'adopt';

const ACT: Readonly<Record<Scene, 0 | 1 | 2 | 3>> = { start: 0, attacker: 1, owner: 2, rules: 3, adopt: 3 };

/**
 * The demo as three acts (docs/showcase/파이널-데모-기획안.md, 화면설계서.md): the visitor steals administrator A's
 * account and exports a confidential project, does the same as the real administrator with an approved transfer, and
 * sees the lines that did it. Each scene runs live; the page never moves on by itself.
 */
export default function ShowPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const visitor = useVisitor();
  const config = useLiveConfig();
  const ruleCases = useRuleCases();
  // The acts' requests come from their designed cases and the employee records (H-03).
  const options = useLabOptions();
  const caseOf = (key: string) => options.data?.cases.find((candidate) => candidate.key === key);
  const attackerCase = caseOf(SCENARIO.attacker);
  const ownerCase = caseOf(SCENARIO.owner);
  const attackerRequest = options.data && attackerCase ? sceneRequest(attackerCase, options.data) : null;
  const ownerRequest = options.data && ownerCase ? sceneRequest(ownerCase, options.data) : null;
  // Gate G-3: the rule-limits scene opens only when Contexa does better than the published rules on real runs.
  const rulesOpen = ruleCases.data ? contexaBetter(ruleCases.data.cases) : false;
  const [scene, setScene] = useState<Scene>('start');
  const main = useRef<HTMLElement>(null);
  const firstScene = useRef(true);

  // A new scene starts at the top, and screen readers start at its title; the first screen keeps the page's own focus.
  useEffect(() => {
    if (firstScene.current) {
      firstScene.current = false;
      return;
    }
    window.scrollTo({ top: 0 });
    main.current?.querySelector<HTMLElement>('h1')?.focus({ preventScroll: true });
  }, [scene]);

  /** A run still waiting for the visitor (the attacker's second try, a check) ends before the next scene. */
  async function moveOn(next: Scene) {
    const current = queryClient.getQueryData<LiveRunView>(['live-run']);
    if (current && (current.status === 'AWAITING' || current.status === 'CHALLENGE')) {
      const response = await postJson<LiveRunView>('/api/live/runs/current/abandon', {});
      if (response.body && response.status < 300) {
        queryClient.setQueryData(['live-run'], response.body);
      }
    }
    setScene(next);
  }

  const liveClosed = config.isError && config.error instanceof HttpError && config.error.status === 404;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" ref={main} className={styles.page} data-scene={scene}>
        <ActBar act={ACT[scene]} />
        {scene === 'start' ? <StartScene onStart={() => setScene('attacker')} /> : null}
        {scene === 'attacker' || scene === 'owner' ? (
          <>
            {config.isPending ? <StateScreen kind="loading" /> : null}
            {liveClosed ? <StateScreen kind="liveClosed" recordTo="/benchmark" /> : null}
            {config.isError && !liveClosed ? (
              <StateScreen kind="error" onRetry={() => void config.refetch()} />
            ) : null}
            {options.isError && !liveClosed ? (
              <StateScreen kind="error" onRetry={() => void options.refetch()} />
            ) : null}
            {config.data && options.data && attackerRequest && ownerRequest ? (
              <StreamScene
                key={scene}
                role={scene === 'attacker' ? 'attacker' : 'owner'}
                gate={{
                  visitorReady: visitor.isSuccess,
                  turnstileSiteKey: config.data.turnstileSiteKey,
                  remainingToday: config.data.remainingToday,
                }}
                request={scene === 'attacker' ? attackerRequest : ownerRequest}
                previous={scene === 'attacker' ? null : attackerRequest}
                assessmentReasons={options.data.assessmentReasons}
                onNext={() => void moveOn(scene === 'attacker' ? 'owner' : rulesOpen ? 'rules' : 'adopt')}
              />
            ) : null}
          </>
        ) : null}
        {scene === 'rules' && ruleCases.data ? (
          <RulesScene cases={ruleCases.data.cases} onNext={() => setScene('adopt')} />
        ) : null}
        {scene === 'adopt' ? <AdoptScene onRestart={() => setScene('start')} /> : null}
      </main>
    </>
  );
}
