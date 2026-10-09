import { useTranslation } from 'react-i18next';
import { AppHeader } from '../../components/AppHeader';
import { Term, TermScope } from '../../components/common/Glossary';
import { SourceMark } from '../../components/common/SourceMark';
import { CumulativeMeter } from '../../components/inside/CumulativeMeter';
import { DecisionDetail, InsidePanel } from '../../components/inside/InsidePanel';
import { ActEndCard, TeaserBand } from '../../components/journey/Cards';
import { GoalChips, IdentityDefinition, JustSaw, RoleBanner } from '../../components/journey/JourneyParts';
import styles from './DesignStatesPage.module.css';

/**
 * Development-only gallery of the shared components of the screen design v2.3 (S2), for the four-width captures and
 * the accessibility check before the screens use them. Every value here is a sample and is marked as one; Vite leaves
 * this page out of the production bundle.
 */
export default function DesignPartsPage() {
  const { t } = useTranslation();
  const sample = (text: string) => `${text} (예시 · sample)`;
  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <h1>{sample('S2 shared components')}</h1>
        <TermScope>
          <section aria-label="thread">
            <IdentityDefinition />
            <GoalChips differences={[3, 5]} />
            <RoleBanner role="owner" name="Administrator A" />
            <p>
              <Term term="permission">{t('glossary.permission.term')}</Term> ·{' '}
              <Term term="sync">{t('glossary.sync.term')}</Term>
            </p>
            <JustSaw difference={2} sentence="e1Compare" values={{ n: 3 }} />
          </section>
          <section aria-label="cards">
            <TeaserBand
              copy={{ question: sample(t('teaser.HOOK_TRY.question')), teaser: '…', teaserItem: null }}
            />
            <ActEndCard
              act={1}
              differences={[1, 2, 4, 5]}
              sentence={sample('…')}
              measured
              runId="run-000000000000"
              next={{ question: sample(t('teaser.E1_AFTER_RULES.question')), teaser: null, teaserItem: null }}
              continueTo="/try/owner/scene"
              back={{ to: '/try/attacker/after', label: sample('…') }}
              resendAsyncTo="/try/timing/try?from=attacker"
              benchmarkTo="/benchmark"
              shareUrl="http://localhost/try/attacker/after"
            />
          </section>
          <section aria-label="inside">
            <InsidePanel
              cells={[
                { id: 'request', state: 'done', summary: sample('…') },
                { id: 'usual', state: 'done' },
                { id: 'company', state: 'done' },
                { id: 'history', state: 'done' },
                { id: 'prompt', state: 'done' },
                { id: 'judgement', state: 'active' },
                {
                  id: 'decision',
                  state: 'decision',
                  detail: (
                    <DecisionDetail
                      plain={sample('…')}
                      original="sample"
                      cited={['baseline', 'approval']}
                      riskScore={null}
                      confidence={0.5}
                      inspector={{ met: 1, total: 2, names: [] }}
                    />
                  ),
                },
                { id: 'followUp', state: 'waiting' },
                { id: 'learning', state: 'waiting' },
              ]}
            />
            <CumulativeMeter
              caption={sample(t('meter.title'))}
              rows={[
                {
                  request: 1,
                  observations: 1,
                  deltas: 1,
                  verdict: 'CHALLENGE',
                  riskScore: 0.5,
                  prior: false,
                },
                { request: 2, observations: null, deltas: null, verdict: null, riskScore: null, prior: true },
              ]}
            />
            <p>
              {sample('value')}
              <SourceMark kind="MEASUREMENT" measured>
                {sample('formula')}
              </SourceMark>
            </p>
          </section>
        </TermScope>
      </main>
    </>
  );
}
