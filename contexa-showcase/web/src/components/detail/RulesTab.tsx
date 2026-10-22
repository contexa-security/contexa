import { Fragment } from 'react';
import { useTranslation } from 'react-i18next';
import { useExchanges, useReceived, type DecisionAnatomyView } from '../../api/anatomy';
import { useTeasers } from '../../api/teasers';
import { count } from '../../journey/format';
import { G_RULES_CARDS, G_RULES_PLAIN } from '../../pages/intro/rulesLines';
import { countedCall } from '../inside/promptSections';
import { Icon } from '../Icon';
import { StateScreen } from '../StateScreen';
import { VerdictChip } from '../VerdictChip';
import { analysed, challengeOutcomes, knownOutcome, ruleKey, type ChallengeOutcomes } from './detailWords';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';

const VERDICTS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;

/**
 * The rule lines that define the four judgments, of the v20 and the v21 texts; the tab states them with the judgments,
 * not again in the list.
 */
const DEFINITIONS: ReadonlySet<string> = new Set([
  ...VERDICTS.map((verdict) => `gRules.plain.${verdict}`),
  ...VERDICTS.map((verdict) => `gRules.plain.v21${verdict}`),
  'gRules.plain.v21ESCALATEBefore216',
]);

/**
 * The published rules (RO-1, RO-8): the four judgments and what each means (the rules' first four lines), with the
 * outcomes of every identity check Contexa asked for in this demo under the identity check (the counts 2-6 left out);
 * the overlap rule (a judgment is never overwritten by a looser one); then the other lines of the rules this request's
 * AI received that have plain words, in the order of the text, each marked when the request met it. The whole text is
 * the original record's. Without the text (past its retention) the tab says so and states the gist of the rules the
 * demo sends.
 */
export function RulesTab({ view, runId, step }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const exchanges = useExchanges(runId, step, true);
  const received = useReceived(analysed(view) ? runId : null, step).data ?? null;
  const outcomes = challengeOutcomes(useTeasers().data);
  if (exchanges.isPending) {
    return <StateScreen kind="loading" />;
  }
  const system = exchanges.data?.kept ? (countedCall(exchanges.data.calls)?.systemPrompt ?? null) : null;
  const met = new Set(
    (received?.minimumRules?.rules ?? []).filter((rule) => rule.met).map((rule) => rule.line),
  );
  const lines = (system ?? '').split('\n').flatMap((text) => {
    const plain = G_RULES_PLAIN.find((candidate) => text.startsWith(candidate.starts));
    return plain && !DEFINITIONS.has(plain.key)
      ? [{ key: ruleKey(plain.key, (key) => i18n.exists(key)), met: met.has(text.trim()) }]
      : [];
  });
  const missing =
    exchanges.data?.missing === 'PAST_RETENTION'
      ? 'detail.r7.rules.gone'
      : system === null
        ? 'detail.r7.rules.notKept'
        : 'detail.r7.rules.noLines';

  return (
    <TabFrame source={t(outcomes ? 'detail.r7.rules.source' : 'detail.r7.rules.sourceText')}>
      <section className={styles.group} aria-labelledby="detail-rules-four" data-block>
        <h3 id="detail-rules-four" className={styles.title}>
          {t('detail.r7.rules.four')}
        </h3>
        <ul className={styles.list}>
          {VERDICTS.map((verdict) => (
            <li key={verdict} className={styles.item}>
              <span className={styles.value}>
                <VerdictChip verdict={verdict} />
                <span>{t(`gRules.verdict.${verdict}`)}</span>
              </span>
              {verdict === 'CHALLENGE' && outcomes ? <Outcomes outcomes={outcomes} /> : null}
            </li>
          ))}
        </ul>
        <p className={styles.line}>
          <span className={styles.strong}>{t('detail.r7.rules.overlap')}</span>{' '}
          {t('detail.r7.rules.overlapText')}
        </p>
      </section>
      <section className={styles.group} aria-labelledby="detail-rules-lines" data-block>
        <h3 id="detail-rules-lines" className={styles.title}>
          {t('detail.r7.rules.lines')}
        </h3>
        <p className={styles.aside}>{t(lines.length > 0 ? 'detail.r7.rules.linesLead' : missing)}</p>
        {lines.length > 0 ? (
          <ol className={styles.list}>
            {lines.map((line, index) => (
              // The text's own order is the identity of a line.
              <li key={`${line.key}-${index}`} className={styles.item}>
                <span>{t(line.key)}</span>
                {line.met ? (
                  <span className={styles.mark}>
                    <Icon name="check" />
                    {t('detail.r7.rules.met')}
                  </span>
                ) : null}
              </li>
            ))}
          </ol>
        ) : (
          <ul className={styles.list}>
            {G_RULES_CARDS.map((card) => (
              <li key={card.key}>{t(`gRules.line.${card.key}`)}</li>
            ))}
          </ul>
        )}
      </section>
    </TabFrame>
  );
}

/**
 * The outcomes of the demo's identity checks as the portal counted them: the total, then each outcome with its count,
 * the passed ones with how many sent the original request again; an outcome without words of its own is shown as
 * "other" with its recorded name.
 */
function Outcomes({ outcomes }: { readonly outcomes: ChallengeOutcomes }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <span className={styles.from}>
      {t('detail.r7.rules.outcomes', { total: count(outcomes.total, language) })}{' '}
      {/* L-43: each outcome is one piece (its name with its count); the line wraps only between the pieces. */}
      {outcomes.outcomes.map((entry, index) => (
        <Fragment key={entry.key}>
          {index > 0 ? ' · ' : null}
          <span className={styles.outcome}>
            {entry.key === 'ANSWERED' && outcomes.resumed !== null ? (
              t('detail.r7.rules.outcome.answeredResumed', {
                n: count(entry.n, language),
                resumed: count(outcomes.resumed, language),
              })
            ) : knownOutcome(entry.key) ? (
              t(`detail.r7.rules.outcome.${entry.key}`, { n: count(entry.n, language) })
            ) : (
              <>
                {t('detail.r7.rules.outcome.other', { n: count(entry.n, language) })}{' '}
                <code className={styles.original} data-original>
                  {entry.key}
                </code>
              </>
            )}
          </span>
        </Fragment>
      ))}
    </span>
  );
}
