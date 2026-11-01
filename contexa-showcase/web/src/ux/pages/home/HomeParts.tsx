import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { benchOf, digitsOf, readable, shareText, testOf, useBundle, words } from '../../bench/bundle';
import { Badge, ButtonLink, Icon, type UxIconName } from '../../ui';
import styles from './Home.module.css';

/** The four steps every threat scenario walks (기획안 7.0 d-home 진행 방식). */
export function HowBand() {
  const { t } = useTranslation();
  return (
    <section aria-label={t('ux.home.how.label')} className={styles.how}>
      <ol className={styles.howList}>
        {[1, 2, 3, 4].map((n) => (
          <li key={n} className={styles.howStep}>
            <span className={styles.howN} aria-hidden="true">
              {n}
            </span>
            <div>
              <b className={styles.howTitle}>{t(`ux.home.how.${n}.title`)}</b>
              <span className={styles.howDesc}>{t(`ux.home.how.${n}.desc`)}</span>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

interface ScenarioCardProps {
  readonly icon: UxIconName;
  readonly title: string;
  readonly situation: string;
  readonly check: string;
  readonly tags: readonly ReactNode[];
  /** The size of the scenario in requests or the kind of run, beside its action. */
  readonly foot: ReactNode;
  readonly to: string;
  /** The recommended first run: the gold line and the primary action. */
  readonly recommended?: boolean;
}

/**
 * A threat scenario on the start screen: icon, tags, the situation in one line and what it checks. The result is not
 * shown ahead, so the prediction keeps its meaning (기획안 7.0).
 */
export function ScenarioCard({
  icon,
  title,
  situation,
  check,
  tags,
  foot,
  to,
  recommended = false,
}: ScenarioCardProps) {
  const { t } = useTranslation();
  return (
    <article className={styles.scenario} data-recommended={recommended || undefined}>
      <div className={styles.scenarioTop}>
        <span className={styles.scenarioIcon}>
          <Icon name={icon} size="xl" />
        </span>
        <span className={styles.scenarioTags}>
          {recommended ? (
            <Badge tone="line" icon="star">
              {t('ux.flow.recommended')}
            </Badge>
          ) : null}
          {tags.map((tag, index) => (
            <Badge key={index} tone="line">
              {tag}
            </Badge>
          ))}
        </span>
      </div>
      <h3 className={styles.scenarioTitle}>{title}</h3>
      <p className={styles.scenarioSituation}>{situation}</p>
      <div className={styles.scenarioCheck}>
        <span>{t('ux.home.check')}</span>
        {check}
      </div>
      <div className={styles.scenarioFoot}>
        <span>{foot}</span>
        <ButtonLink
          to={to}
          size="sm"
          variant={recommended ? 'primary' : 'secondary'}
          iconAfter="arrow-right"
          label={`${title} ${t('ux.flow.run')}`}
        >
          {t('ux.flow.run')}
        </ButtonLink>
      </div>
    </article>
  );
}

/**
 * The standard benchmarks on the start screen (DEC-23, DEC-58): the result bundle's headline tests with their
 * conditions, the unprotected and the protected value, a line on what the protection costs legitimate work and the
 * victim agent, and the way to the full results. Without the bundle, one line and the way (ST-67).
 */
export function BenchBand() {
  const { t, i18n } = useTranslation();
  const bundle = useBundle();
  const data = readable(bundle.data) ? bundle.data : null;
  if (bundle.isPending) {
    return null;
  }
  if (!data) {
    return (
      <section aria-label={t('ux.home.bench.label')} className={styles.benchFailed}>
        <span>{t('ux.home.bench.failed')}</span>
        <ButtonLink to="/benchmarks" variant="text" size="sm" icon="arrow-right">
          {t('ux.home.bench.all')}
        </ButtonLink>
      </section>
    );
  }
  const benign = benchOf(data, 'agentdojo')?.impact.find(
    (row) => row.test === 'S-1a' && row.metric === 'Benign Utility',
  );
  const cost =
    benign?.unprotected && benign.protected
      ? t('ux.home.bench.cost', {
          from: shareText(benign.unprotected, i18n.language, digitsOf('agentdojo')).value,
          to: shareText(benign.protected, i18n.language, digitsOf('agentdojo')).value,
          test: words(testOf(data, 'agentdojo', 'S-1a')?.label ?? { ko: 'S-1a', en: 'S-1a' }, i18n.language),
        })
      : null;
  return (
    <section aria-labelledby="home-bench" className={styles.bench}>
      <div className={styles.benchHead}>
        <h2 id="home-bench" className={styles.benchTitle}>
          {t('ux.home.bench.label')}
        </h2>
        <span className={styles.howDesc}>{t('ux.home.bench.sub')}</span>
      </div>
      {data.headline.map((headline) => {
        const bench = benchOf(data, headline.benchmark);
        const test = testOf(data, headline.benchmark, headline.test);
        if (!bench || !test || !test.unprotected || !test.protected) {
          return null;
        }
        const digits = digitsOf(bench.id);
        const before = shareText(test.unprotected, i18n.language, digits);
        const after = shareText(test.protected, i18n.language, digits);
        return (
          <div key={bench.id} className={styles.benchCell}>
            <span className={styles.benchName}>
              {bench.name} · {test.metric}
            </span>
            <span className={styles.benchValues}>
              <s
                className={styles.benchBefore}
                aria-label={t('ux.home.bench.before', { value: before.value })}
              >
                {before.value}
              </s>
              <Icon name="arrow-right" size="sm" />
              <b className={styles.benchAfter} aria-label={t('ux.home.bench.after', { value: after.value })}>
                {after.value}
              </b>
            </span>
            <span className={styles.howDesc}>
              {words(test.label, i18n.language)}
              {after.upper ? ' · ' : null}
              {after.upper ? t('ux.bench.share.upper', { value: after.upper }) : null}
            </span>
          </div>
        );
      })}
      <div className={styles.benchFoot}>
        <span>
          {[cost, t('ux.home.bench.victim', { victim: data.program.models.victimBase })]
            .filter(Boolean)
            .join(' · ')}
        </span>
        <ButtonLink to="/benchmarks" variant="secondary" size="sm" icon="arrow-right">
          {t('ux.home.bench.all')}
        </ButtonLink>
      </div>
    </section>
  );
}
