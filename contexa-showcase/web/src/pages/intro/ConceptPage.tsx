import { Trans, useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useLabOptions } from '../../api/lab';
import { SourceMark } from '../../components/common/SourceMark';
import { Term } from '../../components/common/Glossary';
import { Icon } from '../../components/Icon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { NextLink } from '../../components/journey/StepParts';
import { count } from '../../journey/format';
import styles from './ConceptPage.module.css';

/** The case whose export the picture shows: try 1's (A3), so the number is the one the visitor will send. */
const CASE = 'A3';

/**
 * G2, the problem (g2-concept, 7.5): layer 1 shows sign-in checking once and never asking again; "next" draws layer 2
 * over the same picture (the real employee and someone using a stolen account send the same request) with the one-line
 * conclusion, and the next "next" goes on to the five approaches. Layer 2 has its own address (?layer=2).
 */
export default function ConceptPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const layer2 = params.get('layer') === '2';
  const items =
    useLabOptions().data?.cases.find((candidate) => candidate.key === CASE)?.requests[0]?.items ?? null;
  const steps = [
    { name: t('concept.signIn'), state: t('concept.checked'), checked: true },
    { name: t('concept.menu'), state: t('concept.notAgain'), checked: false },
    { name: t('concept.documents'), state: t('concept.notAgain'), checked: false },
    {
      name: t('concept.export', { items: items === null ? '-' : count(items, language) }),
      state: t('concept.notAgain'),
      checked: false,
    },
  ];
  return (
    <RouteScreen
      title={t('concept.title')}
      purpose={
        <Trans
          i18nKey="concept.purpose"
          components={{
            session: <Term term="session">{''}</Term>,
            permission: <Term term="permission">{''}</Term>,
          }}
        />
      }
      source={
        items === null ? null : <SourceMark kind="CASE">{t('concept.source', { case: CASE })}</SourceMark>
      }
      nextLabel={t('concept.nextJudge')}
      main={
        layer2 ? undefined : <NextLink to="/intro/concept?route=intro&layer=2" label={t('concept.reveal')} />
      }
    >
      <figure className={styles.figure} aria-label={t('concept.figure')}>
        <ol className={styles.steps}>
          {steps.map((step, index) => (
            <li key={step.name} className={styles.step}>
              {index > 0 ? <Icon name="arrowRight" className={styles.arrow} /> : null}
              <span className={styles.card} data-checked={step.checked || undefined}>
                <span className={styles.name}>{step.name}</span>
                <span className={styles.state}>
                  <Icon name={step.checked ? 'check' : 'dash'} />
                  {step.state}
                </span>
              </span>
            </li>
          ))}
        </ol>
        {layer2 ? (
          <p className={styles.layer2}>
            <Icon name="user" className={styles.layerIcon} />
            <span>
              <Trans
                i18nKey="concept.sameLine"
                components={{
                  employee: <strong className={styles.person} />,
                  stolen: <strong className={styles.person} data-stolen />,
                }}
              />
            </span>
          </p>
        ) : null}
      </figure>
      {layer2 ? <p className={styles.conclusion}>{t('concept.conclusion')}</p> : null}
    </RouteScreen>
  );
}
