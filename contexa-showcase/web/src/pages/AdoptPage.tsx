import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useStats } from '../api/queries';
import { AppHeader } from '../components/AppHeader';
import { SourceMark } from '../components/common/SourceMark';
import { utcTime } from '../journey/format';
import styles from './AdoptPage.module.css';

const REPOSITORY = 'https://github.com/contexa-security/contexa';
const DOCS = 'https://docs.ctxa.ai';
const QUICKSTART = 'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-quickstart';
const LEGACY = 'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-legacy-system';

/** The real coordinates and annotations of the current Contexa release (README, release 0.1.0). */
const STEP_CODE = {
  attach: `dependencies {
    implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"
}

@SpringBootApplication
@EnableAISecurity
public class MyApplication {
}

@Protectable(sync = true)
@PostMapping("/api/projects/{id}/exports")
public ExportJob export(@PathVariable String id) {
    return exports.start(id);
}`,
  observe: `contexa:
  security:
    zerotrust:
      mode: SHADOW`,
  enforce: `contexa:
  security:
    zerotrust:
      mode: ENFORCE`,
} as const;

/**
 * Adopting Contexa (deck p.16): attach, observe in Shadow mode, then enforce. The Shadow numbers are this demo's own
 * resolved decisions; in Shadow mode they would have been recorded without being enforced.
 */
export default function AdoptPage() {
  const { t, i18n } = useTranslation();
  const stats = useStats();
  const count = new Intl.NumberFormat(i18n.language === 'ko' ? 'ko-KR' : 'en-US');
  const actions = stats.data?.engineActions;
  const decisions = stats.data?.engineDecisions ?? null;

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.header}>
          <h1 className={styles.title}>{t('adopt.title')}</h1>
          <p className={styles.lead}>{t('adopt.lead')}</p>
        </header>
        <ol className={styles.steps}>
          <li className={styles.step}>
            <h2 className={styles.stepTitle}>{t('adopt.attach.title')}</h2>
            <p className={styles.text}>
              <Trans i18nKey="adopt.attach.body" components={{ code: <code data-original /> }} />
            </p>
            <CodeBlock code={STEP_CODE.attach} label={t('adopt.attach.title')} />
          </li>
          <li className={styles.step}>
            <h2 className={styles.stepTitle}>{t('adopt.observe.title')}</h2>
            <p className={styles.text}>{t('adopt.observe.body')}</p>
            <CodeBlock code={STEP_CODE.observe} label={t('adopt.observe.title')} />
            {actions && decisions !== null && decisions > 0 ? (
              <dl className={styles.shadow}>
                <div>
                  <dt>{t('adopt.observe.block')}</dt>
                  <dd>{count.format(actions.BLOCK)}</dd>
                </div>
                <div>
                  <dt>{t('adopt.observe.challenge')}</dt>
                  <dd>{count.format(actions.CHALLENGE)}</dd>
                </div>
                <div>
                  <dt>{t('adopt.observe.review')}</dt>
                  <dd>{count.format(actions.ESCALATE)}</dd>
                </div>
              </dl>
            ) : null}
            {decisions !== null && decisions > 0 ? (
              <p className={styles.note}>
                {t('adopt.observe.note', { count: count.format(decisions) })}{' '}
                <SourceMark kind="ENGINE">
                  {t('adopt.observe.source', {
                    from: stats.data?.runs.firstAt ? utcTime(stats.data.runs.firstAt) : '-',
                    to: stats.data?.runs.lastAt ? utcTime(stats.data.runs.lastAt) : '-',
                  })}
                </SourceMark>
              </p>
            ) : null}
          </li>
          <li className={styles.step}>
            <h2 className={styles.stepTitle}>{t('adopt.enforce.title')}</h2>
            <p className={styles.text}>{t('adopt.enforce.body')}</p>
            <CodeBlock code={STEP_CODE.enforce} label={t('adopt.enforce.title')} />
          </li>
        </ol>
        <section className={styles.section} aria-labelledby="adopt-legacy">
          <h2 id="adopt-legacy" className={styles.sectionTitle}>
            {t('adopt.legacy.title')}
          </h2>
          <p className={styles.text}>{t('adopt.legacy.body')}</p>
        </section>
        <nav className={styles.links} aria-label={t('adopt.links')}>
          <a href={REPOSITORY} target="_blank" rel="noopener noreferrer">
            {t('adopt.repository')}
          </a>
          <a href={DOCS} target="_blank" rel="noopener noreferrer">
            {t('adopt.docs')}
          </a>
          <a href={QUICKSTART} target="_blank" rel="noopener noreferrer">
            {t('adopt.quickstart')}
          </a>
          <a href={LEGACY} target="_blank" rel="noopener noreferrer">
            {t('adopt.legacyExample')}
          </a>
        </nav>
      </main>
    </>
  );
}

/** The lines that turn Contexa on or protect a method are the only ones lit, as in the demo's last scene. */
const NEWLINE = String.fromCharCode(10);
const LIT = /^\s*(@EnableAISecurity|@Protectable|mode: (SHADOW|ENFORCE))/;

function CodeBlock({ code, label }: { readonly code: string; readonly label: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className={styles.code}>
      <pre className={styles.pre} tabIndex={0} aria-label={label} data-original>
        <code>
          {code.split(NEWLINE).map((line, index) => (
            <span key={index} className={LIT.test(line) ? styles.lineOn : undefined}>
              {line}
              {NEWLINE}
            </span>
          ))}
        </code>
      </pre>
      <div className={styles.codeActions}>
        <button type="button" className={styles.copy} onClick={() => void copy()}>
          {t('adopt.copy')}
        </button>
        <span className={styles.copied} role="status">
          {copied ? t('adopt.copied') : ''}
        </span>
      </div>
    </div>
  );
}
