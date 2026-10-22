import { Trans, useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useBenchmark } from '../api/benchmark';
import { useStats } from '../api/queries';
import { usePublicSettings } from '../api/settings';
import { AppHeader } from '../components/AppHeader';
import { Icon } from '../components/Icon';
import { SourceLine } from '../components/journey/FrameParts';
import { ScreenBody } from '../components/journey/ScreenBody';
import { NextLink } from '../components/journey/StepParts';
import step from '../components/journey/StepParts.module.css';
import { count } from '../journey/format';
import frame from './try/Experience.module.css';
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
} as const;

/**
 * The adopt space's three views, walked in order (화면재편-구현계획 5절, RO-4, RO-9): what changes when you adopt it
 * (the cells screen 5-3 leaves here), how to add it, and how to turn it on. Each view is one screen of the shared frame,
 * kept within the limits by splitting rather than folding; the address names the view (?step=).
 */
const VIEWS = ['change', 'attach', 'on'] as const;
type View = (typeof VIEWS)[number];

function viewOf(value: string | null): View {
  return VIEWS.find((view) => view === value) ?? 'change';
}

function adoptPath(view: View): string {
  return view === 'change' ? '/adopt' : `/adopt?step=${view}`;
}

export default function AdoptPage() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const view = viewOf(params.get('step'));
  return (
    <>
      <AppHeader space={{ name: t('frame.space.adopt'), step: t(`space.r7.adopt.${view}.step`) }} />
      <main id="main" className={frame.page} data-type="T7">
        {view === 'change' ? <ChangeView /> : view === 'attach' ? <AttachView /> : <OnView />}
      </main>
    </>
  );
}

/**
 * What changes, and for whom (the three cells 5-3 leaves to this screen): the data kept with its retention, the
 * employee's side and the security team's side. The retention is the running settings', the employee's counts the
 * benchmark's measurement of Contexa; a value the server does not give is said, never filled in.
 */
function ChangeView() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const settings = usePublicSettings();
  const benchmark = useBenchmark(null);
  const setting = settings.data ?? null;
  const contexa = benchmark.data?.controls.find((score) => score.control === 'D') ?? null;
  const number = (value: number) => count(value, language);

  const retention = setting?.retention ?? null;
  const kept = retention
    ? retention.behaviorDays === null
      ? t('space.r7.adopt.data.keptNoBehavior', { original: number(retention.promptOriginalDays) })
      : t('space.r7.adopt.data.kept', {
          behavior: number(retention.behaviorDays),
          original: number(retention.promptOriginalDays),
        })
    : settings.isError
      ? t('space.r7.adopt.data.keptNone')
      : null;
  const sealed = setting?.sealedEvidence ?? null;
  const seal =
    sealed && sealed.cleanPeriodDays !== null && sealed.samplePercent !== null
      ? t('space.r7.adopt.data.seal', {
          days: number(sealed.cleanPeriodDays),
          percent: number(sealed.samplePercent),
        })
      : settings.isPending
        ? null
        : t('space.r7.adopt.data.sealPlain');
  const counts = contexa
    ? t('space.r7.adopt.employee.counts', {
        normal: number(contexa.falseBlock.total),
        blocked: number(contexa.falseBlock.hits),
        checked: number(contexa.friction.hits),
      })
    : null;
  const source =
    retention && contexa ? (
      t('space.r7.adopt.change.source')
    ) : retention ? (
      t('space.r7.adopt.change.sourceSettings')
    ) : contexa ? (
      <SourceLine kind="measured" />
    ) : null;

  const cells = [
    { id: 'data', lines: [t('space.r7.adopt.data.what'), kept, seal] },
    { id: 'employee', lines: [t('space.r7.adopt.employee.what'), counts] },
    { id: 'admin', lines: [t('space.r7.adopt.admin.what')] },
  ] as const;

  return (
    <ScreenBody
      title={t('space.r7.adopt.change.title')}
      purpose={t('space.r7.adopt.change.guide')}
      sourceLine={source}
      back={null}
      main={<NextLink to={adoptPath('attach')} label={t('space.r7.adopt.change.next')} />}
    >
      {/* One list of three cells: a name over its lines (the same cells as screen 5-3). */}
      <dl className={styles.cells} aria-label={t('space.r7.adopt.change.title')} data-block>
        {cells.map((cell) => (
          <div key={cell.id} className={styles.cell} data-cell={cell.id}>
            <dt className={styles.name}>{t(`space.r7.adopt.name.${cell.id}`)}</dt>
            {cell.lines.map((line, index) =>
              line ? (
                <dd key={index} className={styles.value}>
                  {line}
                </dd>
              ) : null,
            )}
          </div>
        ))}
      </dl>
    </ScreenBody>
  );
}

/** How to add it: the dependency and the two annotations, then the same for a legacy system, with their examples. */
function AttachView() {
  const { t } = useTranslation();
  return (
    <ScreenBody
      title={t('space.r7.adopt.attach.title')}
      purpose={t('space.r7.adopt.attach.guide')}
      back={{ to: adoptPath('change'), label: t('frame.back') }}
      main={<NextLink to={adoptPath('on')} label={t('space.r7.adopt.attach.next')} />}
    >
      <div className={styles.block}>
        <p className={styles.text}>
          <Trans
            i18nKey="space.r7.adopt.attach.body"
            components={{ code: <code className={styles.inline} data-original /> }}
          />
        </p>
        <CodeBlock code={STEP_CODE.attach} label={t('space.r7.adopt.attach.code')} />
        <nav className={styles.links} aria-label={t('space.r7.adopt.links')}>
          <ExternalLink href={QUICKSTART} label={t('adopt.quickstart')} />
          <ExternalLink href={REPOSITORY} label={t('adopt.repository')} />
        </nav>
      </div>
      <section className={styles.block} aria-labelledby="adopt-legacy">
        <h2 id="adopt-legacy" className={styles.name}>
          {t('space.r7.adopt.legacy.name')}
        </h2>
        <p className={styles.text}>{t('space.r7.adopt.legacy.body')}</p>
        <nav className={styles.links} aria-label={t('space.r7.adopt.legacy.links')}>
          <ExternalLink href={LEGACY} label={t('adopt.legacyExample')} />
        </nav>
      </section>
    </ScreenBody>
  );
}

/**
 * How to turn it on: record only first, then stop. The counts are this demo's own resolved judgments as the server
 * counted them (/api/stats); in record-only mode they would have been recorded without stopping anything. The mode the
 * demo runs in is the running settings'.
 */
function OnView() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const stats = useStats();
  const settings = usePublicSettings();
  const actions = stats.data?.engineActions ?? null;
  const decisions = stats.data?.engineDecisions ?? null;
  const counted = actions !== null && decisions !== null && decisions > 0;
  const mode = settings.data?.engine.effectiveMode ?? null;
  const modeKey =
    mode === 'ENFORCE' || mode === 'SHADOW' || mode === 'DISABLED' ? `space.r7.adopt.on.mode.${mode}` : null;
  const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : '-');

  return (
    <ScreenBody
      title={t('space.r7.adopt.on.title')}
      purpose={t('space.r7.adopt.on.guide')}
      sourceLine={
        counted
          ? t('space.r7.adopt.on.source', {
              from: day(stats.data?.runs.firstAt),
              to: day(stats.data?.runs.lastAt),
            })
          : null
      }
      back={{ to: adoptPath('attach'), label: t('frame.back') }}
      main={
        <a className={step.next} href={DOCS} target="_blank" rel="noopener noreferrer" data-main>
          {t('space.r7.adopt.docs')}
          <Icon name="arrowRight" className={step.nextIcon} />
        </a>
      }
    >
      <section className={styles.block} aria-labelledby="adopt-watch">
        <h2 id="adopt-watch" className={styles.name}>
          {t('space.r7.adopt.watch.name')}
        </h2>
        <p className={styles.text}>{t('space.r7.adopt.watch.body')}</p>
        <CodeBlock code={STEP_CODE.observe} label={t('space.r7.adopt.watch.code')} />
        {counted ? (
          <p className={styles.text}>
            {t('space.r7.adopt.watch.counts', {
              count: count(decisions, language),
              block: count(actions.BLOCK, language),
              challenge: count(actions.CHALLENGE, language),
              review: count(actions.ESCALATE, language),
            })}
          </p>
        ) : null}
      </section>
      <section className={styles.block} aria-labelledby="adopt-on">
        <h2 id="adopt-on" className={styles.name}>
          {t('space.r7.adopt.on.name')}
        </h2>
        <p className={styles.text}>
          <Trans
            i18nKey="space.r7.adopt.on.body"
            components={{ code: <code className={styles.inline} data-original /> }}
          />
        </p>
        {modeKey ? <p className={styles.text}>{t(modeKey)}</p> : null}
      </section>
    </ScreenBody>
  );
}

function ExternalLink({ href, label }: { readonly href: string; readonly label: string }) {
  return (
    <a className={styles.link} href={href} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  );
}

/** The lines that turn Contexa on or protect a method are the only ones lit. */
const NEWLINE = String.fromCharCode(10);
const LIT = /^\s*(@EnableAISecurity|@Protectable|mode: (SHADOW|ENFORCE))/;

/** Code as the original it is: kept apart from the screen's words and numbers, scrolled inside on a narrow screen. */
function CodeBlock({ code, label }: { readonly code: string; readonly label: string }) {
  return (
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
  );
}
