import { Fragment, useEffect, useId, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useBenchmark } from '../../../api/benchmark';
import { useStats } from '../../../api/queries';
import { usePublicSettings } from '../../../api/settings';
import { formatNumber, formatSeconds } from '../../format';
import { breakable } from '../../ui/breakable';
import {
  Button,
  ButtonAnchor,
  Card,
  DataTable,
  KeyValue,
  Note,
  PageHead,
  TabPanel,
  Tabs,
  VerdictBadge,
} from '../../ui';
import { scoreOf } from '../../validation/shapes';
import styles from './Adopt.module.css';
import { CODE, LINKS, TABS, tabOf } from './adopt';

/** The starter's retention and audit defaults (DEC-66), each read from the OSS source where it is defined. */
const DEFAULTS = [
  { id: 'sample', property: 'contexa.pqa.oss.sealed-evidence.sample-percent', value: 1, unit: 'percent' },
  { id: 'fullCapture', property: 'contexa.pqa.oss.sealed-evidence.full-capture-after-change', value: 1000, unit: 'decisions' },
  { id: 'period', property: 'contexa.pqa.oss.sealed-evidence.retention.period', value: 90, unit: 'days' },
  { id: 'clean', property: 'contexa.pqa.oss.sealed-evidence.retention.clean-period', value: 30, unit: 'days' },
  { id: 'baseline', property: 'contexa.security.zerotrust.baseline.retention', value: 30, unit: 'afterLearning' },
  { id: 'behavior', property: 'contexa.rag.etl.behavior.retention-days', value: 90, unit: 'days' },
] as const;
type DefaultRow = (typeof DEFAULTS)[number];

/**
 * Deployment & integration (기획안 7.12, DEC-66): the three steps with their code, shadow mode with what this demo's
 * own decisions would have been, the starter's retention and audit defaults beside this demo's, and the bridge for an
 * existing sign-in. An old `?step=` link opens the tab that holds that step.
 */
export default function AdoptPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const tab = tabOf(params);
  return (
    <>
      <PageHead
        title={t('ux.adopt.title')}
        desc={t('ux.adopt.desc')}
        actions={
          <ButtonAnchor href={LINKS.quickstart} icon="rocket">
            {t('ux.adopt.links.quickstart')}
          </ButtonAnchor>
        }
      />
      <Tabs
        idBase="adopt"
        label={t('ux.adopt.tabs')}
        value={tab}
        onChange={(id) => setParams(new URLSearchParams({ tab: id }), { replace: true })}
        items={TABS.map((id) => ({ id, label: t(`ux.adopt.tab.${id}`) }))}
      />
      <TabPanel idBase="adopt" id={tab}>
        {tab === 'steps' ? (
          <Steps />
        ) : tab === 'shadow' ? (
          <Shadow />
        ) : tab === 'retention' ? (
          <Retention />
        ) : (
          <Integration />
        )}
      </TabPanel>
    </>
  );
}

/** A sentence with its `code` parts drawn as code. */
function withCode(text: string): ReactNode {
  return text.split(/(`[^`]+`)/).map((part, index) =>
    part.startsWith('`') && part.endsWith('`') ? (
      <code key={index} className={styles.inline}>
        {/* A code's own spaces never break ("sync = true" stays one piece); a long name breaks at its parts. */}
        {breakable(part.slice(1, -1).replace(/ /g, '\u00a0'))}
      </code>
    ) : (
      <Fragment key={index}>{part}</Fragment>
    ),
  );
}

/** The lines the old screen marked: the annotations and the mode a reader changes. */
const MARKED = /@EnableAISecurity|@Protectable|mode:/;
const TOKENS = /(@\w+|"[^"]*"|\b(?:SHADOW|ENFORCE)\b)/;

function Line({ line }: { readonly line: string }) {
  return (
    <span className={styles.codeLine} data-mark={MARKED.test(line) || undefined}>
      {line.split(TOKENS).map((part, index) => {
        const kind = part.startsWith('@')
          ? 'annotation'
          : part.startsWith('"')
            ? 'string'
            : part === 'SHADOW' || part === 'ENFORCE'
              ? 'keyword'
              : undefined;
        return kind ? (
          <span key={index} data-k={kind}>
            {part}
          </span>
        ) : (
          <Fragment key={index}>{part}</Fragment>
        );
      })}
      {'\n'}
    </span>
  );
}

type CopyState = 'idle' | 'copied' | 'failed';

/** A code block as it is written (original text), with a copy button whose result is announced (ST-80). */
function CodeBlock({ name, code }: { readonly name: string; readonly code: string }) {
  const { t } = useTranslation();
  const [state, setState] = useState<CopyState>('idle');
  const statusId = useId();
  useEffect(() => {
    if (state !== 'copied') {
      return undefined;
    }
    const timer = window.setTimeout(() => setState('idle'), 2000);
    return () => window.clearTimeout(timer);
  }, [state]);
  const copy = async () => {
    try {
      if (!navigator.clipboard) {
        throw new Error('no clipboard');
      }
      await navigator.clipboard.writeText(code);
      setState('copied');
    } catch {
      setState('failed');
    }
  };
  return (
    <figure className={styles.codeFigure}>
      <figcaption className={styles.codeHead}>
        <span>{name}</span>
        <Button
          variant="text"
          size="sm"
          icon={state === 'copied' ? 'copy-check' : 'copy'}
          aria-label={t('ux.adopt.copyNamed', { name })}
          onClick={() => void copy()}
        >
          {state === 'copied' ? t('ux.adopt.copied') : t('ux.adopt.copy')}
        </Button>
      </figcaption>
      <pre className={styles.code} lang="en" role="region" tabIndex={0} aria-label={name} data-original="">
        {code.split('\n').map((line, index) => (
          <Line key={index} line={line} />
        ))}
      </pre>
      <p id={statusId} className={styles.copyStatus} role="status">
        {state === 'failed' ? t('ux.adopt.copyFailed') : ''}
      </p>
    </figure>
  );
}

function Steps() {
  const { t } = useTranslation();
  const steps = [
    { n: 1, code: CODE.dependency, name: t('ux.adopt.code.dependency') },
    { n: 2, code: CODE.annotations, name: t('ux.adopt.code.annotations') },
    { n: 3, code: CODE.shadow, name: t('ux.adopt.code.shadow') },
  ];
  return (
    <div className={styles.split}>
      <ol className={styles.steps} aria-label={t('ux.adopt.steps')}>
        {steps.map((step) => (
          <li key={step.n} className={styles.step}>
            <Card
              title={
                <span className={styles.stepTitle}>
                  <span className={styles.stepNo} aria-hidden="true">
                    {step.n}
                  </span>
                  {t(`ux.adopt.step.${step.n}.title`)}
                </span>
              }
            >
              <div className={styles.stack}>
                <p className={styles.line}>{withCode(t(`ux.adopt.step.${step.n}.body`))}</p>
                <CodeBlock name={step.name} code={step.code} />
              </div>
            </Card>
          </li>
        ))}
      </ol>
      <div className={styles.stack}>
        <Roles />
        <Card title={t('ux.adopt.links.title')}>
          <div className={styles.stack}>
            <div className={styles.links}>
              <ButtonAnchor href={LINKS.docs} icon="book-open" size="sm">
                {t('ux.adopt.links.docs')}
              </ButtonAnchor>
              <ButtonAnchor href={LINKS.repository} icon="code-xml" size="sm">
                {t('ux.adopt.links.repository')}
              </ButtonAnchor>
            </div>
            <p className={styles.note}>
              {t('ux.adopt.cost')}{' '}
              <Link className={styles.textLink} to="/validation?tab=quality">
                {t('ux.adopt.costLink')}
              </Link>
            </p>
          </div>
        </Card>
      </div>
    </div>
  );
}

/** What changes for whom (기획안 11절 "역할별 도입 효과"): the data kept, the employee, the security administrator. */
function Roles() {
  const { t, i18n } = useTranslation();
  const benchmark = useBenchmark(null);
  const n = (value: number) => formatNumber(value, i18n.language);
  const contexa = benchmark.data ? scoreOf(benchmark.data.controls, 'D') : null;
  return (
    <Card title={t('ux.adopt.roles.title')} sub={t('ux.adopt.roles.sub')}>
      <dl className={styles.roles}>
        <div>
          <dt>{t('ux.adopt.roles.data')}</dt>
          <dd>{t('ux.adopt.roles.dataWhat')}</dd>
        </div>
        <div>
          <dt>{t('ux.adopt.roles.employee')}</dt>
          <dd>
            {t('ux.adopt.roles.employeeWhat')}
            {contexa ? (
              <span className={styles.figureLine}>
                {t('ux.adopt.roles.employeeCounts', {
                  normal: n(contexa.falseBlock.total),
                  blocked: n(contexa.falseBlock.hits),
                  checked: n(contexa.friction.hits),
                })}
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>{t('ux.adopt.roles.admin')}</dt>
          <dd>{t('ux.adopt.roles.adminWhat')}</dd>
        </div>
      </dl>
    </Card>
  );
}

function Shadow() {
  const { t, i18n } = useTranslation();
  const stats = useStats();
  const settings = usePublicSettings();
  const n = (value: number) => formatNumber(value, i18n.language);
  const mode = settings.data?.engine.effectiveMode ?? null;
  const decisions = stats.data ? (stats.data.engineDecisions ?? stats.data.decisionTime.decisions) : 0;
  return (
    <div className={styles.split}>
      <div className={styles.stack}>
        <Card title={t('ux.adopt.shadow.title')}>
          <div className={styles.stack}>
            <p className={styles.line}>{t('ux.adopt.shadow.body')}</p>
            <CodeBlock name={t('ux.adopt.code.shadow')} code={CODE.shadow} />
          </div>
        </Card>
        <Card title={t('ux.adopt.enforce.title')}>
          <div className={styles.stack}>
            <p className={styles.line}>{withCode(t('ux.adopt.enforce.body'))}</p>
            <CodeBlock name={t('ux.adopt.code.enforce')} code={CODE.enforce} />
            {mode !== null && i18n.exists(`ux.adopt.now.${mode}`) ? (
              <Note icon="info">
                {t('ux.adopt.now.label')} · <code className={styles.inline}>{mode}</code> · {t(`ux.adopt.now.${mode}`)}
              </Note>
            ) : null}
          </div>
        </Card>
      </div>
      {stats.data && decisions > 0 ? (
        <Card title={t('ux.adopt.record.title')} sub={t('ux.adopt.record.sub')}>
          <div className={styles.stack}>
            <KeyValue
              alignEnd
              items={[
                { label: t('ux.adopt.record.decisions'), value: t('ux.adopt.record.count', { n: n(decisions) }) },
                {
                  label: <VerdictBadge verdict="BLOCK" />,
                  value: t('ux.adopt.record.count', { n: n(stats.data.engineActions.BLOCK ?? 0) }),
                },
                {
                  label: <VerdictBadge verdict="CHALLENGE" />,
                  value: t('ux.adopt.record.count', { n: n(stats.data.engineActions.CHALLENGE ?? 0) }),
                },
                {
                  label: <VerdictBadge verdict="ESCALATE" />,
                  value: t('ux.adopt.record.count', { n: n(stats.data.engineActions.ESCALATE ?? 0) }),
                },
                ...(stats.data.decisionTime.p50Ms === null
                  ? []
                  : [
                      {
                        label: t('ux.adopt.record.latency'),
                        value: t('ux.time.seconds', { value: formatSeconds(stats.data.decisionTime.p50Ms, i18n.language) }),
                      },
                    ]),
              ]}
            />
            {stats.data.runs.firstAt && stats.data.runs.lastAt ? (
              <p className={styles.note}>
                {t('ux.adopt.record.source', {
                  from: stats.data.runs.firstAt.slice(0, 10),
                  to: stats.data.runs.lastAt.slice(0, 10),
                  zone: t('ux.time.zone'),
                })}
              </p>
            ) : null}
            <Link className={styles.textLink} to="/metrics">
              {t('ux.adopt.record.metrics')}
            </Link>
          </div>
        </Card>
      ) : null}
    </div>
  );
}

function Retention() {
  const { t, i18n } = useTranslation();
  const settings = usePublicSettings();
  const n = (value: number) => formatNumber(value, i18n.language);
  const write = (row: DefaultRow, value: number) => t(`ux.adopt.value.${row.unit}`, { n: n(value) });
  /** This demo's value of a row: the portal's published setting, or why there is none (ST-78). */
  const demo = (row: DefaultRow): string => {
    if (settings.isError) {
      return t('ux.adopt.value.unread');
    }
    if (!settings.data) {
      return '…';
    }
    const published =
      row.id === 'sample'
        ? settings.data.sealedEvidence?.samplePercent
        : row.id === 'clean'
          ? settings.data.sealedEvidence?.cleanPeriodDays
          : row.id === 'behavior'
            ? settings.data.retention.behaviorDays
            : undefined;
    return published === undefined || published === null ? t('ux.adopt.value.notInAnswer') : write(row, published);
  };
  const original = settings.data?.retention.promptOriginalDays;
  return (
    <div className={styles.stack}>
      <Card title={t('ux.adopt.retention.title')} sub={t('ux.adopt.retention.sub')} flush>
        <DataTable<DefaultRow>
          caption={t('ux.adopt.retention.title')}
          stack
          rowKey={(row) => row.id}
          rows={DEFAULTS}
          columns={[
            { key: 'item', header: t('ux.adopt.col.item'), strong: true, render: (row) => t(`ux.adopt.row.${row.id}`) },
            { key: 'default', header: t('ux.adopt.col.default'), render: (row) => write(row, row.value) },
            {
              key: 'property',
              header: t('ux.adopt.col.property'),
              render: (row) => <code className={styles.inline}>{breakable(row.property)}</code>,
            },
            { key: 'demo', header: t('ux.adopt.col.demo'), render: demo },
          ]}
        />
      </Card>
      <p className={styles.note}>
        {original === undefined ? t('ux.adopt.demoNoteNone') : t('ux.adopt.demoNote', { days: n(original) })}
      </p>
      <Card title={t('ux.adopt.seal.title')}>
        <div className={styles.stack}>
          <p className={styles.line}>{t('ux.adopt.seal.body')}</p>
          <p className={styles.line}>{withCode(t('ux.adopt.seal.inspect'))}</p>
          <p className={styles.note}>{t('ux.adopt.seal.oss')}</p>
        </div>
      </Card>
    </div>
  );
}

function Integration() {
  const { t } = useTranslation();
  return (
    <Card title={t('ux.adopt.integration.title')}>
      <div className={styles.stack}>
        <p className={styles.line}>{t('ux.adopt.integration.body')}</p>
        <div className={styles.links} role="group" aria-label={t('ux.adopt.integration.links')}>
          <ButtonAnchor href={LINKS.legacy} icon="workflow" size="sm">
            {t('ux.adopt.links.legacy')}
          </ButtonAnchor>
          <ButtonAnchor href={LINKS.quickstart} icon="rocket" size="sm">
            {t('ux.adopt.links.quickstart')}
          </ButtonAnchor>
          <ButtonAnchor href={LINKS.repository} icon="code-xml" size="sm">
            {t('ux.adopt.links.repository')}
          </ButtonAnchor>
          <ButtonAnchor href={LINKS.docs} icon="book-open" size="sm">
            {t('ux.adopt.links.docs')}
          </ButtonAnchor>
        </div>
      </div>
    </Card>
  );
}
