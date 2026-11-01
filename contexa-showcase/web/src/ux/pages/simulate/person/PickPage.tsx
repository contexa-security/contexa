import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomy, useBeforeSend, type BeforeSendView } from '../../../../api/anatomy';
import { useLabOptions, type LabCase } from '../../../../api/lab';
import { useLiveConfig } from '../../../../api/queries';
import { formatNumber } from '../../../format';
import { FlowProgress, FlowSteps, GroupTabs } from '../../../simulate/FlowFrame';
import {
  PERSON_KEYS,
  authWords,
  companyClock,
  contextChips,
  deviceWords,
  flowPath,
  shortPath,
  truthOf,
  type PersonKey,
} from '../../../simulate/person';
import { Badge, ButtonLink, FlagBadge, Icon, PageHead, type UxIconName } from '../../../ui';
import styles from '../../../simulate/Flow.module.css';
import { breakable } from '../../../ui/breakable';

/**
 * Step 1 of the threat simulation (기획안 7.0 d-pick): one shared request — the same account, time, network, login and
 * request — forks into the compromised account (S13) and the legitimate user (S13T); the insider (S16) sits beside
 * them. Every value is what the engine received in the latest run of each scenario (/api/live/before, DEC-21); the
 * ground truth is shown and never sent to any control.
 */
export default function PickPage() {
  const { t, i18n } = useTranslation();
  const options = useLabOptions();
  const live = useLiveConfig();
  const ato = useBeforeSend('S13', 1).data?.comparison ?? null;
  const owner = useBeforeSend('S13T', 1).data?.comparison ?? null;
  const request = useAnatomy(ato?.runId ?? null, 1).data?.context.resource ?? null;
  const caseOf = (key: PersonKey) => options.data?.cases.find((labCase) => labCase.key === key) ?? null;
  const employee =
    options.data?.employees.find((candidate) => candidate.key === caseOf('S13')?.conditions.employee) ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  const items = caseOf('S13')?.requests[0]?.items ?? null;
  const network = ato?.businessFacts.find((fact) => fact.code.startsWith('NETWORK_')) ?? null;
  const networkNow = ato?.usualVsNow.find((row) => row.dimension === 'network')?.now ?? null;
  const auth = ato?.usualVsNow.find((row) => row.dimension === 'authenticationType')?.now ?? null;
  return (
    <>
      <FlowSteps current="pick" />
      <PageHead title={t('ux.pick.title')} desc={t('ux.pick.desc')} />
      <GroupTabs
        current="person"
        counts={{
          person: PERSON_KEYS.length,
          agent: live.data?.agentCases?.length ?? null,
          surge: live.data ? (live.data.burst ? 1 : 0) : null,
        }}
      />
      <div className={styles.pick}>
        <div className={styles.pickMain}>
          <section className={styles.shared} aria-labelledby="shared-title">
            <div className={styles.sharedHead}>
              <Icon name="copy-check" />
              <h2 id="shared-title" className={styles.sharedTitle}>
                {t('ux.pick.shared')}
              </h2>
              <span className={styles.sharedNote}>{t('ux.pick.sharedNote')}</span>
            </div>
            <dl className={styles.sharedFacts}>
              <SharedFact icon="user" label={t('ux.facts.label.account')}>
                {employee ? t(`ux.person.${employee.key}`, { defaultValue: employee.displayName }) : '…'}
              </SharedFact>
              <SharedFact icon="clock" label={t('ux.facts.label.time')}>
                {companyClock(t, ato?.companyTime)}
              </SharedFact>
              <SharedFact icon="network" label={t('ux.pick.network')} sub={networkNow}>
                {network ? contextChips(t, [network])[0] : (networkNow ?? '…')}
              </SharedFact>
              <SharedFact icon="key-round" label={t('ux.facts.label.auth')}>
                {authWords(t, auth)}
              </SharedFact>
              <SharedFact
                icon="download"
                label={t('ux.pick.request')}
                sub={items !== null ? t('ux.home.replay.export', { n: n(items) }) : null}
              >
                <code className={styles.mono} title={request?.requestPath ?? undefined}>
                  {request?.httpMethod ?? ''} {breakable(shortPath(request?.requestPath))}
                </code>
              </SharedFact>
            </dl>
          </section>
          <div className={styles.fork} aria-hidden="true">
            <i />
            <i />
          </div>
          <div className={styles.branches}>
            <Branch
              caseKey="S13"
              labCase={caseOf('S13')}
              comparison={ato}
              icon="user-round-x"
              recommended
              tag={null}
            />
            <Branch
              caseKey="S13T"
              labCase={caseOf('S13T')}
              comparison={owner}
              icon="user-round-check"
              tag={t('ux.flow.controlRun')}
            />
          </div>
          <p className={styles.pairNote}>
            <Icon name="git-compare-arrows" size="md" />
            {t('ux.pick.pairNote')}
          </p>
        </div>
        <div className={styles.pickSide}>
          <Insider labCase={caseOf('S16')} />
          <section className={styles.nextGroup} aria-labelledby="next-group-title">
            <span className={styles.nextGroupIcon}>
              <Icon name="bot" size="xl" />
            </span>
            <div>
              <h2 id="next-group-title" className={styles.nextGroupTitle}>
                {t('ux.pick.nextGroup.title', { n: live.data?.agentCases?.length ?? '' })}
              </h2>
              <p className={styles.nextGroupDesc}>{t('ux.pick.nextGroup.desc')}</p>
              <ButtonLink to="/simulate/agent" size="sm" iconAfter="arrow-right">
                {t('ux.pick.nextGroup.action')}
              </ButtonLink>
            </div>
          </section>
        </div>
      </div>
      <FlowProgress />
    </>
  );
}

function SharedFact({
  icon,
  label,
  sub,
  children,
}: {
  readonly icon: UxIconName;
  readonly label: string;
  readonly sub?: ReactNode;
  readonly children: ReactNode;
}) {
  return (
    <div className={styles.sharedFact}>
      <dt>
        <Icon name={icon} size="sm" />
        {label}
      </dt>
      <dd>
        {children}
        {sub ? <span className={styles.sharedSub}>{typeof sub === 'string' ? breakable(sub) : sub}</span> : null}
      </dd>
    </div>
  );
}

function TruthBadge({ classification }: { readonly classification: string | null | undefined }) {
  const { t } = useTranslation();
  return <Badge tone="line">{t(`ux.flow.truth.${truthOf(classification)}`)}</Badge>;
}

/** One fork of the shared request: who sends it, from which device, and the scenario that runs it. */
function Branch({
  caseKey,
  labCase,
  comparison,
  icon,
  recommended = false,
  tag,
}: {
  readonly caseKey: 'S13' | 'S13T';
  readonly labCase: LabCase | null;
  readonly comparison: BeforeSendView | null;
  readonly icon: UxIconName;
  readonly recommended?: boolean;
  readonly tag: string | null;
}) {
  const { t, i18n } = useTranslation();
  const device = comparison?.usualVsNow.find((row) => row.dimension === 'device') ?? null;
  const steps = labCase?.steps ?? null;
  const title = t(`ux.pick.${caseKey}.title`);
  return (
    <article
      className={styles.branch}
      data-recommended={recommended || undefined}
      aria-labelledby={`branch-${caseKey}`}
    >
      <div className={styles.branchTop}>
        <span className={styles.branchIcon}>
          <Icon name={icon} size="xl" />
        </span>
        <span className={styles.branchTags}>
          {recommended ? (
            <Badge tone="line" icon="star">
              {t('ux.flow.recommended')}
            </Badge>
          ) : null}
          {tag ? <Badge tone="line">{tag}</Badge> : null}
          <TruthBadge classification={labCase?.classification} />
        </span>
      </div>
      <h3 id={`branch-${caseKey}`} className={styles.branchTitle}>
        {title}
      </h3>
      <p className={styles.branchLine}>{t(`ux.pick.${caseKey}.line`)}</p>
      <dl className={styles.branchFacts}>
        <dt>{t('ux.facts.label.device')}</dt>
        <dd>
          {deviceWords(device?.now)}{' '}
          {device?.inUsual === 'false' ? (
            <FlagBadge />
          ) : device?.inUsual === 'true' ? (
            <Badge tone="none">{t('ux.facts.mark.in')}</Badge>
          ) : null}
        </dd>
        <dt>{t('ux.pick.scenario')}</dt>
        <dd>{caseKey}</dd>
      </dl>
      <div className={styles.branchFoot}>
        <span>
          {steps !== null
            ? t('ux.flow.requests', { count: steps, n: formatNumber(steps, i18n.language) })
            : null}
        </span>
        <ButtonLink
          to={flowPath(caseKey, 'review')}
          size="sm"
          variant={recommended ? 'primary' : 'secondary'}
          iconAfter="arrow-right"
          label={`${title} ${t('ux.flow.select')}`}
        >
          {t('ux.flow.select')}
        </ButtonLink>
      </div>
    </article>
  );
}

/** The insider: the same person's own account inside the permission, several document requests one after another. */
function Insider({ labCase }: { readonly labCase: LabCase | null }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const titles = (labCase?.requests ?? []).map((request) => {
    const fact = request.document?.fact ?? null;
    const document = fact !== null ? (labCase?.facts[fact - 1]?.document ?? null) : null;
    return document?.title?.[language] ?? null;
  });
  const title = t('ux.pick.S16.title');
  return (
    <article className={styles.branch} aria-labelledby="branch-S16">
      <div className={styles.branchTop}>
        <span className={styles.branchIcon}>
          <Icon name="user-round-cog" size="xl" />
        </span>
        <span className={styles.branchTags}>
          <TruthBadge classification={labCase?.classification} />
        </span>
      </div>
      <h3 id="branch-S16" className={styles.branchTitle}>
        {title}
      </h3>
      <p className={styles.branchLine}>
        {t('ux.pick.S16.line', { n: formatNumber(labCase?.steps ?? 0, i18n.language) })}
      </p>
      {titles.some((value) => value !== null) ? (
        <ol className={styles.documents}>
          {titles.map((value, index) => (
            <li key={index}>
              <span className={styles.documentNo}>{t('ux.pick.requestNo', { n: index + 1 })}</span>
              {value ?? '—'}
            </li>
          ))}
        </ol>
      ) : null}
      <dl className={styles.branchFacts}>
        <dt>{t('ux.home.check')}</dt>
        <dd>{t('ux.home.card.insider.check')}</dd>
        <dt>{t('ux.pick.scenario')}</dt>
        <dd>S16</dd>
      </dl>
      <div className={styles.branchFoot}>
        <span>
          {labCase
            ? t('ux.flow.requests', { count: labCase.steps, n: formatNumber(labCase.steps, i18n.language) })
            : null}
        </span>
        <ButtonLink
          to={flowPath('S16', 'review')}
          size="sm"
          iconAfter="arrow-right"
          label={`${title} ${t('ux.flow.select')}`}
        >
          {t('ux.flow.select')}
        </ButtonLink>
      </div>
    </article>
  );
}
