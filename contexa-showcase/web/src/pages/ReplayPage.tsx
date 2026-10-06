import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation, useParams } from 'react-router-dom';
import { useReplay, useSpec } from '../api/queries';
import type { Choice, Layer, Scene } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { LayerCard } from '../components/LayerCard';
import { ReplayBadge } from '../components/ReplayBadge';
import { StateScreen } from '../components/StateScreen';
import { evidenceChain, reasonLine } from '../domain/evidence';
import { evidenceKinds, factLine } from '../domain/reasons';
import { tally } from '../domain/summary';
import type { ControlId } from '../domain/verdict';
import styles from './ReplayPage.module.css';

/** Mobile shows Contexa and the business record rule first; the other three are folded (deck p.20). */
const MOBILE_PRIORITY: readonly ControlId[] = ['D', 'C2'];

/**
 * Screen 1, the five approaches compared (deck p.10), read top to bottom: the request, what it does not show, the
 * conclusion in one sentence (how many stopped it and what Contexa did), then each approach's result and reason with
 * the evidence one click away. The visitor moves on to the legitimate request that looks the same when ready.
 */
export default function ReplayPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { pairKey } = useParams();
  const location = useLocation();
  const choice = (location.state as { choice?: Choice } | null)?.choice;
  const replay = useReplay(pairKey);
  const [index, setIndex] = useState(0);
  const [openControl, setOpenControl] = useState<ControlId | null>(null);
  const [expanded, setExpanded] = useState(false);

  const scenes = replay.data?.scenes ?? [];
  const scene: Scene | undefined = scenes[index];
  const spec = useSpec(scene?.specHash);
  const last = index >= scenes.length - 1;

  const openLayer = useMemo(
    () => scene?.layers.find((layer) => layer.control === openControl) ?? null,
    [scene, openControl],
  );

  function go(next: number) {
    setIndex(next);
    setOpenControl(null);
    window.scrollTo({ top: 0 });
  }

  function reason(layer: Layer): string {
    return reasonLine(layer, scene?.engineReason ?? null, t);
  }

  const specLabel = spec.data ? `engine ${spec.data.spec.engineVersion} · ${spec.data.spec.chatModel}` : '…';
  const contexa = scene?.layers.find((layer) => layer.control === 'D');
  const foldedCount = (scene?.layers.length ?? 0) - MOBILE_PRIORITY.length;
  const cited = evidenceKinds(scene?.engineReason ?? null, t);
  const facts = (scene?.companyFacts ?? [])
    .map((fact) => factLine(fact, t))
    .filter((line): line is string => !!line);
  const counts = scene ? tally(scene.layers) : null;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        {replay.isPending ? <StateScreen kind="loading" /> : null}
        {replay.isError ? <StateScreen kind="notReady" /> : null}
        {scene && contexa && counts ? (
          <section className={styles.frame} aria-labelledby="scene-request">
            <div className={styles.topRow}>
              <p className={styles.stepLabel}>{t('replay.step')}</p>
              <ReplayBadge mode="replay" specLabel={specLabel} />
            </div>
            <div className={styles.request}>
              <span className={styles.requestLabel}>
                {t('replay.sceneCount', { n: index + 1, total: scenes.length })} ·{' '}
                {t(`replay.scene.${scene.kind}`)}
              </span>
              <h1 id="scene-request" className={styles.requestText}>
                {scene.sentence[language]}
              </h1>
              <p className={styles.meta}>
                <span>
                  {t('replay.agreement', { agreeing: scene.agreeing, repetitions: scene.repetitions })}
                </span>
                <span aria-hidden="true">·</span>
                <span>{t('replay.companyTime', { time: scene.companyTime.substring(11, 16) })}</span>
                <span aria-hidden="true">·</span>
                <span>
                  {t('replay.recordedAt', {
                    date: new Date(scene.recordedAt).toLocaleDateString(
                      language === 'ko' ? 'ko-KR' : 'en-US',
                    ),
                  })}
                </span>
              </p>
            </div>
            {facts.length > 0 ? (
              <section className={styles.reality} aria-labelledby="company-facts">
                <h2 id="company-facts" className={styles.panelTitle}>
                  {t('replay.companyFacts')}
                </h2>
                <ul className={styles.factChips}>
                  {facts.map((line) => (
                    <li key={line} className={styles.factChip}>
                      {line}
                    </li>
                  ))}
                </ul>
                <p className={styles.expect}>{t(`replay.expect.${scene.kind}`)}</p>
              </section>
            ) : null}
            <section className={styles.summary} aria-labelledby="scene-summary">
              <h2 id="scene-summary" className={styles.summaryTitle}>
                {t('replay.summary', { stopped: counts.stopped, passed: counts.passed })}
                {counts.other > 0 ? ` ${t('replay.summaryOther', { count: counts.other })}` : ''}
              </h2>
              <p className={styles.summaryContexa} data-outcome={contexa.outcome}>
                {t(`replay.contexa.${contexa.outcome}`)}
              </p>
              {choice && scene.kind === 'ATTACK' ? (
                <p className={styles.prediction} data-match={matches(choice, contexa)}>
                  {t('replay.prediction', { choice: t(`replay.choice.${choice}`) })}
                </p>
              ) : null}
            </section>
            <h2 className={styles.cardsTitle}>{t('replay.cardsTitle')}</h2>
            <div className={styles.layers} data-expanded={expanded}>
              {scene.layers.map((layer) => (
                <div
                  key={layer.control}
                  className={styles.layerSlot}
                  data-priority={MOBILE_PRIORITY.includes(layer.control) ? 'primary' : 'secondary'}
                  data-control={layer.control}
                >
                  <LayerCard
                    control={layer.control}
                    outcome={layer.outcome}
                    verdict={layer.verdict}
                    unresolved={layer.evidence.unresolved}
                    reason={reason(layer)}
                    highlighted={layer.control === 'D'}
                    rowAligned
                    onOpenEvidence={setOpenControl}
                  />
                </div>
              ))}
            </div>
            <button
              type="button"
              className={styles.foldToggle}
              aria-expanded={expanded}
              onClick={() => setExpanded((value) => !value)}
            >
              {expanded ? t('layers.less') : t('layers.more', { count: foldedCount })}
            </button>
            {cited.length > 0 ? (
              <p className={styles.cited}>
                <span className={styles.citedLabel}>{t('replay.engineCited')}</span> {cited.join(' · ')}
              </p>
            ) : null}
            <footer className={styles.next}>
              {last ? (
                <p className={styles.nextLabel}>{t('replay.finished')}</p>
              ) : (
                <p className={styles.nextLabel}>
                  {t('next.scene')} · {scenes[index + 1]?.sentence[language]}
                </p>
              )}
              <div className={styles.actions}>
                {index > 0 ? (
                  <button type="button" className={styles.secondaryAction} onClick={() => go(index - 1)}>
                    {t('replay.previous')}
                  </button>
                ) : null}
                {last ? (
                  <Link className={styles.primaryAction} to={`/end/${pairKey ?? ''}`}>
                    {t('replay.results')}
                  </Link>
                ) : (
                  <button type="button" className={styles.primaryAction} onClick={() => go(index + 1)}>
                    {t('next.button')}
                  </button>
                )}
              </div>
            </footer>
            {spec.data ? (
              <a className={styles.specLink} href={`/api/specs/${scene.specHash}`}>
                {t('replay.specLink')}
              </a>
            ) : null}
          </section>
        ) : null}
      </main>
      <EvidenceDrawer
        title={openLayer ? t(`control.${openLayer.control}.name`) : ''}
        evidence={openLayer ? evidenceChain(openLayer, t) : null}
        onClose={() => setOpenControl(null)}
      />
    </>
  );
}

/** Whether the visitor's call matches what actually happened to the data at Contexa. */
function matches(choice: Choice, contexa: Layer): boolean {
  return (choice === 'ALLOW') === (contexa.outcome === 'DELIVERED');
}
