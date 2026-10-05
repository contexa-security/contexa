import { useEffect, useMemo, useReducer, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation, useParams } from 'react-router-dom';
import { useReplay, useSpec } from '../api/queries';
import type { Choice, Layer, Scene } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import type { EvidenceChain } from '../components/EvidenceDrawer';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { LayerCard } from '../components/LayerCard';
import { OutcomeStrip } from '../components/OutcomeStrip';
import { ReplayBadge } from '../components/ReplayBadge';
import { StateScreen } from '../components/StateScreen';
import { Stepper } from '../components/Stepper';
import { AUTO_ADVANCE_MS, playback, TICK_MS } from '../domain/playback';
import { engineReasonLine, evidenceKinds, factLine, ruleReason, timingLine } from '../domain/reasons';
import { timelineEntries, timelineSummary } from '../domain/timeline';
import type { ControlId } from '../domain/verdict';
import { OUTCOME_KEYS } from '../domain/verdict';
import styles from './ReplayPage.module.css';

/** Mobile shows Contexa and the context-lookup rule first; the other three are folded (deck p.20). */
const MOBILE_PRIORITY: readonly ControlId[] = ['D', 'C2'];

/**
 * Screen 1, verdict comparison (deck p.10): the result of the five layers in one second, the reason in one line, the
 * evidence chain one click away, and the legitimate request that looks the same right after the attack.
 */
export default function ReplayPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { pairKey } = useParams();
  const location = useLocation();
  const choice = (location.state as { choice?: Choice } | null)?.choice;
  const replay = useReplay(pairKey);
  const [{ index, elapsed }, dispatch] = useReducer(playback, { index: 0, elapsed: 0 });
  const [paused, setPaused] = useState(false);
  const [openControl, setOpenControl] = useState<ControlId | null>(null);
  const [expanded, setExpanded] = useState(false);

  const scenes = replay.data?.scenes ?? [];
  const scene: Scene | undefined = scenes[index];
  const spec = useSpec(scene?.specHash);
  const last = index >= scenes.length - 1;
  const running = Boolean(scene) && !last && !paused && openControl === null;

  useEffect(() => {
    if (!running) {
      return undefined;
    }
    const timer = window.setInterval(() => dispatch({ type: 'tick', scenes: scenes.length }), TICK_MS);
    return () => window.clearInterval(timer);
  }, [running, scenes.length]);

  const openLayer = useMemo(
    () => scene?.layers.find((layer) => layer.control === openControl) ?? null,
    [scene, openControl],
  );

  function go(next: number) {
    dispatch({ type: 'go', index: next });
    setOpenControl(null);
  }

  function reason(layer: Layer): string {
    return layer.control === 'D'
      ? engineReasonLine(layer, scene?.engineReason ?? null, t)
      : ruleReason(layer, t);
  }

  function evidence(layer: Layer): EvidenceChain {
    const chain: EvidenceChain = {
      decisionId: layer.evidence.decisionId,
      verdict: layer.evidence.verdict,
      unresolved: layer.evidence.unresolved,
      timing: timingLine(layer.evidence.timing, t),
      httpStatus: layer.evidence.httpStatus,
      outcome: t(OUTCOME_KEYS[layer.evidence.outcome]),
    };
    const entries = timelineEntries(layer.evidence, t);
    const withStream = layer.evidence.stream ? { ...chain, stream: layer.evidence.stream } : chain;
    const withTimeline =
      entries.length > 0
        ? { ...withStream, timeline: { entries, summary: timelineSummary(layer.evidence, t) } }
        : withStream;
    return layer.evidence.engineReasoning
      ? { ...withTimeline, engineReasoning: layer.evidence.engineReasoning }
      : withTimeline;
  }

  const specLabel = spec.data ? `engine ${spec.data.spec.engineVersion} · ${spec.data.spec.chatModel}` : '…';
  const contexa = scene?.layers.find((layer) => layer.control === 'D');
  const foldedCount = (scene?.layers.length ?? 0) - MOBILE_PRIORITY.length;
  const cited = evidenceKinds(scene?.engineReason ?? null, t);
  const facts = (scene?.companyFacts ?? [])
    .map((fact) => factLine(fact, t))
    .filter((line): line is string => !!line);

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        {replay.isPending ? <StateScreen kind="loading" /> : null}
        {replay.isError ? <StateScreen kind="notReady" /> : null}
        {scene && contexa ? (
          <section className={styles.frame} aria-labelledby="scene-request">
            <div className={styles.topRow}>
              <Stepper current={0} />
              <ReplayBadge mode="replay" specLabel={specLabel} />
            </div>
            <div className={styles.request}>
              <span className={styles.requestLabel}>
                {t(`replay.scene.${scene.kind}`)} · {index + 1}/{scenes.length}
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
            {choice && scene.kind === 'ATTACK' ? (
              <p className={styles.prediction} data-match={matches(choice, contexa)}>
                {t('replay.prediction', {
                  choice: t(`replay.choice.${choice}`),
                  verdict: t(OUTCOME_KEYS[contexa.outcome]),
                })}
              </p>
            ) : null}
            <OutcomeStrip outcomes={scene.layers.map(({ control, outcome }) => ({ control, outcome }))} />
            <h2 className="visually-hidden">{t('layers.title')}</h2>
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
            <div className={styles.context}>
              {cited.length > 0 ? (
                <section className={styles.panel} aria-labelledby="engine-cited">
                  <h2 id="engine-cited" className={styles.panelTitle}>
                    {t('replay.engineCited')}
                  </h2>
                  <ul className={styles.chips}>
                    {cited.map((kind) => (
                      <li key={kind} className={styles.chip}>
                        {kind}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}
              {facts.length > 0 ? (
                <section className={styles.panel} aria-labelledby="company-facts">
                  <h2 id="company-facts" className={styles.panelTitle}>
                    {t('replay.companyFacts')}
                  </h2>
                  <ul className={styles.facts}>
                    {facts.map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </section>
              ) : null}
            </div>
            <footer className={styles.next}>
              {last ? (
                <p className={styles.nextLabel}>{t('replay.finished')}</p>
              ) : (
                <div className={styles.nextInfo}>
                  <p className={styles.nextLabel}>
                    {t('next.scene')} · {scenes[index + 1]?.sentence[language]}
                  </p>
                  <div
                    className={styles.progress}
                    role="progressbar"
                    aria-label={t('next.scene')}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round((elapsed / AUTO_ADVANCE_MS) * 100)}
                  >
                    <span
                      className={styles.progressValue}
                      style={{ inlineSize: `${Math.min(100, (elapsed / AUTO_ADVANCE_MS) * 100)}%` }}
                    />
                  </div>
                </div>
              )}
              <div className={styles.actions}>
                {index > 0 ? (
                  <button type="button" className={styles.secondaryAction} onClick={() => go(index - 1)}>
                    {t('replay.previous')}
                  </button>
                ) : null}
                {!last ? (
                  <button
                    type="button"
                    className={styles.secondaryAction}
                    aria-pressed={paused}
                    onClick={() => setPaused((value) => !value)}
                  >
                    {paused ? t('replay.resume') : t('replay.pause')}
                  </button>
                ) : null}
                {last ? (
                  <>
                    <button type="button" className={styles.secondaryAction} onClick={() => go(0)}>
                      {t('replay.restart')}
                    </button>
                    <Link className={styles.primaryAction} to={`/end/${pairKey ?? ''}`}>
                      {t('replay.results')}
                    </Link>
                  </>
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
        evidence={openLayer ? evidence(openLayer) : null}
        onClose={() => setOpenControl(null)}
      />
    </>
  );
}

/** Whether the visitor's call matches what actually happened to the data at Contexa. */
function matches(choice: Choice, contexa: Layer): boolean {
  return (choice === 'ALLOW') === (contexa.outcome === 'DELIVERED');
}
