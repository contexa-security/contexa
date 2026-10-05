import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AppHeader } from '../../components/AppHeader';
import { EvidenceDrawer } from '../../components/EvidenceDrawer';
import { LayerCard } from '../../components/LayerCard';
import { OutcomeStrip } from '../../components/OutcomeStrip';
import { ReplayBadge } from '../../components/ReplayBadge';
import { Stepper } from '../../components/Stepper';
import type { ControlId } from '../../domain/verdict';
import { designScene } from './designScene';
import styles from './DesignPage.module.css';

/** Mobile shows Contexa and the context-lookup rule first; the other three are folded (deck page 20). */
const MOBILE_PRIORITY: readonly ControlId[] = ['D', 'C2'];

export default function DesignPage() {
  const { t, i18n } = useTranslation();
  const [openControl, setOpenControl] = useState<ControlId | null>(null);
  const [expanded, setExpanded] = useState(false);
  const language = i18n.language === 'ko' ? 'ko' : 'en';

  const openLayer = useMemo(
    () => designScene.layers.find((layer) => layer.control === openControl) ?? null,
    [openControl],
  );
  const foldedCount = designScene.layers.length - MOBILE_PRIORITY.length;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <p className={styles.mockBadge}>{designScene.badge[language]}</p>
        <h1 className="visually-hidden">{designScene.title[language]}</h1>
        <section className={styles.frame} aria-labelledby="scene-request">
          <div className={styles.topRow}>
            <Stepper current={0} />
            <ReplayBadge mode="replay" specLabel={designScene.specLabel} />
          </div>
          <div className={styles.request}>
            <span className={styles.requestLabel}>{t('request.label')}</span>
            <p id="scene-request" className={styles.requestText}>
              {designScene.request[language]}
            </p>
          </div>
          <OutcomeStrip outcomes={designScene.layers.map(({ control, outcome }) => ({ control, outcome }))} />
          <div className={styles.layers} data-expanded={expanded}>
            {designScene.layers.map((layer) => (
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
                  reason={layer.reason[language]}
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
          <footer className={styles.next}>
            <div className={styles.nextInfo}>
              <p className={styles.nextLabel}>
                {t('next.scene')} · {designScene.nextScene[language]}
              </p>
              <div
                className={styles.progress}
                role="progressbar"
                aria-label={t('next.scene')}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={40}
              >
                <span className={styles.progressValue} />
              </div>
            </div>
            <button type="button" className={styles.primaryAction}>
              {t('next.button')}
            </button>
          </footer>
        </section>
      </main>
      <EvidenceDrawer
        title={openLayer ? t(`control.${openLayer.control}.name`) : ''}
        evidence={openLayer ? openLayer.evidence : null}
        onClose={() => setOpenControl(null)}
      />
    </>
  );
}
