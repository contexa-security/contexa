import { useTranslation } from 'react-i18next';
import type { RunQuality } from '../../api/promptQuality';
import { utcTime } from '../../journey/format';
import { Icon } from '../Icon';
import { failuresFirst } from './factWords';
import styles from './Facts.module.css';

/**
 * The checks of a decision (U-4, the "original and checks" tab): the bundle the decision used, its seal, the seal's
 * own check (the package hash and the inspector's seal integrity row) and the official inspection with a table by
 * check, the failed checks on top. A part the server has no record of says so; nothing is shown as checked that was
 * not, and nothing claims the input was drawn again (no reproduction source exists).
 */
export function VerifyParts({ quality }: { readonly quality: RunQuality | null }) {
  const { t } = useTranslation();
  const bundle = quality?.bundle ?? null;
  const seal = quality?.seal ?? null;
  const inspection = quality?.inspection ?? null;
  const sealCheck = inspection?.checks.find((check) => check.code === 'SEAL_INTEGRITY') ?? null;
  return (
    <div className={styles.verify}>
      {quality && !quality.available ? (
        <p className={styles.verifyLine} data-state="not-available">
          {t(`factsReason.${quality.reason ?? 'other'}`, { defaultValue: t('factsReason.other') })}
        </p>
      ) : null}
      <section className={styles.verifyPart} aria-labelledby="verify-bundle">
        <h3 id="verify-bundle" className={styles.verifyName}>
          {t('detail.verify.bundle')}
        </h3>
        <div className={styles.verifyBody}>
          {bundle ? (
            <p className={styles.verifyLine}>
              <code data-original>{bundle.version ?? '-'}</code>
              <span>· {t('detail.verify.hash')}</span>
              <code data-original>{(bundle.hash ?? '-').slice(0, 12)}</code>
              <span>· {t('detail.verify.selection')}</span>
              <code data-original>{bundle.selectionSource ?? '-'}</code>
            </p>
          ) : (
            <p className={styles.verifyLine}>{t('detail.verify.bundleNone')}</p>
          )}
        </div>
      </section>
      <section className={styles.verifyPart} aria-labelledby="verify-seal">
        <h3 id="verify-seal" className={styles.verifyName}>
          {t('detail.verify.seal')}
        </h3>
        <div className={styles.verifyBody}>
          {seal ? (
            <>
              <p className={styles.check} data-ok="true">
                <Icon name="check" />
                {t('detail.verify.sealed')}
              </p>
              <p className={styles.verifyLine}>
                <code data-original>{seal.packageId}</code>
                {seal.capturedAt ? (
                  <span>{t('detail.verify.sealedAt', { time: utcTime(seal.capturedAt) })}</span>
                ) : null}
              </p>
            </>
          ) : (
            <p className={styles.verifyLine}>{t('detail.verify.sealNone')}</p>
          )}
        </div>
      </section>
      <section className={styles.verifyPart} aria-labelledby="verify-seal-check">
        <h3 id="verify-seal-check" className={styles.verifyName}>
          {t('detail.verify.sealCheck')}
        </h3>
        <div className={styles.verifyBody}>
          {sealCheck ? (
            <>
              {/* The sealed text is the one the last model call sent only when the seal check found nothing wrong. */}
              <p className={styles.check} data-ok={sealCheck.mismatched === 0}>
                <Icon name={sealCheck.mismatched === 0 ? 'check' : 'cross'} />
                {t(sealCheck.mismatched === 0 ? 'detail.verify.sealSame' : 'detail.verify.sealCheckFailed')}
              </p>
              <p className={styles.verifyLine}>
                {seal ? <code data-original>{seal.packageHash ?? seal.packageId}</code> : null}
                <span>
                  {t('detail.verify.sealCheckCounts', {
                    matched: sealCheck.matched,
                    mismatched: sealCheck.mismatched,
                    unverifiable: sealCheck.unverifiable,
                  })}
                </span>
              </p>
            </>
          ) : (
            <p className={styles.verifyLine}>{t('detail.verify.sealCheckNone')}</p>
          )}
        </div>
      </section>
      <section className={styles.verifyPart} aria-labelledby="verify-inspection">
        <h3 id="verify-inspection" className={styles.verifyName}>
          {t('detail.verify.inspection')}
        </h3>
        <div className={styles.verifyBody}>
          {inspection ? (
            <>
              <p className={styles.check} data-ok={inspection.verdict === 'PASS'}>
                <Icon name={inspection.verdict === 'PASS' ? 'check' : 'cross'} />
                {t('detail.verify.inspected', {
                  verdict: t(`quality.verdict.${inspection.verdict}`, { defaultValue: t('quality.verdict.ERROR') }),
                })}
              </p>
              <p className={styles.verifyLine}>
                <code data-original>{inspection.inspectorVersion ?? '-'}</code>
                {inspection.inspectedAt ? (
                  <span>{t('detail.verify.inspectedAt', { time: utcTime(inspection.inspectedAt) })}</span>
                ) : null}
              </p>
              <details className={styles.fold}>
                <summary>{t('detail.verify.byCheck')}</summary>
                <table className={styles.checks}>
                  <thead>
                    <tr>
                      <th scope="col">{t('detail.verify.col.check')}</th>
                      <th scope="col">{t('detail.verify.col.matched')}</th>
                      <th scope="col">{t('detail.verify.col.mismatched')}</th>
                      <th scope="col">{t('detail.verify.col.unverifiable')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {failuresFirst(inspection.checks).map((check) => (
                      <tr key={check.code} data-failed={check.mismatched > 0 || undefined}>
                        <th scope="row">
                          {t(`quality.check.${check.code}`, { defaultValue: t('fact.label.other') })}
                          {check.mismatches.length > 0 ? (
                            <ul className={styles.deltaLines} aria-label={t('detail.verify.mismatches')}>
                              {check.mismatches.map((mismatch, index) => (
                                <li key={`${mismatch.line ?? '-'}-${index}`} className={styles.mismatch} data-original>
                                  {[mismatch.factId, mismatch.entry, mismatch.line, mismatch.expected, mismatch.actual]
                                    .map((part) => (part === null ? '-' : String(part)))
                                    .join(' · ')}
                                  {mismatch.reason ? ` (${mismatch.reason})` : ''}
                                </li>
                              ))}
                            </ul>
                          ) : null}
                        </th>
                        <td>{check.matched}</td>
                        <td>{check.mismatched}</td>
                        <td>{check.unverifiable}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </>
          ) : (
            <p className={styles.verifyLine}>{t('detail.verify.inspectionNone')}</p>
          )}
        </div>
      </section>
    </div>
  );
}
