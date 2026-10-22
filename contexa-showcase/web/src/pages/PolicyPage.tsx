import { useTranslation } from 'react-i18next';
import { AppHeader } from '../components/AppHeader';
import { ScreenBody } from '../components/journey/ScreenBody';
import { NextLink } from '../components/journey/StepParts';
import { PRIVACY } from '../content/policies';
import frame from './try/Experience.module.css';
import styles from './PolicyPage.module.css';

/**
 * The privacy notice (화면재편-구현계획 5절, RO-7), opened from the menu: the same frame as every screen (top bar with
 * the space's name, title zone, body, action bar). It is a document, so its length is the notice's own; every fact of
 * docs/showcase/개인정보-데이터목록.md stays as written, in the plain terms of the redesign. The demo itself never asks
 * the visitor for anything, so the page has nothing to answer.
 */
export default function PolicyPage() {
  const { t, i18n } = useTranslation();
  const content = PRIVACY[i18n.language === 'ko' ? 'ko' : 'en'];

  return (
    <>
      <AppHeader space={{ name: t('frame.space.privacy') }} />
      <main id="main" className={frame.page} data-type="doc">
        <ScreenBody
          title={content.title}
          purpose={t('space.r7.privacy.guide')}
          back={null}
          main={<NextLink to="/" label={t('state.home')} />}
        >
          {content.sections.map((section) => (
            <section key={section.heading} className={styles.section}>
              <h2 className={styles.heading}>{section.heading}</h2>
              {section.paragraphs ? (
                <ul className={styles.points}>
                  {section.paragraphs.map((paragraph) => (
                    <li key={paragraph}>{paragraph}</li>
                  ))}
                </ul>
              ) : null}
              {section.table ? <PolicyTable rows={section.table} /> : null}
            </section>
          ))}
        </ScreenBody>
      </main>
    </>
  );
}

/** A row named by a technical identifier (a cookie's name) shows it as the original it is. */
const TECHNICAL = /^[A-Z][A-Z0-9_-]+$/;

function PolicyTable({ rows }: { readonly rows: readonly (readonly string[])[] }) {
  const [head, ...body] = rows;
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            {head?.map((cell, index) => (
              <th key={index} scope="col">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((row) => (
            <tr key={row[0]}>
              {row.map((cell, index) =>
                index === 0 ? (
                  <th key={index} scope="row">
                    {TECHNICAL.test(cell) ? <code data-original>{cell}</code> : cell}
                  </th>
                ) : (
                  // Phones stack a row's cells; each cell then names its column (the head row is hidden there).
                  <td key={index} data-label={head?.[index]}>
                    {cell}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
