import { useTranslation } from 'react-i18next';
import { AppHeader } from '../components/AppHeader';
import { PRIVACY } from '../content/policies';
import styles from './PolicyPage.module.css';

/** The privacy notice, linked from the footer only; the demo itself never asks the visitor for anything. */
export default function PolicyPage() {
  const { t, i18n } = useTranslation();
  const content = PRIVACY[i18n.language === 'ko' ? 'ko' : 'en'];

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <article className={styles.article}>
          <h1 className={styles.title}>{content.title}</h1>
          {content.sections.map((section) => (
            <section key={section.heading} className={styles.section}>
              <h2 className={styles.heading}>{section.heading}</h2>
              {section.paragraphs?.map((paragraph) => (
                <p key={paragraph} className={styles.paragraph}>
                  {paragraph}
                </p>
              ))}
              {section.table ? <PolicyTable rows={section.table} /> : null}
            </section>
          ))}
        </article>
      </main>
    </>
  );
}

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
                    {cell}
                  </th>
                ) : (
                  <td key={index}>{cell}</td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
