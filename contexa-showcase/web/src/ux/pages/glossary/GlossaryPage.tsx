import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { search, termOf, TERMS } from '../../glossary/search';
import type { GlossaryTerm } from '../../glossary/terms';
import { formatNumber } from '../../format';
import { ButtonLink, Button, DetailPanel, Drawer, EmptyState, Field, PageHead, TextInput } from '../../ui';
import { DRAWER_QUERY, useMedia } from '../../useMedia';
import styles from './Glossary.module.css';

/**
 * The security glossary (기획안 4절 바닥 · 9절, DEC-69): the official names of every screen with their definitions,
 * searchable in either language; the list on the left and the chosen term on the right, or in a drawer under 1024.
 * `?term=` names the chosen term and `?q=` keeps the search, so both can be shared.
 */
export default function GlossaryPage() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const narrow = useMedia(DRAWER_QUERY);
  const query = params.get('q') ?? '';
  const chosen = termOf(params.get('term'));
  const words = (term: GlossaryTerm) => [
    t(`ux.glossary.term.${term.id}.name`),
    t(`ux.glossary.term.${term.id}.def`),
    ...(term.short ? [t(`ux.glossary.term.${term.id}.short`)] : []),
  ];
  const groups = search(query, words);
  const found = groups.reduce((sum, group) => sum + group.terms.length, 0);
  const set = (changes: Readonly<Record<string, string | null>>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null || value === '') {
        next.delete(key);
      } else {
        next.set(key, value);
      }
    }
    setParams(next, { replace: true });
  };
  const hrefOf = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('term', id);
    return `?${next.toString()}`;
  };
  return (
    <>
      <PageHead title={t('ux.glossary.title')} desc={t('ux.glossary.desc')} />
      <div className={styles.layout} data-open={(chosen !== null && !narrow) || undefined}>
        <section className={styles.listSide} aria-label={t('ux.glossary.list')}>
          <div className={styles.searchRow}>
            <Field label={t('ux.glossary.search')}>
              {(props) => (
                <TextInput
                  {...props}
                  compact
                  type="search"
                  placeholder={t('ux.glossary.searchHint')}
                  value={query}
                  onChange={(event) => set({ q: event.target.value })}
                />
              )}
            </Field>
            <p className={styles.count} role="status">
              {query.trim() === ''
                ? t('ux.glossary.count', { count: TERMS.length, n: formatNumber(TERMS.length, i18n.language) })
                : t('ux.glossary.found', { count: found, n: formatNumber(found, i18n.language) })}
            </p>
          </div>
          {groups.length === 0 ? (
            <EmptyState
              action={
                <Button variant="secondary" onClick={() => set({ q: null })}>
                  {t('ux.glossary.clear')}
                </Button>
              }
            >
              {t('ux.glossary.empty')}
            </EmptyState>
          ) : (
            groups.map((group) => (
              <section key={group.id} className={styles.group} aria-labelledby={`glossary-${group.id}`}>
                <h2 id={`glossary-${group.id}`} className={styles.groupName}>
                  {t(`ux.glossary.group.${group.id}`)}
                </h2>
                <ul className={styles.terms}>
                  {group.terms.map((term) => (
                    <li key={term.id}>
                      <Link
                        to={hrefOf(term.id)}
                        replace
                        className={styles.term}
                        aria-current={chosen?.id === term.id ? 'true' : undefined}
                      >
                        <span className={styles.termName}>{t(`ux.glossary.term.${term.id}.name`)}</span>
                        {i18n.language === 'en' ? null : (
                          // The space keeps the two names apart when the link is read out.
                          <>
                            {' '}
                            <span className={styles.termEn} lang="en">
                              {term.en}
                            </span>
                          </>
                        )}
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            ))
          )}
        </section>
        {!narrow ? (
          <div className={styles.side}>
            {chosen ? (
              <DetailPanel title={t(`ux.glossary.term.${chosen.id}.name`)} onClose={() => set({ term: null })}>
                <TermBody term={chosen} />
              </DetailPanel>
            ) : (
              <aside className={styles.pick}>{t('ux.glossary.pick')}</aside>
            )}
          </div>
        ) : null}
      </div>
      {narrow ? (
        <Drawer
          open={chosen !== null}
          onClose={() => set({ term: null })}
          title={chosen ? t(`ux.glossary.term.${chosen.id}.name`) : ''}
        >
          {chosen ? <TermBody term={chosen} /> : null}
        </Drawer>
      ) : null}
    </>
  );
}

function TermBody({ term }: { readonly term: GlossaryTerm & { readonly group: string } }) {
  const { t, i18n } = useTranslation();
  return (
    <div className={styles.body}>
      <p className={styles.definition}>{t(`ux.glossary.term.${term.id}.def`)}</p>
      <dl className={styles.facts}>
        {i18n.language === 'en' ? null : (
          <div>
            <dt>{t('ux.glossary.english')}</dt>
            <dd lang="en">{term.en}</dd>
          </div>
        )}
        {term.short && t(`ux.glossary.term.${term.id}.short`) !== t(`ux.glossary.term.${term.id}.name`) ? (
          <div>
            <dt>{t('ux.glossary.short')}</dt>
            <dd>{t(`ux.glossary.term.${term.id}.short`)}</dd>
          </div>
        ) : null}
        <div>
          <dt>{t('ux.glossary.group')}</dt>
          <dd>{t(`ux.glossary.group.${term.group}`)}</dd>
        </div>
      </dl>
      {term.link ? (
        <ButtonLink to={term.link} icon="arrow-right" variant="secondary">
          {t('ux.glossary.open')}
        </ButtonLink>
      ) : null}
    </div>
  );
}
