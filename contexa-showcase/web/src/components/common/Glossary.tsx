import { createContext, useContext, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import {
  GLOSSARY_GROUPS,
  GLOSSARY_MODAL,
  glossaryKey,
  useGlossary,
  type GlossaryTerm,
} from './glossaryTerms';
import { Modal } from './Modal';
import { useUrlModal } from './useUrlModal';
import styles from './Glossary.module.css';

interface Entry {
  readonly id: GlossaryTerm;
  readonly term: string;
  readonly plain: string;
  /** The field's own name for it, where it has one (written as the field writes it, even an old screen word). */
  readonly industry: string | null;
}

/**
 * The glossary (화면재편-기획안 11절, R-11): a window opened from the menu, with a search box and the terms in the groups
 * and order of the word tables. Each term is the name the screens use, its meaning in one line, and the field's own
 * name where it has one. It has its own address (?modal=glossary&term=...), so a term's "more" button opens it on that
 * term.
 */
export function GlossaryModal() {
  const { t, i18n } = useTranslation();
  const modal = useUrlModal(GLOSSARY_MODAL, ['term']);
  const [query, setQuery] = useState('');
  const focus = modal.params.get('term');
  const searchId = useId();
  const groups = useMemo(
    () =>
      GLOSSARY_GROUPS.map((group) => ({
        id: group.id,
        name: t(`space.r7.glossary.group.${group.id}`),
        entries: group.terms.map((id): Entry => ({
          id,
          term: t(glossaryKey(id, 'term')),
          plain: t(glossaryKey(id, 'plain')),
          industry: i18n.exists(glossaryKey(id, 'industry')) ? t(glossaryKey(id, 'industry')) : null,
        })),
      })),
    [t, i18n],
  );
  const needle = query.trim().toLowerCase();
  const shown = groups
    .map((group) => ({
      ...group,
      entries: group.entries.filter(
        (entry) =>
          needle === '' ||
          `${entry.term} ${entry.plain} ${entry.industry ?? ''}`.toLowerCase().includes(needle),
      ),
    }))
    .filter((group) => group.entries.length > 0);
  return (
    <Modal open={modal.open} onClose={modal.hide} title={t('glossary.title')}>
      <label className={styles.search} htmlFor={searchId}>
        {t('glossary.search')}
        <input
          id={searchId}
          type="search"
          className={styles.input}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      {shown.length === 0 ? (
        <p className={styles.empty}>{t('glossary.empty')}</p>
      ) : (
        shown.map((group) => (
          <section key={group.id} className={styles.group} aria-labelledby={`glossary-${group.id}`}>
            <h3 id={`glossary-${group.id}`} className={styles.groupName}>
              {group.name}
            </h3>
            <dl className={styles.list}>
              {group.entries.map((entry) => (
                <div key={entry.id} className={styles.entry} data-focus={entry.id === focus || undefined}>
                  <dt className={styles.term}>{entry.term}</dt>
                  <dd className={styles.plain}>{entry.plain}</dd>
                  {entry.industry ? (
                    // The field's own name is quoted as written (11절 '업계 용어'), so it is marked as an original.
                    <dd className={styles.industry}>
                      <Trans
                        i18nKey="space.r7.glossary.industry"
                        values={{ name: entry.industry }}
                        components={{ original: <span data-original /> }}
                      />
                    </dd>
                  ) : null}
                </div>
              ))}
            </dl>
          </section>
        ))
      )}
    </Modal>
  );
}

interface TermScopeValue {
  /** True for the first occurrence of a term in the scope; later ones render as plain words. */
  readonly claim: (term: GlossaryTerm, instance: string) => boolean;
}

const TermScopeContext = createContext<TermScopeValue | null>(null);

/**
 * One screen's terms (common-1): the same term is underlined only the first time it appears on the screen. A screen
 * wraps its content in one scope.
 */
export function TermScope({ children }: { readonly children: ReactNode }) {
  const first = useRef(new Map<GlossaryTerm, string>());
  const value = useMemo<TermScopeValue>(
    () => ({
      claim: (term, instance) => {
        const owner = first.current.get(term);
        if (owner === undefined) {
          first.current.set(term, instance);
          return true;
        }
        return owner === instance;
      },
    }),
    [],
  );
  return <TermScopeContext.Provider value={value}>{children}</TermScopeContext.Provider>;
}

interface TermProps {
  readonly term: GlossaryTerm;
  readonly children: ReactNode;
}

/**
 * A term explained where it first appears (common-1): a dotted underline that opens a short plain explanation and a
 * button to the glossary. Outside a scope every occurrence is underlined.
 */
export function Term({ term, children }: TermProps) {
  const { t } = useTranslation();
  const scope = useContext(TermScopeContext);
  const instance = useId();
  const tipId = useId();
  const [open, setOpen] = useState(false);
  const openGlossary = useGlossary();
  if (scope && !scope.claim(term, instance)) {
    return <>{children}</>;
  }
  return (
    <span className={styles.termWrap}>
      <button
        type="button"
        className={styles.termButton}
        data-term
        aria-expanded={open}
        aria-describedby={open ? tipId : undefined}
        onClick={() => setOpen((value) => !value)}
      >
        {children}
      </button>
      {open ? (
        <span id={tipId} role="tooltip" className={styles.tip}>
          <span className={styles.tipTerm}>{t(glossaryKey(term, 'term'))}</span> ·{' '}
          {t(glossaryKey(term, 'plain'))}
          <button type="button" className={styles.more} onClick={() => openGlossary(term)}>
            {t('glossary.more')}
          </button>
        </span>
      ) : null}
    </span>
  );
}
