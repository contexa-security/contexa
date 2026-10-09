import { createContext, useContext, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { GLOSSARY, GLOSSARY_MODAL, useGlossary, type GlossaryTerm } from './glossaryTerms';
import { Modal } from './Modal';
import { useUrlModal } from './useUrlModal';
import styles from './Glossary.module.css';

/**
 * The glossary (common-1): a modal opened from the top menu with a search box and the terms in alphabetical order, the
 * same content as the plain-words tables. It has its own address (?modal=glossary&term=...), so a term's "more" link
 * opens it on that term.
 */
export function GlossaryModal() {
  const { t, i18n } = useTranslation();
  const modal = useUrlModal(GLOSSARY_MODAL);
  const [query, setQuery] = useState('');
  const focus = modal.params.get('term');
  const searchId = useId();
  const entries = useMemo(() => {
    const collator = new Intl.Collator(i18n.language);
    return GLOSSARY.map((id) => ({
      id,
      term: t(`glossary.${id}.term`),
      plain: t(`glossary.${id}.plain`),
    })).sort((left, right) => collator.compare(left.term, right.term));
  }, [t, i18n.language]);
  const shown = entries.filter(
    (entry) =>
      query.trim() === '' ||
      `${entry.term} ${entry.plain}`.toLowerCase().includes(query.trim().toLowerCase()),
  );
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
        <dl className={styles.list}>
          {shown.map((entry) => (
            <div key={entry.id} className={styles.entry} data-focus={entry.id === focus || undefined}>
              <dt className={styles.term}>{entry.term}</dt>
              <dd className={styles.plain}>{entry.plain}</dd>
            </div>
          ))}
        </dl>
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
 * link to the glossary. Outside a scope every occurrence is underlined.
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
          <span className={styles.tipTerm}>{t(`glossary.${term}.term`)}</span> · {t(`glossary.${term}.plain`)}
          <button type="button" className={styles.more} onClick={() => openGlossary(term)}>
            {t('glossary.more')}
          </button>
        </span>
      ) : null}
    </span>
  );
}
