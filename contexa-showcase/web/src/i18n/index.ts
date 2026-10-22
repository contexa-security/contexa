import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

export const SUPPORTED_LANGUAGES = ['ko', 'en'] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

// index.html picks the first language by the same rule and key (languagePreload.ts); change both together.
const STORAGE_KEY = 'showcase.language';
const PSEUDO_LANGUAGE = 'pseudo';

type Dictionary = Readonly<Record<string, string>>;
type Part = 'first' | 'rest';

/**
 * Each language's dictionary is its own chunk (C-13), in two parts (FC-4, dictionarySplit.ts): the words the main flow
 * can show, which the first screen waits for and index.html preloads next to the application's code, and the rest,
 * read after the first screen is shown or when a screen that needs it opens (dictionaryComplete).
 */
const DICTIONARIES: Readonly<
  Record<SupportedLanguage, Readonly<Record<Part, () => Promise<{ readonly default: Dictionary }>>>>
> = {
  ko: {
    first: () => import('virtual:dictionary/ko/first'),
    rest: () => import('virtual:dictionary/ko/rest'),
  },
  en: {
    first: () => import('virtual:dictionary/en/first'),
    rest: () => import('virtual:dictionary/en/rest'),
  },
};

/** Each part is read once; a second ask gets the same promise. */
const parts = new Map<string, Promise<void>>();

function loadPart(language: SupportedLanguage, part: Part): Promise<void> {
  const key = `${language}/${part}`;
  let loading = parts.get(key);
  if (!loading) {
    loading = DICTIONARIES[language][part]().then((module) => {
      i18n.addResourceBundle(language, 'translation', module.default, true, false);
    });
    parts.set(key, loading);
  }
  return loading;
}

function supported(language: string | null): language is SupportedLanguage {
  return language !== null && (SUPPORTED_LANGUAGES as readonly string[]).includes(language);
}

/**
 * Pseudo locale used only by layout tests in development: English stretched by 30 percent so that
 * a mock proves the layout survives longer translations without overflow.
 */
function pseudoLocalize(source: Dictionary): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    const padding = Math.ceil(value.length * 0.3);
    result[key] = `${value}${' ~'.repeat(Math.ceil(padding / 2))}`.slice(0, value.length + padding);
  }
  return result;
}

function initialLanguage(): string {
  const requested = new URLSearchParams(window.location.search).get('lng');
  if (import.meta.env.DEV && requested === PSEUDO_LANGUAGE) {
    return PSEUDO_LANGUAGE;
  }
  if (supported(requested)) {
    return requested;
  }
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (supported(stored)) {
      return stored;
    }
  } catch {
    // Storage can be unavailable (private mode); the browser language is used instead.
  }
  return window.navigator.language.toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

/** Reads a language's whole dictionary once and adds it; the pseudo locale (development only) is stretched English. */
export async function loadLanguage(language: string): Promise<void> {
  if (import.meta.env.DEV && language === PSEUDO_LANGUAGE) {
    if (!i18n.hasResourceBundle(PSEUDO_LANGUAGE, 'translation')) {
      const [first, rest] = await Promise.all([DICTIONARIES.en.first(), DICTIONARIES.en.rest()]);
      i18n.addResourceBundle(
        PSEUDO_LANGUAGE,
        'translation',
        pseudoLocalize({ ...first.default, ...rest.default }),
      );
    }
    return;
  }
  if (supported(language)) {
    await Promise.all([loadPart(language, 'first'), loadPart(language, 'rest')]);
  }
}

/**
 * The rest of the current language's dictionary, read now if it is not in yet: a screen outside the main flow waits
 * for it before it is drawn (src/screens.tsx), and the application reads it once the first screen is shown.
 */
export function dictionaryComplete(): Promise<void> {
  const language = i18n.language;
  return supported(language) ? loadPart(language, 'rest') : loadLanguage(language);
}

/** Switches the language once its dictionary is in, so no screen shows keys meanwhile. */
export async function setLanguage(language: SupportedLanguage): Promise<void> {
  await loadLanguage(language);
  await i18n.changeLanguage(language);
}

const firstLanguage = initialLanguage();

// Both dictionaries carry the same keys (dictionaries.test.ts), so no language falls back to another.
void i18n.use(initReactI18next).init({
  resources: {},
  partialBundledLanguages: true,
  lng: firstLanguage,
  fallbackLng: false,
  interpolation: { escapeValue: false },
  returnNull: false,
});

/** The first screen is painted once this has settled: the first part of the visitor's language's dictionary is in. */
export const i18nReady: Promise<void> = supported(firstLanguage)
  ? loadPart(firstLanguage, 'first')
  : loadLanguage(firstLanguage);

function remember(language: string) {
  if (supported(language)) {
    try {
      window.localStorage.setItem(STORAGE_KEY, language);
    } catch {
      // Remembering the language is a convenience only.
    }
  }
}

i18n.on('languageChanged', (language) => {
  document.documentElement.lang = language === PSEUDO_LANGUAGE ? 'en' : language;
  remember(language);
});
// The language a link opened with (?lng=) is remembered too, so a reload or the next address without it keeps it.
remember(i18n.language);
document.documentElement.lang = i18n.language === PSEUDO_LANGUAGE ? 'en' : i18n.language;

export default i18n;
