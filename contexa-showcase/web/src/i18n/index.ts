import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

export const SUPPORTED_LANGUAGES = ['ko', 'en'] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

// index.html picks the first language by the same rule and key (languagePreload.ts); change both together.
const STORAGE_KEY = 'showcase.language';
const PSEUDO_LANGUAGE = 'pseudo';

type Dictionary = Record<string, string>;

/**
 * Each language's dictionary is its own chunk (C-13): the first screen needs only the visitor's language, and
 * index.html preloads that one next to the application's code.
 */
const DICTIONARIES: Readonly<Record<SupportedLanguage, () => Promise<{ readonly default: Dictionary }>>> = {
  ko: () => import('./ko.json'),
  en: () => import('./en.json'),
};

function supported(language: string | null): language is SupportedLanguage {
  return language !== null && (SUPPORTED_LANGUAGES as readonly string[]).includes(language);
}

/**
 * Pseudo locale used only by layout tests in development: English stretched by 30 percent so that
 * a mock proves the layout survives longer translations without overflow.
 */
function pseudoLocalize(source: Record<string, string>): Record<string, string> {
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

/** Reads a language's dictionary once and adds it; the pseudo locale (development only) is stretched English. */
export async function loadLanguage(language: string): Promise<void> {
  if (i18n.hasResourceBundle(language, 'translation')) {
    return;
  }
  if (import.meta.env.DEV && language === PSEUDO_LANGUAGE) {
    i18n.addResourceBundle(PSEUDO_LANGUAGE, 'translation', pseudoLocalize((await DICTIONARIES.en()).default));
    return;
  }
  if (supported(language)) {
    i18n.addResourceBundle(language, 'translation', (await DICTIONARIES[language]()).default);
  }
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

/** The first screen is painted once this has settled: the visitor's language's dictionary is in. */
export const i18nReady: Promise<void> = loadLanguage(firstLanguage);

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
