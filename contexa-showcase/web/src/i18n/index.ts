import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from './en.json';
import ko from './ko.json';

export const SUPPORTED_LANGUAGES = ['ko', 'en'] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

const STORAGE_KEY = 'showcase.language';
const PSEUDO_LANGUAGE = 'pseudo';

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
  if (requested && (SUPPORTED_LANGUAGES as readonly string[]).includes(requested)) {
    return requested;
  }
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored && (SUPPORTED_LANGUAGES as readonly string[]).includes(stored)) {
      return stored;
    }
  } catch {
    // Storage can be unavailable (private mode); the browser language is used instead.
  }
  return window.navigator.language.toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

const resources: Record<string, { translation: Record<string, string> }> = {
  ko: { translation: ko },
  en: { translation: en },
};
if (import.meta.env.DEV) {
  resources[PSEUDO_LANGUAGE] = { translation: pseudoLocalize(en) };
}

void i18n.use(initReactI18next).init({
  resources,
  lng: initialLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
  returnNull: false,
});

i18n.on('languageChanged', (language) => {
  document.documentElement.lang = language === PSEUDO_LANGUAGE ? 'en' : language;
  if ((SUPPORTED_LANGUAGES as readonly string[]).includes(language)) {
    try {
      window.localStorage.setItem(STORAGE_KEY, language);
    } catch {
      // Remembering the language is a convenience only.
    }
  }
});
document.documentElement.lang = i18n.language === PSEUDO_LANGUAGE ? 'en' : i18n.language;

export default i18n;
