import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import ko from '../i18n/ko.json';
import { PRIVACY } from '../content/policies';
import { required } from '../test/required';
import PolicyPage from './PolicyPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 0, step: 'hook', differences: [] },
          runs: [],
          predictions: [],
        },
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), {
        status: body === undefined ? 404 : 200,
      });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/privacy']}>
        <PolicyPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The privacy notice in the shared frame (화면재편-구현계획 5절, RO-7): a document, opened from the menu. */
describe('privacy notice', () => {
  it.each(['ko', 'en'] as const)(
    'shows every heading, line and table cell of the notice in %s, the cookies as the originals they are',
    async (language) => {
      await i18n.changeLanguage(language);
      const { container } = open();
      const content = PRIVACY[language];
      expect(screen.getByRole('heading', { level: 1, name: content.title })).toBeInTheDocument();
      const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
      for (const section of content.sections) {
        expect(within(body).getByRole('heading', { level: 2, name: section.heading })).toBeInTheDocument();
        for (const paragraph of section.paragraphs ?? []) {
          expect(within(body).getByText(paragraph)).toBeInTheDocument();
        }
        for (const row of section.table ?? []) {
          for (const cell of row) {
            expect(within(body).getAllByText(cell).length, cell).toBeGreaterThan(0);
          }
        }
      }
      for (const cookie of ['SC_VISITOR', 'XSRF-TOKEN']) {
        const name = screen.getByRole('rowheader', { name: cookie });
        expect(within(name).getByText(cookie).tagName).toBe('CODE');
        expect(within(name).getByText(cookie)).toHaveAttribute('data-original');
      }
      expect(container.querySelector('main')).toHaveAttribute('data-type', 'doc');
    },
  );

  it.each([
    { language: 'ko' as const, gone: ['이해 확인', '공유 카드', '투표'], lab: '실험실', words: ['해시', '비용 방어', '도착한', '장면', '투표'] },
    { language: 'en' as const, gone: ['quiz', 'Share card', 'vote'], lab: 'lab', words: ['hash', 'Cost protection', 'scene', 'vote'] },
  ])('lists only what the demo processes today, in plain words ($language)', ({ language, gone, lab, words }) => {
    const content = PRIVACY[language];
    const [processed] = content.sections.filter((section) => section.table && section.table[0]?.length === 3);
    const rows = required(processed?.table, 'the table of what is processed').slice(1);
    // V-19: the quiz and the share card are gone, so they are no rows of what is processed; the lab's calls are.
    for (const row of rows) {
      for (const word of gone) {
        expect(row[0]?.toLowerCase(), word).not.toContain(word.toLowerCase());
      }
    }
    expect(rows.some((row) => row[0]?.toLowerCase().includes(lab.toLowerCase()))).toBe(true);
    // P-20: no technical shorthand in the notice.
    const text = JSON.stringify(content).toLowerCase();
    for (const word of words) {
      expect(text, word).not.toContain(word.toLowerCase());
    }
  });

  it('asks nothing of the visitor: nothing to press in the notice, one way on to the start', async () => {
    await i18n.changeLanguage('ko');
    const { container } = open();
    expect(screen.getByText(word('space.r7.privacy.guide'))).toBeInTheDocument();
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    expect(zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href], input')))).toHaveLength(
      0,
    );
    const actions = required(container.querySelector<HTMLElement>('[data-zone="actions"]'), 'the action bar');
    expect(within(actions).getByRole('link', { name: word('state.home') })).toHaveAttribute('href', '/');
    // The top bar names the space instead of the five parts.
    expect(container.querySelector('[data-zone="top"]')).toHaveTextContent(word('frame.space.privacy'));
  });
});
