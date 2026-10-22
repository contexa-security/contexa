import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import HowPage from './HowPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const STEPS = [
  'request',
  'usual',
  'company',
  'history',
  'prompt',
  'judgement',
  'decision',
  'followUp',
  'learning',
];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 3, step: 'g-how', differences: [] },
          runs: [],
          predictions: [],
        },
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/intro/how']}>
        <HowPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Screen 3-2 (화면재편 T7): the nine steps a request passes, as one figure that is read, not pressed. */
describe('how Contexa judges', () => {
  it('draws the nine steps in order, each with its name and what it does, and the way back to the usual', () => {
    open();
    const figure = screen.getByRole('list', { name: word('p3.how.figure') });
    const items = within(figure).getAllByRole('listitem');
    expect(items.map((item) => item.textContent)).toEqual(
      STEPS.map(
        (id, index) => `${index + 1}${word(`p3.how.step.${id}.name`)}${word(`p3.how.step.${id}.text`)}`,
      ),
    );
    expect(screen.getByText(word('p3.how.loop'))).toBeInTheDocument();
  });

  it('keeps only the figure: nothing to press in the body, and the old two-way comparison is not drawn', () => {
    const { container } = open();
    expect(screen.getByRole('heading', { level: 1, name: word('screen.3-2.title') })).toBeInTheDocument();
    expect(screen.getByText(word('screen.3-2.guide'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.e3-stack')) })).toHaveAttribute('href', '/try/stack');
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details')).toHaveLength(0);
    // No numbers to source on this screen, so no source line.
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
    const text = document.body.textContent ?? '';
    for (const key of ['how.old.name', 'how.old.text', 'how.new.text', 'how.flowLabel']) {
      expect(text).not.toContain(word(key));
    }
  });
});
