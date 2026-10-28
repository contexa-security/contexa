import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import OpeningPage from './OpeningPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = url === '/api/visitor' ? { predictions: {} } : undefined;
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function opening() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="*" element={<OpeningPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * 1-1, the landing (docs/showcase/첫화면-선택형-체험-구현계획 NW-2, 사용자 지시 2026-10-27): Contexa introduced with one
 * strong question and one line, what the demo is for in a short line, and one way into the demo, "데모 시작하기". The
 * choice of a track is the next screen's.
 */
describe('the landing screen', () => {
  it('introduces Contexa strongly, says what the demo is for and offers one way into the demo', () => {
    opening();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('main.1-1.title'));
    expect(screen.getByText(word('main.1-1.intro'))).toBeInTheDocument();
    expect(screen.getByText(word('main.1-1.purpose'))).toBeInTheDocument();
    const start = screen.getByRole('link', { name: new RegExp(word('main.1-1.cta')) });
    expect(start).toHaveAttribute('href', '/choose');
    expect(word('main.1-1.cta')).toBe('데모 시작하기');
    // nothing else to press: the tracks are chosen on the next screen
    expect(screen.queryByRole('link', { name: /에이전트가 보낸 요청|사람이 보낸 요청/ })).toBeNull();
  });

  it('keeps the title within 28 characters and the intro within 40 (R-N4, spaces not counted)', () => {
    expect(word('main.1-1.title').replace(/\s/g, '').length).toBeLessThanOrEqual(28);
    expect(word('main.1-1.intro').replace(/\s/g, '').length).toBeLessThanOrEqual(40);
  });

  it('keeps the first screen under the text budget of a landing (AC-N1, 120 characters with the button)', () => {
    const spoken = [
      word('main.1-1.title'),
      word('main.1-1.intro'),
      word('main.1-1.purpose'),
      word('main.1-1.meta'),
      word('main.1-1.cta'),
    ]
      .join('')
      .replace(/\s/g, '');
    expect(spoken.length).toBeLessThanOrEqual(120);
  });

  it('draws no steps in the top bar before a track is chosen', () => {
    opening();
    expect(screen.queryByRole('list', { name: /여섯 단계/ })).toBeNull();
  });

  // 가이드영상-제작기획안.md 4.1절: the start video's link stands beside the start button, for a visitor who is new here.
  it('offers the start guide right after the start button once it was recorded, and nothing before', async () => {
    const { container } = opening();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container.querySelector('[data-guide-slot]')).toBeNull();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/guides/guides.json'
          ? new Response(
              JSON.stringify({
                start: {
                  file: 'start.webm',
                  captions: { ko: 'start.ko.vtt', en: 'start.en.vtt' },
                  durationSec: 65,
                  recordedAt: '2026-11-02T03:30:00Z',
                  screens: 'v5',
                },
              }),
              { status: 200 },
            )
          : url === '/api/visitor'
            ? new Response(JSON.stringify({ predictions: {} }), { status: 200 })
            : new Response(null, { status: 404 }),
      ),
    );
    const again = opening();
    const link = await screen.findByRole('button', { name: '미리보기 영상 · 1분 5초' });
    const start = screen.getAllByRole('link', { name: new RegExp(word('main.1-1.cta')) })[1] as HTMLElement;
    expect(start.compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(link.closest('[data-guide-slot]')).toHaveAttribute('data-variant', 'start');
    again.unmount();
  });
});
