import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { MainScreen } from './MainScreen';

/** One recorded video per guide id, as the recording script lists them (가이드영상-제작기획안.md 7.1절). */
function recorded(ids: readonly string[]) {
  return Object.fromEntries(
    ids.map((id) => [
      id,
      {
        file: `${id}.webm`,
        captions: { ko: `${id}.ko.vtt`, en: `${id}.en.vtt` },
        durationSec: 74,
        recordedAt: '2026-11-02T03:30:00Z',
        screens: 'v5',
      },
    ]),
  );
}

function serve(ids: readonly string[]) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url === '/guides/guides.json'
        ? new Response(JSON.stringify(recorded(ids)), { status: 200 })
        : new Response(null, { status: 404 }),
    ),
  );
}

function screenAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="*"
            element={
              <MainScreen title="제목" intro="안내">
                <p>핵심</p>
              </MainScreen>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// 가이드영상-제작기획안.md 4.1절: every screen a video explains carries the same link in the same place.
describe('the guide link of a screen', () => {
  it('stands in the title zone, in its own slot, on every screen its video explains', async () => {
    serve(['request']);
    for (const path of [
      '/attack/request',
      '/attack/console',
      '/normal/request',
      '/normal/console',
      '/insider/request',
      '/insider/console',
    ]) {
      const { container, unmount } = screenAt(path);
      const link = await screen.findByRole('button', { name: '미리보기 영상 · 1분 14초' });
      const slot = container.querySelector('[data-guide-slot]');
      expect(slot?.contains(link), path).toBe(true);
      expect(slot?.closest('[data-zone="title"]'), path).not.toBeNull();
      unmount();
    }
  });

  it('is not drawn on a screen without a video, nor for a video that was not recorded', async () => {
    serve(['request']);
    for (const path of ['/choose', '/person', '/deeper', '/summary', '/evidence/map', '/agent/request']) {
      const { container, unmount } = screenAt(path);
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(screen.queryByRole('button', { name: /미리보기 영상/ }), path).toBeNull();
      expect(container.querySelector('[data-guide-slot]'), path).toBeNull();
      unmount();
    }
  });

  it('finds each screen by its number: the result, the agent and the evidence screens each get their own video', async () => {
    serve(['result', 'agentResult', 'evidence', 'delegate', 'insider', 'check', 'rules', 'diff', 'confirm', 'burst']);
    const expected: Record<string, number> = {
      '/attack/result': 1,
      '/attack/reason': 1,
      '/insider/reason': 1,
      '/agent/request': 1,
      '/agent/console': 1,
      '/agent/result': 1,
      '/agent/reason': 1,
      '/normal/check': 1,
      '/evidence/map': 1,
      '/evidence/prompt': 1,
      '/evidence/verdict': 1,
      '/compare/rule': 1,
      '/compare/change': 1,
      '/normal/diff': 1,
      '/agent/confirm': 1,
      '/agent/end': 1,
      '/agent/burst': 1,
    };
    for (const [path, count] of Object.entries(expected)) {
      const { unmount } = screenAt(path);
      expect(await screen.findAllByRole('button', { name: /미리보기 영상/ }), path).toHaveLength(count);
      unmount();
    }
  });

  it('draws nothing while the manifest has no video at all', async () => {
    serve([]);
    const { container } = screenAt('/attack/request');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container.querySelector('[data-guide-slot]')).toBeNull();
  });
});
