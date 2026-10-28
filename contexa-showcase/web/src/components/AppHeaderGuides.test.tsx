import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { AppHeader } from './AppHeader';

function serve(ids: readonly string[]) {
  const manifest = Object.fromEntries(
    ids.map((id) => [
      id,
      {
        file: `${id}.webm`,
        captions: { ko: `${id}.ko.vtt`, en: `${id}.en.vtt` },
        durationSec: 70,
        recordedAt: '2026-11-02T03:30:00Z',
        screens: 'v5',
      },
    ]),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url === '/guides/guides.json'
        ? new Response(JSON.stringify(manifest), { status: 200 })
        : new Response(null, { status: 404 }),
    ),
  );
}

function menu() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AppHeader />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: i18n.t('frame.menu') }));
  return within(screen.getByRole('dialog'));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the menu and the guide videos', () => {
  it('leads to the list of the guide videos once one was recorded', async () => {
    serve(['request']);
    const nav = menu();
    const link = await nav.findByRole('link', { name: i18n.t('frame.menu.guides') });
    expect(link).toHaveAttribute('href', '/videos');
  });

  it('shows the entry only when a video exists in the screen language', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/guides/guides.json'
          ? new Response(
              JSON.stringify({
                request: {
                  en: { file: 'request.en.webm', captions: { en: 'request.en.vtt' }, durationSec: 70, recordedAt: '2026-11-02T03:30:00Z', screens: 'v5' },
                },
              }),
              { status: 200 },
            )
          : new Response(null, { status: 404 }),
      ),
    );
    const nav = menu();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(nav.queryByRole('link', { name: i18n.t('frame.menu.guides') })).toBeNull();
  });

  it('shows no such entry while nothing but the old recordings exists', async () => {
    serve(['console', 'agent']);
    const nav = menu();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(nav.queryByRole('link', { name: i18n.t('frame.menu.guides') })).toBeNull();
    expect(nav.getByRole('link', { name: i18n.t('frame.menu.more') })).toBeInTheDocument();
  });
});
