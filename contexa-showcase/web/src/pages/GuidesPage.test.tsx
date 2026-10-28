import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import GuidesPage from './GuidesPage';

function recorded(durations: Readonly<Record<string, number>>) {
  return Object.fromEntries(
    Object.entries(durations).map(([id, durationSec]) => [
      id,
      {
        file: `${id}.webm`,
        captions: { ko: `${id}.ko.vtt`, en: `${id}.en.vtt` },
        durationSec,
        recordedAt: '2026-11-02T03:30:00Z',
        screens: 'v5',
      },
    ]),
  );
}

function serve(durations: Readonly<Record<string, number>>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url === '/guides/guides.json'
        ? new Response(JSON.stringify(recorded(durations)), { status: 200 })
        : new Response(null, { status: 404 }),
    ),
  );
}

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/videos']}>
        <Routes>
          <Route path="/videos" element={<GuidesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  window.localStorage.removeItem('contexa.guide.watched');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// 가이드영상-제작기획안.md 4.1절: the menu leads to one place where every recorded video can be found again.
describe('the list of the guide videos', () => {
  it('has a strong title and one intro line, and tells when no video was recorded yet', async () => {
    serve({});
    open();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(i18n.t('guides.title'));
    expect(screen.getByText(i18n.t('guides.intro'))).toBeInTheDocument();
    expect(await screen.findByText(i18n.t('guides.none'))).toBeInTheDocument();
  });

  it('groups the recorded videos for a newcomer, a person, an agent and the shared deeper ones, and leaves the old recordings out', async () => {
    serve({ evidence: 120, delegate: 80, request: 74, start: 65, console: 70 });
    open();
    const groups = await screen.findAllByRole('heading', { level: 2 });
    expect(groups.map((group) => group.textContent)).toEqual([
      i18n.t('guides.group.S'),
      i18n.t('guides.group.H'),
      i18n.t('guides.group.A'),
      i18n.t('guides.group.C'),
    ]);
    expect(screen.getByText(i18n.t('guide.start.title'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('guide.request.title'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('guide.delegate.title'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('guide.console.title'))).toBeNull();
  });

  it('names the length of each video and the screens it explains, each a link to that screen', async () => {
    serve({ request: 74 });
    open();
    const row = (await screen.findByText(i18n.t('guide.request.title'))).closest('li') as HTMLElement;
    expect(row).toHaveTextContent('1분 14초');
    const hrefs = within(row)
      .getAllByRole('link')
      .map((link) => link.getAttribute('href'));
    expect(hrefs).toEqual([
      '/attack/request',
      '/attack/console',
      '/normal/request',
      '/normal/console',
      '/insider/request',
      '/insider/console',
    ]);
  });

  it('marks a video watched to the end in this browser', async () => {
    window.localStorage.setItem('contexa.guide.watched', JSON.stringify(['request']));
    serve({ request: 74, start: 65 });
    open();
    const watched = (await screen.findByText(i18n.t('guide.request.title'))).closest('li') as HTMLElement;
    const other = screen.getByText(i18n.t('guide.start.title')).closest('li') as HTMLElement;
    expect(watched).toHaveTextContent(i18n.t('guides.watched'));
    expect(other).not.toHaveTextContent(i18n.t('guides.watched'));
  });

  it('opens a video in its window from its row, and the window is the same one the screens open', async () => {
    serve({ start: 65 });
    open();
    const row = (await screen.findByText(i18n.t('guide.start.title'))).closest('li') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: new RegExp(i18n.t('guides.play')) }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.querySelector('video')).toHaveAttribute('src', '/guides/start.webm');
    expect(dialog).toHaveTextContent(i18n.t('guide.start.title'));
  });

  it('lists only the videos recorded in the screen language', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url === '/guides/guides.json'
          ? new Response(
              JSON.stringify({
                start: { ko: recorded({ start: 65 }).start },
                request: { en: recorded({ request: 74 }).request },
              }),
              { status: 200 },
            )
          : new Response(null, { status: 404 }),
      ),
    );
    open();
    expect(await screen.findByText(i18n.t('guide.start.title'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('guide.request.title'))).toBeNull();
  });

  it('draws nothing for a video that no screen carries (the detail window is opened from its own screens)', async () => {
    serve({ detail: 90 });
    open();
    expect(await screen.findByText(i18n.t('guide.detail.title'))).toBeInTheDocument();
    const row = screen.getByText(i18n.t('guide.detail.title')).closest('li') as HTMLElement;
    expect(within(row).queryAllByRole('link')).toHaveLength(0);
  });
});
