import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { GuidePreview } from './GuidePreview';
import scripts from './guides.json';

/** The manifest the recording script writes next to the video (가이드영상-계획.md 5절). */
const MANIFEST = {
  console: {
    file: 'console.webm',
    captions: { ko: 'console.ko.vtt', en: 'console.en.vtt' },
    durationSec: 90.4,
    recordedAt: '2026-10-21T03:10:00Z',
    screens: 'v4',
  },
};

function serve(manifest: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url === '/guides/guides.json' && manifest !== null
        ? new Response(JSON.stringify(manifest), { status: 200 })
        : new Response(null, { status: 404 }),
    ),
  );
}

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <GuidePreview id="console" />
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// The guide videos (가이드영상-계획.md): an optional preview at the entrance of a feature, never played on its own.
describe('the guide preview', () => {
  it('draws nothing while no video of the guide was recorded', async () => {
    serve(null);
    const { container } = open();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container).toBeEmptyDOMElement();
  });

  it('names its length on the button from the recorded video and plays nothing until pressed', async () => {
    serve(MANIFEST);
    open();
    const button = await screen.findByRole('button', { name: '미리 보기 · 1분 30초' });
    expect(button).toHaveAttribute('aria-haspopup', 'dialog');
    expect(document.querySelector('video')).toBeNull();
  });

  it('opens the video with both caption tracks, the screen language first, and the transcript beside it', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리 보기/ }));
    const dialog = screen.getByRole('dialog');
    const video = dialog.querySelector('video');
    expect(video).toHaveAttribute('src', '/guides/console.webm');
    expect(video).not.toHaveAttribute('autoplay');
    const tracks = [...dialog.querySelectorAll('track')];
    expect(tracks.map((track) => [track.getAttribute('srclang'), track.getAttribute('src')])).toEqual([
      ['ko', '/guides/console.ko.vtt'],
      ['en', '/guides/console.en.vtt'],
    ]);
    expect(tracks[0]).toHaveAttribute('default');
    expect(tracks[1]).not.toHaveAttribute('default');
    const lines = within(dialog).getAllByRole('listitem');
    expect(lines.map((line) => line.textContent)).toEqual(scripts.console.scenes.map((key) => i18n.t(key)));
    expect(dialog).toHaveTextContent('2026-10-21');
  });

  it('closes with its button and gives the focus back to the preview button', async () => {
    serve(MANIFEST);
    open();
    const button = await screen.findByRole('button', { name: /미리 보기/ });
    button.focus();
    fireEvent.click(button);
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: i18n.t('modal.close') }));
    expect(document.querySelector('video')).toBeNull();
    expect(button).toHaveFocus();
  });

  it('speaks the screen language: English length and English captions first', async () => {
    await i18n.changeLanguage('en');
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: 'Preview · 1 min 30 s' }));
    const tracks = [...screen.getByRole('dialog').querySelectorAll('track')];
    expect(tracks.find((track) => track.hasAttribute('default'))).toHaveAttribute('srclang', 'en');
  });

  it('has every scene line, the title and the track names in both dictionaries', () => {
    const keys = Object.values(scripts).flatMap((script) => [script.title, ...script.scenes]);
    for (const dictionary of [ko, en] as readonly Record<string, string>[]) {
      for (const key of [
        ...keys,
        'guide.preview',
        'guide.transcript',
        'guide.recorded',
        'guide.track.ko',
        'guide.track.en',
      ]) {
        expect(dictionary[key], key).toBeTruthy();
      }
    }
  });
});
