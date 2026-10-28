import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { GuidePreview } from './GuidePreview';
import { guideEntry } from './guideConfig';

/** The manifest the recording script writes next to the video (가이드영상-제작기획안.md 7.1절). */
const MANIFEST = {
  console: {
    file: 'console.webm',
    captions: { ko: 'console.ko.vtt', en: 'console.en.vtt' },
    captionsNarrow: { ko: 'console.ko.m.vtt', en: 'console.en.m.vtt' },
    durationSec: 90.4,
    recordedAt: '2026-10-21T03:10:00Z',
    screens: 'v4',
    scenes: [
      { key: 'guide.console.request', start: 1.6 },
      { key: 'guide.console.arrive', start: 13.7 },
      { key: 'guide.console.hold', start: 20.4 },
      { key: 'guide.console.bars', start: 34.4 },
      { key: 'guide.console.log', start: 47.6 },
      { key: 'guide.console.judgment', start: 58.3 },
    ],
  },
};

const WATCHED = 'contexa.guide.watched';

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

/** The browser's caption tracks of a video, which jsdom does not have: one showing track with the cue on the screen. */
function giveTracks(video: HTMLVideoElement, cue: string | null, mode: 'showing' | 'hidden' = 'showing') {
  const track = {
    kind: 'captions',
    language: 'ko',
    mode,
    activeCues: cue === null ? [] : [{ text: cue }],
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  };
  Object.defineProperty(video, 'textTracks', {
    configurable: true,
    value: { length: 1, 0: track, addEventListener: () => undefined, removeEventListener: () => undefined },
  });
}

function matchPhone(matches: boolean) {
  vi.stubGlobal(
    'matchMedia',
    (query: string) => ({
      matches: matches && query.includes('40rem'),
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  window.localStorage.removeItem(WATCHED);
});

afterEach(() => {
  vi.unstubAllGlobals();
  Object.defineProperty(document, 'fullscreenEnabled', { configurable: true, value: false });
});

// The guide videos (가이드영상-제작기획안.md 4·6절): an optional preview at a screen, never played on its own.
describe('the guide link', () => {
  it('draws nothing while no video of the guide was recorded', async () => {
    serve(null);
    const { container } = open();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container).toBeEmptyDOMElement();
  });

  it('names its length from the recorded video, is marked as a guide link and plays nothing until pressed', async () => {
    serve(MANIFEST);
    open();
    const button = await screen.findByRole('button', { name: '미리보기 영상 · 1분 30초' });
    expect(button).toHaveAttribute('aria-haspopup', 'dialog');
    expect(button).toHaveAttribute('data-guide-link');
    expect(document.querySelector('video')).toBeNull();
  });

  it('turns into "watch again" once the video ended, and remembers it in this browser only', async () => {
    serve(MANIFEST);
    const first = open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const video = screen.getByRole('dialog').querySelector('video') as HTMLVideoElement;
    fireEvent.ended(video);
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: i18n.t('modal.close') }));
    expect(await screen.findByRole('button', { name: '다시 보기 · 1분 30초' })).toBeInTheDocument();
    expect(JSON.parse(window.localStorage.getItem(WATCHED) ?? '[]')).toEqual(['console']);
    first.unmount();
    open();
    expect(await screen.findByRole('button', { name: '다시 보기 · 1분 30초' })).toBeInTheDocument();
  });

  it('keeps a video unmarked when the browser refuses to store the mark', async () => {
    serve(MANIFEST);
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    expect(() => fireEvent.ended(screen.getByRole('dialog').querySelector('video') as HTMLVideoElement)).not.toThrow();
    vi.restoreAllMocks();
  });

  it('speaks the screen language: English length and English captions first', async () => {
    await i18n.changeLanguage('en');
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: 'Preview video · 1 min 30 s' }));
    const tracks = [...screen.getByRole('dialog').querySelectorAll('track')];
    expect(tracks.find((track) => track.hasAttribute('default'))).toHaveAttribute('srclang', 'en');
  });
});

// 가이드영상-제작기획안.md 7.2절 (D-1): the screen's words are in the video, so each language has its own recording.
describe('a guide recorded per language', () => {
  const PER_LANGUAGE = {
    console: {
      ko: { ...MANIFEST.console, file: 'console.ko.webm', captions: { ko: 'console.ko.vtt' }, durationSec: 70 },
      en: { ...MANIFEST.console, file: 'console.en.webm', captions: { en: 'console.en.vtt' }, durationSec: 80 },
    },
  };

  it('plays the recording of the screen language, with its own length and its own captions', async () => {
    serve(PER_LANGUAGE);
    open();
    fireEvent.click(await screen.findByRole('button', { name: '미리보기 영상 · 1분 10초' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.querySelector('video')).toHaveAttribute('src', '/guides/console.ko.webm');
    expect([...dialog.querySelectorAll('track')].map((track) => track.getAttribute('srclang'))).toEqual(['ko']);
  });

  it('plays the English recording on an English screen', async () => {
    await i18n.changeLanguage('en');
    serve(PER_LANGUAGE);
    open();
    fireEvent.click(await screen.findByRole('button', { name: 'Preview video · 1 min 20 s' }));
    expect(screen.getByRole('dialog').querySelector('video')).toHaveAttribute('src', '/guides/console.en.webm');
  });

  it('draws no link where the screen language has no recording: the video would show the other language', async () => {
    serve({ console: { en: PER_LANGUAGE.console.en } });
    const { container } = open();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(container).toBeEmptyDOMElement();
  });
});

describe('the guide window', () => {
  it('opens the video with both caption tracks, the screen language first, and no native full screen', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const dialog = screen.getByRole('dialog');
    const video = dialog.querySelector('video');
    expect(video).toHaveAttribute('src', '/guides/console.webm');
    expect(video).not.toHaveAttribute('autoplay');
    expect(video).toHaveAttribute('controlslist', 'nofullscreen');
    const tracks = [...dialog.querySelectorAll('track')];
    expect(tracks.map((track) => [track.getAttribute('srclang'), track.getAttribute('src')])).toEqual([
      ['ko', '/guides/console.ko.vtt'],
      ['en', '/guides/console.en.vtt'],
    ]);
    expect(tracks[0]).toHaveAttribute('default');
    expect(tracks[1]).not.toHaveAttribute('default');
    expect(dialog).toHaveTextContent('2026-10-21');
  });

  it('lists the scene lines as the transcript and jumps to a scene when its line is pressed', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const dialog = screen.getByRole('dialog');
    const lines = within(dialog).getAllByRole('listitem');
    expect(lines.map((line) => line.textContent)).toEqual(guideEntry('console').scenes.map((key) => i18n.t(key)));
    const video = dialog.querySelector('video') as HTMLVideoElement;
    fireEvent.click(within(lines[3] as HTMLElement).getByRole('button'));
    expect(video.currentTime).toBeCloseTo(34.4, 1);
  });

  it('draws one thin bar segment per scene and marks the scene being played', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const dialog = screen.getByRole('dialog');
    const video = dialog.querySelector('video') as HTMLVideoElement;
    const segments = dialog.querySelectorAll('[data-scene]');
    expect(segments).toHaveLength(6);
    video.currentTime = 36;
    fireEvent.timeUpdate(video);
    expect(dialog.querySelector('[data-scene][data-now]')).toBe(segments[3]);
  });

  it('shows the caption on a band under the video, in one line, from the track the browser is showing', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const dialog = screen.getByRole('dialog');
    const video = dialog.querySelector('video') as HTMLVideoElement;
    const band = dialog.querySelector('[data-caption-band]') as HTMLElement;
    expect(video.compareDocumentPosition(band) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    giveTracks(video, '같은 요청이 다섯 보안에 동시에 도착합니다.');
    fireEvent.timeUpdate(video);
    expect(band).toHaveTextContent('같은 요청이 다섯 보안에 동시에 도착합니다.');
    giveTracks(video, null);
    fireEvent.timeUpdate(video);
    expect(band).toBeEmptyDOMElement();
  });

  it('draws no band caption when the visitor turned the captions off in the browser', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const video = screen.getByRole('dialog').querySelector('video') as HTMLVideoElement;
    giveTracks(video, '보이지 않아야 하는 줄', 'hidden');
    fireEvent.timeUpdate(video);
    expect(screen.getByRole('dialog').querySelector('[data-caption-band]')).toBeEmptyDOMElement();
  });

  it('uses the caption files cut for a phone when the window is a phone wide', async () => {
    matchPhone(true);
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    const tracks = [...screen.getByRole('dialog').querySelectorAll('track')];
    expect(tracks.map((track) => track.getAttribute('src'))).toEqual([
      '/guides/console.ko.m.vtt',
      '/guides/console.en.m.vtt',
    ]);
  });

  it('offers full screen for the video and its band together only where the browser can', async () => {
    serve(MANIFEST);
    open();
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상/ }));
    expect(within(screen.getByRole('dialog')).queryByRole('button', { name: i18n.t('guide.fullscreen') })).toBeNull();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: i18n.t('modal.close') }));
    Object.defineProperty(document, 'fullscreenEnabled', { configurable: true, value: true });
    fireEvent.click(await screen.findByRole('button', { name: /미리보기 영상|다시 보기/ }));
    const dialog = screen.getByRole('dialog');
    const player = dialog.querySelector('[data-player]') as HTMLElement;
    const request = vi.fn(async () => undefined);
    player.requestFullscreen = request;
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: i18n.t('guide.fullscreen') }));
    });
    expect(request).toHaveBeenCalledTimes(1);
    expect(player.contains(dialog.querySelector('[data-caption-band]'))).toBe(true);
  });

  it('closes with its button and gives the focus back to the link', async () => {
    serve(MANIFEST);
    open();
    const button = await screen.findByRole('button', { name: /미리보기 영상/ });
    button.focus();
    fireEvent.click(button);
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: i18n.t('modal.close') }));
    expect(document.querySelector('video')).toBeNull();
    expect(button).toHaveFocus();
  });

  it('has every title, scene line and word of the window in both dictionaries', () => {
    for (const dictionary of [ko, en] as readonly Record<string, string>[]) {
      for (const key of [
        'guide.preview',
        'guide.previewAgain',
        'guide.transcript',
        'guide.recorded',
        'guide.track.ko',
        'guide.track.en',
        'guide.fullscreen',
      ]) {
        expect(dictionary[key], key).toBeTruthy();
      }
    }
  });
});
