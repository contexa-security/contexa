import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import manifest from '../../../../public/guides/guides.json';
import i18n from '../../../i18n';
import { renderAt, stubPortal } from '../../test/portal';
import TourPage from './TourPage';
import { clock } from './tour';

const MANIFEST = '/guides/guides.json';

function open(address: string, answer: unknown = manifest) {
  stubPortal({ get: { [MANIFEST]: answer } });
  return renderAt(
    address,
    <Routes>
      <Route path="/tour" element={<TourPage />} />
    </Routes>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  try {
    window.localStorage.clear();
  } catch {
    // A test browser without storage keeps no mark.
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the product tour', () => {
  it('writes a time as a player does', () => {
    expect(clock(1.628)).toBe('0:01');
    expect(clock(70.1)).toBe('1:10');
    expect(clock(600)).toBe('10:00');
  });

  it('lists the recorded videos with their length and date, marking those recorded on the earlier screens (DEC-68)', async () => {
    open('/tour');
    const list = await screen.findByRole('region', { name: '영상 목록' });
    const items = within(list).getAllByRole('link');
    expect(items).toHaveLength(Object.keys(manifest).length);
    expect(items[0]).toHaveTextContent('실시간 판정 화면 읽는 법');
    expect(items[0]).toHaveTextContent('1분 10초');
    expect(items[0]).toHaveTextContent('녹화 2026-10-21 세계 표준시');
    expect(items[0]).toHaveTextContent('개편 전 화면');
    expect(items[0]).toHaveAttribute('aria-current', 'true');
    expect(items[1]).toHaveTextContent('업무 에이전트에게 업무를 맡기는 법');
    expect(items[1]).toHaveTextContent('1분 7초');
    expect(screen.getByText(/지금 영상은 개편 전 화면으로 녹화했습니다/)).toBeInTheDocument();
  });

  it('plays nothing by itself, puts the screen language captions first and jumps to a scene', async () => {
    const { container } = open('/tour');
    const video = await screen.findByLabelText('실시간 판정 화면 읽는 법 영상');
    expect(video).toHaveAttribute('src', '/guides/console.webm');
    expect(video).toHaveAttribute('preload', 'metadata');
    expect(video).not.toHaveAttribute('autoplay');
    const tracks = [...container.querySelectorAll('track')];
    expect(tracks.map((track) => [track.getAttribute('src'), track.getAttribute('srclang')])).toEqual([
      ['/guides/console.ko.vtt', 'ko'],
      ['/guides/console.en.vtt', 'en'],
    ]);
    expect(tracks[0]).toHaveAttribute('default');
    const scenes = screen.getByRole('region', { name: '장면' });
    const buttons = within(scenes).getAllByRole('button');
    expect(buttons).toHaveLength(manifest.console.scenes.length);
    expect(buttons[1]).toHaveAccessibleName(/^0:13부터 보기 · 같은 요청이 5개 보안 통제에 동시에 도착합니다/);
    fireEvent.click(buttons[3] as HTMLElement);
    expect(buttons[3]).toHaveAttribute('aria-current', 'true');
  });

  it('opens a chosen video, the first for one it does not know, and marks a video watched to the end (ST-85)', async () => {
    const first = open('/tour?video=agent');
    const video = await screen.findByLabelText('업무 에이전트에게 업무를 맡기는 법 영상');
    fireEvent.ended(video);
    await waitFor(() => expect(screen.getAllByText('끝까지 봄')).toHaveLength(1));
    first.unmount();
    vi.unstubAllGlobals();
    open('/tour?video=nothing');
    expect(await screen.findByLabelText('실시간 판정 화면 읽는 법 영상')).toBeInTheDocument();
  });

  it('gives a phone the shorter caption lines', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('width < 768px') || query.includes('width < 1024px'),
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }));
    const { container } = open('/tour');
    await screen.findByLabelText('실시간 판정 화면 읽는 법 영상');
    expect([...container.querySelectorAll('track')].map((track) => track.getAttribute('src'))).toEqual([
      '/guides/console.ko.m.vtt',
      '/guides/console.en.m.vtt',
    ]);
  });

  it('says there is no video when the manifest is missing or holds none in the language, and an error otherwise (ST-83, ST-84)', async () => {
    const missing = open('/tour', 404);
    expect(await screen.findByText('아직 녹화한 영상이 없습니다.')).toBeInTheDocument();
    missing.unmount();
    vi.unstubAllGlobals();
    const english = open('/tour', { console: { en: manifest.console } });
    expect(await screen.findByText('아직 녹화한 영상이 없습니다.')).toBeInTheDocument();
    english.unmount();
    vi.unstubAllGlobals();
    open('/tour', 500);
    expect(await screen.findByText('불러오기 실패')).toBeInTheDocument();
  });
});
