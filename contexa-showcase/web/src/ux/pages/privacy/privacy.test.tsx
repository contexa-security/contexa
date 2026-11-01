import { screen, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import watchedSource from '../../../components/guide/guideWatched.ts?raw';
import languageSource from '../../../i18n/index.ts?raw';
import i18n from '../../../i18n';
import agentSource from '../../simulate/agent.ts?raw';
import { renderAt, stubPortal } from '../../test/portal';
import { THEME_STORAGE_KEY } from '../../theme';
import PrivacyPage from './PrivacyPage';

function open() {
  stubPortal({ get: {} });
  return renderAt(
    '/privacy',
    <Routes>
      <Route path="/privacy" element={<PrivacyPage />} />
    </Routes>,
  );
}

function rowsOf(name: string): HTMLElement[] {
  return within(screen.getByRole('table', { name })).getAllByRole('row').slice(1);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the privacy policy', () => {
  it('lists what is processed with how long the portal keeps it (DEC-70)', async () => {
    open();
    expect(await screen.findByRole('heading', { level: 1, name: '개인정보 처리방침' })).toBeInTheDocument();
    const data = rowsOf('처리하는 정보');
    expect(data).toHaveLength(5);
    expect(data[0]).toHaveTextContent('마지막 방문 뒤 30일');
    expect(data[2]).toHaveTextContent('396일. AI에게 보낸 글의 원래 기록은 90일.');
    expect(data[3]).toHaveTextContent('7일');
    expect(data[4]).toHaveTextContent('주소 자체는 저장하지 않음');
    expect(screen.getByText('보관 기간이 지난 정보는 매일 03:30(세계 표준시) 자동으로 지웁니다.')).toBeInTheDocument();
    expect(screen.getByText(/서버는 확인 요청에 접속 주소를 함께 보냅니다/)).toBeInTheDocument();
  });

  it('names the two cookies and the browser storage exactly as the code sets them', async () => {
    open();
    const cookies = await screen.findByRole('table', { name: '쿠키' });
    const names = within(cookies).getAllByRole('row').slice(1).map((row) => row.querySelector('code')?.textContent);
    expect(names).toEqual(['SC_VISITOR', 'XSRF-TOKEN']);
    expect(rowsOf('쿠키')[0]).toHaveTextContent('처음 받은 뒤 30일');
    expect(rowsOf('쿠키')[1]).toHaveTextContent('브라우저를 닫을 때까지');
    const storage = rowsOf('브라우저 저장소').map((row) => row.querySelector('code')?.textContent);
    expect(storage).toEqual([
      THEME_STORAGE_KEY,
      /STORAGE_KEY = '([^']+)'/.exec(languageSource)?.[1],
      /const KEY = '([^']+)'/.exec(watchedSource)?.[1],
      `${/const CALL_KEY = '([^']+)'/.exec(agentSource)?.[1] ?? ''}*`,
    ]);
    expect(rowsOf('브라우저 저장소')[3]).toHaveTextContent('세션 저장소 · 탭을 닫을 때까지');
  });

  it('drops what the current screens no longer do and says what the earlier screens left (DEC-70)', async () => {
    open();
    const main = await screen.findByRole('heading', { level: 1, name: '개인정보 처리방침' });
    const page = main.ownerDocument.body;
    expect(page).not.toHaveTextContent('날짜별 건수로만 셉니다');
    expect(page).not.toHaveTextContent('판단 평가');
    expect(page).not.toHaveTextContent('이제 없습니다');
    expect(page).toHaveTextContent('지금 화면이 보내지 않습니다');
  });

  it('reads the same in English', async () => {
    await i18n.changeLanguage('en');
    open();
    expect(await screen.findByRole('heading', { level: 1, name: 'Privacy policy' })).toBeInTheDocument();
    expect(rowsOf('Information processed')).toHaveLength(5);
    expect(rowsOf('Cookies')).toHaveLength(2);
    expect(rowsOf('Browser storage')).toHaveLength(4);
  });
});
