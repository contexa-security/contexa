import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import type { StatsView } from '../../../api/types';
import benchmark from '../../test/fixtures/benchmark-full.test.json';
import settings from '../../test/fixtures/settings.test.json';
import stats from '../../test/fixtures/stats.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import AdoptPage from './AdoptPage';
import { CODE, LINKS, tabOf } from './adopt';

const STATS = stats as unknown as StatsView;

function serve(extra: PortalStub['get'] = {}) {
  stubPortal({
    get: { '/api/stats': STATS, '/api/settings': settings, '/api/benchmark': benchmark, ...extra },
  });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/adopt" element={<AdoptPage />} />
    </Routes>,
  );
}

function card(name: string | RegExp): HTMLElement {
  return screen.getByRole('region', { name });
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('deployment and integration', () => {
  it('opens an old step link at the tab that holds that step, and an unknown tab at the steps (ST-81, ST-82)', () => {
    expect(tabOf(new URLSearchParams('step=attach'))).toBe('steps');
    expect(tabOf(new URLSearchParams('step=on'))).toBe('shadow');
    expect(tabOf(new URLSearchParams('tab=retention&step=on'))).toBe('retention');
    expect(tabOf(new URLSearchParams('tab=nothing'))).toBe('steps');
    expect(tabOf(new URLSearchParams(''))).toBe('steps');
  });

  it("sets the three steps with the release's own code, marks the code in the sentences and copies a block", async () => {
    serve();
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    open('/adopt');
    const steps = await screen.findByRole('list', { name: '연동 3단계' });
    expect(within(steps).getAllByRole('listitem')).toHaveLength(3);
    const dependency = screen.getByRole('region', { name: '의존성 코드' });
    expect(dependency).toHaveTextContent('implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"');
    const annotations = screen.getByRole('region', { name: '어노테이션 코드' });
    expect(annotations).toHaveTextContent('@EnableAISecurity');
    expect(annotations).toHaveTextContent('@Protectable(sync = true)');
    expect(screen.getByText('sync = true').tagName).toBe('CODE');
    fireEvent.click(screen.getByRole('button', { name: '어노테이션 코드 복사' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(CODE.annotations));
    expect(await screen.findByText('복사했습니다')).toBeInTheDocument();
  });

  it('says a copy that failed and leaves the code to be selected by hand (ST-80)', async () => {
    serve();
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText: () => Promise.reject(new Error('denied')) } });
    open('/adopt');
    fireEvent.click(await screen.findByRole('button', { name: '의존성 코드 복사' }));
    expect(await screen.findByText('복사하지 못했습니다. 코드를 직접 선택해 복사할 수 있습니다.')).toBeInTheDocument();
  });

  it("writes the employee's counts from the scenario validation, and only the sentence without it (ST-79)", async () => {
    serve();
    const shown = open('/adopt');
    const roles = await screen.findByRole('region', { name: '역할별 도입 효과' });
    await waitFor(() =>
      expect(roles).toHaveTextContent(
        '시나리오 검증의 정상 업무 19회 가운데 업무가 멈춘 것 0회, 추가 인증을 거쳐 처리된 것 3회',
      ),
    );
    shown.unmount();
    vi.unstubAllGlobals();
    serve({ '/api/benchmark': 404 });
    open('/adopt');
    const without = await screen.findByRole('region', { name: '역할별 도입 효과' });
    expect(without).toHaveTextContent('의심될 때만 추가 인증을 받습니다.');
    expect(without).not.toHaveTextContent('시나리오 검증의 정상 업무');
  });

  it("sets shadow mode with this demo's decisions and its mode now, and hides what it cannot read (ST-74, ST-78)", async () => {
    serve();
    const shown = open('/adopt?step=on');
    const record = await screen.findByRole('region', { name: '이 데모를 관찰 모드로 두었다면' });
    expect(record).toHaveTextContent('13,733건');
    expect(record).toHaveTextContent('차단517건');
    expect(record).toHaveTextContent('추가 인증2,148건');
    expect(record).toHaveTextContent('검토 보류1,136건');
    expect(record).toHaveTextContent('6.0초');
    expect(record).toHaveTextContent('(2026-10-04 ~ 2026-10-31, 세계 표준시)');
    expect(await screen.findByText(/적용 모드로 돌아갑니다/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: '적용 모드 설정' })).toHaveTextContent('mode: ENFORCE');
    shown.unmount();
    vi.unstubAllGlobals();
    serve({
      '/api/settings': 404,
      '/api/stats': { ...STATS, engineActions: { ALLOW: 0, CHALLENGE: 0, BLOCK: 0, ESCALATE: 0 }, engineDecisions: 0 },
    });
    open('/adopt?tab=shadow');
    expect(await screen.findByRole('region', { name: '관찰 모드 설정' })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('region', { name: '이 데모를 관찰 모드로 두었다면' })).not.toBeInTheDocument());
    expect(screen.queryByText(/로 돌아갑니다/)).not.toBeInTheDocument();
  });

  it("lists the starter's six defaults beside this demo's published settings (DEC-66, DEC-67)", async () => {
    serve();
    const shown = open('/adopt?tab=retention');
    const table = await screen.findByRole('table', { name: '보관 · 감사 기본값' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(6);
    await waitFor(() => expect(rows[0]).toHaveTextContent('요청의 100%'));
    expect(rows[0]).toHaveTextContent('판정 증거 봉인 표본요청의 1%contexa.pqa.oss.sealed-evidence.sample-percent');
    expect(rows[1]).toHaveTextContent('변경 직후 전수 봉인1,000건');
    expect(rows[1]).toHaveTextContent('응답에 없음');
    expect(rows[2]).toHaveTextContent('봉인 보관90일');
    expect(rows[3]).toHaveTextContent('검사 이상 없는 봉인 보관30일');
    expect(rows[3]).toHaveTextContent('90일');
    expect(rows[4]).toHaveTextContent('행위 기준선 보관마지막 학습 후 30일');
    expect(rows[5]).toHaveTextContent('행동 기록 보관90일');
    expect(rows[5]).toHaveTextContent('400일');
    expect(screen.getByText(/AI에게 보낸 글의 원래 기록은 이 데모 포털이 90일 보관합니다/)).toBeInTheDocument();
    const seal = card('봉인과 검사');
    expect(seal).toHaveTextContent('고칠 수 없게');
    expect(seal).not.toHaveTextContent(/판단 입력|보존/);
    shown.unmount();
    vi.unstubAllGlobals();
    serve({ '/api/settings': 503 });
    open('/adopt?tab=retention');
    const unread = await screen.findByRole('table', { name: '보관 · 감사 기본값' });
    await waitFor(() => expect(within(unread).getAllByText('읽지 못함')).toHaveLength(6));
  });

  it('links the examples, the repository and the docs in a new tab', async () => {
    serve();
    open('/adopt?tab=integration');
    const links = await screen.findByRole('group', { name: '예제와 문서' });
    const hrefs = within(links)
      .getAllByRole('link')
      .map((link) => [link.getAttribute('href'), link.getAttribute('target')]);
    expect(hrefs).toEqual([
      [LINKS.legacy, '_blank'],
      [LINKS.quickstart, '_blank'],
      [LINKS.repository, '_blank'],
      [LINKS.docs, '_blank'],
    ]);
  });

  it('opens every tab', async () => {
    for (const tab of ['steps', 'shadow', 'retention', 'integration']) {
      serve();
      const shown = open(`/adopt?tab=${tab}`);
      expect(await screen.findByRole('heading', { level: 1, name: '도입 · 연동 가이드' }), tab).toBeInTheDocument();
      expect(screen.getByRole('tabpanel'), tab).toBeInTheDocument();
      shown.unmount();
      vi.unstubAllGlobals();
    }
  });
});
