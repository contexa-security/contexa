import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import hook from '../../test/fixtures/hook.test.json';
import stats from '../../test/fixtures/stats.test.json';
import { stubPortal, type PortalStub } from '../../test/portal';
import { Where } from '../../test/Where';
import { UxApp } from '../../UxApp';

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({
    get: { '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' }, '/api/hook': hook, '/api/stats': stats, ...extra },
  });
}

/** The whole application at an address, so the introduction is seen as a visitor meets it (without the menu). */
function open(address: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[address]}>
        <UxApp />
        <Where />
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

describe('the introduction (DEC-76)', () => {
  it('opens the demo with the wordmark, its value, what the demo does and the way in, without the menu', async () => {
    serve();
    open('/');
    expect(await screen.findByRole('heading', { level: 1, name: 'Contexa' })).toHaveTextContent('CONTEXA');
    expect(screen.getByText('인증을 통과한 요청도, 문맥으로 다시 판정합니다')).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: '주 메뉴' })).not.toBeInTheDocument();
    const pillars = screen.getByRole('region', { name: '이 데모에서 하는 일' });
    expect(within(pillars).getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent)).toEqual([
      '실행',
      '확인',
      '의미',
    ]);
    expect(screen.getByRole('link', { name: '데모 입장' })).toHaveAttribute('href', '/start');
    expect(screen.getByRole('link', { name: '표준 벤치마크 결과' })).toHaveAttribute('href', '/benchmarks');
    expect(await screen.findByText('지금까지 실제 판정 13,733건 · 판정 시간 중앙값 6.0초')).toBeInTheDocument();
  });

  it("draws the core value from the published recorded run: four existing controls allow, Contexa decides otherwise", async () => {
    serve();
    open('/');
    const figure = await screen.findByRole('figure', { name: '같은 요청, 다른 판정' });
    const lanes = within(figure).getByRole('list', { name: '5개 보안 통제의 판정' });
    expect(await within(lanes).findAllByText('허용')).toHaveLength(4);
    expect(within(lanes).getByText('추가 인증')).toBeInTheDocument();
    expect(within(figure).getByText('설계 자료 480건 대량 반출 요청')).toBeInTheDocument();
    expect(figure).toHaveTextContent(
      `공개 녹화 실행 ${hook.attacker.runId}(시나리오 S13)의 실제 결과입니다. 계정 · 권한이 유효하고 시각 · 건수가 규칙 안이라 기존 통제 4개는 모두 허용했습니다. Contexa의 판정은 추가 인증입니다`,
    );
  });

  it('says only how the controls differ, and leaves out the figures, when the records cannot be read (ST-88)', async () => {
    serve({ '/api/hook': 500, '/api/stats': 500 });
    open('/');
    const figure = await screen.findByRole('figure', { name: '같은 요청, 다른 판정' });
    expect(
      await within(figure).findByText(
        '같은 요청을 5개 보안 통제가 동시에 받습니다. 규칙은 미리 정한 조건만 보고, Contexa는 행위 기준선과 업무 컨텍스트를 함께 봅니다.',
      ),
    ).toBeInTheDocument();
    expect(within(figure).getAllByText('—')).toHaveLength(5);
    expect(screen.queryByText(/지금까지 실제 판정/)).not.toBeInTheDocument();
  });

  it('enters the start of the demo, where the menu is', async () => {
    serve();
    open('/');
    await userEvent.click(await screen.findByRole('link', { name: '데모 입장' }));
    expect(screen.getByTestId('where')).toHaveTextContent('/start');
    expect(await screen.findByRole('navigation', { name: '주 메뉴' })).toBeInTheDocument();
  });
});
