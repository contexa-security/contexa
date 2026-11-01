import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import benchmark from '../../test/fixtures/benchmark.test.json';
import hook from '../../test/fixtures/hook.test.json';
import labOptions from '../../test/fixtures/lab-options.test.json';
import liveConfig from '../../test/fixtures/live-config.test.json';
import receivedAttacker from '../../test/fixtures/received-attacker.test.json';
import receivedOwner from '../../test/fixtures/received-owner.test.json';
import scoreAttacker from '../../test/fixtures/score-attacker.test.json';
import scoreOwner from '../../test/fixtures/score-owner.test.json';
import settings from '../../test/fixtures/settings.test.json';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import ComparePage from './ComparePage';

const ATTACKER = hook.attacker.runId;
const OWNER = hook.owner.runId;

const BASE: Record<string, unknown> = {
  '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 0, step: 'start', differences: [], predictions: {} },
    runs: [],
    predictions: [],
  },
  '/api/live/config': liveConfig,
  '/api/lab/options': labOptions,
  '/api/hook': hook,
  '/api/settings': settings,
  '/api/benchmark': benchmark,
  '/api/lab/runs/recent': [],
  [`/api/runs/${ATTACKER}/score`]: scoreAttacker,
  [`/api/runs/${OWNER}/score`]: scoreOwner,
  [`/api/runs/${ATTACKER}/steps/1/received`]: receivedAttacker,
  [`/api/runs/${OWNER}/steps/1/received`]: receivedOwner,
};

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({ get: { ...BASE, ...extra } });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/compare" element={<ComparePage />} />
    </Routes>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('detection compared', () => {
  it('names the rule from the portal\'s settings and sets the two runs of the shared request side by side (ST-51)', async () => {
    serve();
    open('/compare');
    const threshold = settings.threshold;
    expect(
      await screen.findByText(
        `야간(${threshold.nightStart}~${threshold.nightEnd}) 대량 반출 · ${threshold.volumeLimit}건 초과 반출 · ${threshold.dormantWindowDays}일간 접근 없던 프로젝트 접근을 차단`,
      ),
    ).toBeInTheDocument();
    const table = screen.getByRole('table', { name: '임계값 규칙' });
    expect(within(table).getByRole('link', { name: ATTACKER })).toHaveAttribute('href', `/runs/${ATTACKER}`);
    expect(within(table).getAllByText(/공개 녹화/)).toHaveLength(2);
    expect(await screen.findByText('규칙은 두 요청을 구분하지 못합니다')).toBeInTheDocument();
  });

  it('turns the rule off to show sign-in alone, and leads a change to the policy simulator\'s composition', async () => {
    serve();
    open('/compare');
    await userEvent.click(await screen.findByRole('switch', { name: '규칙 켬' }));
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('rule=off'));
    expect(screen.getByRole('columnheader', { name: '인증 · 권한만' })).toBeInTheDocument();
    const items = Math.min(...labOptions.items);
    expect(screen.getByRole('link', { name: `반출 건수를 ${items}건으로 줄여 보내기` })).toHaveAttribute(
      'href',
      `/simulate/policy?tab=compose&case=S13&field=items&to=${items}`,
    );
  });

  it('says when the visitor has composed no run yet (ST-52)', async () => {
    serve();
    open('/compare?tab=change');
    expect(await screen.findByText('아직 조건을 바꿔 보낸 실행이 없습니다.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '조건을 바꿔 실행하기' })).toHaveAttribute('href', '/simulate/policy?tab=compose');
  });

  it('draws every measured run as a dot that opens its details, and says a failed read (ST-53)', async () => {
    serve();
    const first = open('/compare?tab=runs');
    const contexaAttacks = await screen.findByRole('list', { name: 'Contexa · 위협' });
    const expected = benchmark.cases
      .filter((found) => found.classification === 'THREAT')
      .flatMap((found) => Object.values(found.runResults ?? {}).filter((results) => results.D)).length;
    expect(within(contexaAttacks).getAllByRole('link')).toHaveLength(expected);
    expect(within(contexaAttacks).getAllByRole('link')[0]).toHaveAttribute('href', expect.stringMatching(/^\/runs\/run-/));
    first.unmount();
    serve({ '/api/benchmark': 500 });
    open('/compare?tab=runs');
    expect(await screen.findByText('측정 결과를 불러오지 못했습니다.')).toBeInTheDocument();
  });
});
