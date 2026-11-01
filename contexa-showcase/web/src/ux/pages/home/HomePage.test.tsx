import { screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import anatomy from '../../test/fixtures/anatomy-attacker.test.json';
import hook from '../../test/fixtures/hook.test.json';
import labOptions from '../../test/fixtures/lab-options.test.json';
import liveConfig from '../../test/fixtures/live-config.test.json';
import received from '../../test/fixtures/received-attacker.test.json';
import stats from '../../test/fixtures/stats.test.json';
import bundle from '../../../../public/data/benchmarks/bundle-v1.json';
import { BUNDLE_PATH, shareText, type Bundle } from '../../bench/bundle';
import { renderAt, stubPortal } from '../../test/portal';
import HomePage from './HomePage';

/** The portal's real answers of 2026-10-31 (src/ux/test/fixtures, captured by ux_fixtures.py). */
const PORTAL = {
  '/api/hook': hook,
  '/api/stats': stats,
  '/api/live/config': liveConfig,
  '/api/lab/options': labOptions,
  '/api/runs/run-63b23f7bb5b2/steps/1/anatomy': anatomy,
  '/api/runs/run-63b23f7bb5b2/steps/1/received': received,
  [BUNDLE_PATH]: bundle,
};

const BUNDLE = bundle as unknown as Bundle;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the start of the demo', () => {
  it('runs the account takeover in one click and states the latency and the daily runs from the portal', async () => {
    stubPortal({ get: PORTAL });
    renderAt('/', <HomePage />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      '같은 계정 · 같은 시각 · 같은 요청,그중 하나는 탈취된 계정입니다',
    );
    expect(screen.getByRole('link', { name: '계정 탈취 시나리오 실행' })).toHaveAttribute(
      'href',
      '/simulate/person/S13/review',
    );
    expect(await screen.findByText('실제 AI 판정 · p50 6.0초')).toBeInTheDocument();
    expect(await screen.findByText('방문자당 하루 100회')).toBeInTheDocument();
  });

  it('draws the published recorded run from the operator-designated run, every number from its record', async () => {
    stubPortal({ get: PORTAL });
    renderAt('/', <HomePage />);
    // The card is a named region while it loads too; it is the one that holds the run once the record is in.
    const card = (await screen.findByText('run-63b23f7bb5b2')).closest('section') as HTMLElement;
    expect(card).toHaveAccessibleName('공개 녹화 실행');
    expect(await within(card).findByText('/api/projects/HX-310/exports')).toBeInTheDocument();
    expect(within(card).getByText('POST')).toBeInTheDocument();
    expect(
      await within(card).findByText(
        '480건 반출 · 엔지니어 K 계정 · Safari 18 · macOS (기준선 이탈) · 수요일 14:20',
      ),
    ).toBeInTheDocument();
    const rows = within(within(card).getByRole('table')).getAllByRole('row').slice(1);
    expect(rows.map((row) => row.textContent)).toEqual([
      '웹 방화벽(WAF)허용480건0.050초',
      '인증 · 권한(IAM)허용480건0.029초',
      '임계값 규칙허용480건0.044초',
      '승인 정책 규칙허용480건0.058초',
      'Contexa추가 인증0건8.7초',
    ]);
    expect(within(card).getByText('기존 보안 통제 4개 · 반출').nextElementSibling).toHaveTextContent(
      '480건 × 4',
    );
    expect(within(card).getByText('Contexa · 반출').nextElementSibling).toHaveTextContent('0건');
    expect(within(card).getByText('같은 측정 1회 중 1회가 이 실행과 같은 결과')).toBeInTheDocument();
  });

  it('says when no recorded run is designated, instead of a blank card', async () => {
    stubPortal({ get: { ...PORTAL, '/api/hook': 404 } });
    renderAt('/', <HomePage />);
    expect(await screen.findByText('공개 녹화 실행이 아직 지정되지 않았습니다.')).toBeInTheDocument();
  });

  it('lists the four threat scenarios with their sizes from the portal', async () => {
    stubPortal({ get: PORTAL });
    renderAt('/', <HomePage />);
    const section = screen.getByRole('region', { name: '위협 시나리오' });
    const cards = within(section).getAllByRole('article');
    expect(cards.map((card) => within(card).getByRole('heading').textContent)).toEqual([
      '계정 탈취(ATO)',
      '내부자 위협',
      'AI 에이전트 위임 남용',
      '요청 급증 대응',
    ]);
    expect(await within(section).findByText('요청 1건 · 대조군 1건')).toBeInTheDocument();
    expect(within(section).getByText('요청 3건')).toBeInTheDocument();
    expect(within(section).getByText('시나리오 5종')).toBeInTheDocument();
    expect(within(section).getByText('실시간 최대 10건 · 측정 60건 동시')).toBeInTheDocument();
    expect(within(section).getByRole('link', { name: '내부자 위협 실행' })).toHaveAttribute(
      'href',
      '/simulate/person/S16/review',
    );
  });

  it("heads the standard benchmarks with the bundle's headline tests, their conditions and what they cost (DEC-58)", async () => {
    stubPortal({ get: PORTAL });
    renderAt('/', <HomePage />);
    const band = await screen.findByRole('region', { name: '표준 벤치마크' });
    for (const headline of BUNDLE.headline) {
      const found = BUNDLE.benchmarks
        .find((bench) => bench.id === headline.benchmark)
        ?.tests.find((test) => test.id === headline.test);
      const digits = headline.benchmark === 'agentdojo' ? 2 : 1;
      expect(found?.protected && found.unprotected).toBeTruthy();
      if (found?.protected && found.unprotected) {
        expect(band).toHaveTextContent(shareText(found.unprotected, 'ko', digits).value);
        expect(band).toHaveTextContent(shareText(found.protected, 'ko', digits).value);
        expect(band).toHaveTextContent(found.label.ko);
      }
    }
    expect(band).toHaveTextContent(`피해 에이전트 하나(${BUNDLE.program.models.victimBase})`);
    expect(within(band).getByRole('link', { name: '전체 결과' })).toHaveAttribute('href', '/benchmarks');
  });

  it('keeps a line and the way to the results when the bundle cannot be read (ST-67)', async () => {
    stubPortal({ get: { ...PORTAL, [BUNDLE_PATH]: 500 } });
    renderAt('/', <HomePage />);
    expect(await screen.findByText('표준 벤치마크 결과를 불러오지 못했습니다.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '전체 결과' })).toHaveAttribute('href', '/benchmarks');
  });
});
