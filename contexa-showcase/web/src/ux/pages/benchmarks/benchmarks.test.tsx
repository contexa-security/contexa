import { screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import bundle from '../../../../public/data/benchmarks/bundle-v1.json';
import en from '../../../i18n/en.json';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { BUNDLE_PATH, shareText, type Bundle } from '../../bench/bundle';
import { renderAt, stubPortal, type PortalStub } from '../../test/portal';
import BenchmarksPage from './BenchmarksPage';

/** The real result bundle (written by contexa-benchmark/bench/publish_bundle.py from the pinned report files). */
const BUNDLE = bundle as unknown as Bundle;
/** The value, or a failed test naming what was missing. */
function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) {
    throw new Error(`missing ${what}`);
  }
  return value;
}
const test = (bench: string, id: string) =>
  must(
    BUNDLE.benchmarks.find((b) => b.id === bench)?.tests.find((t) => t.id === id),
    `${bench} ${id}`,
  );

function serve(extra: PortalStub['get'] = {}) {
  return stubPortal({
    get: { '/api/visitor': { predictions: {}, csrfHeader: 'X-XSRF-TOKEN' }, [BUNDLE_PATH]: BUNDLE, ...extra },
  });
}

function open(address: string) {
  return renderAt(
    address,
    <Routes>
      <Route path="/benchmarks" element={<BenchmarksPage />} />
      <Route path="/benchmarks/:bench" element={<BenchmarksPage />} />
    </Routes>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the standard benchmarks', () => {
  it("sets every test of the result matrix with the bundle's own values and the programme beside them (DEC-56)", async () => {
    serve();
    open('/benchmarks');
    const matrix = await screen.findByRole('table', { name: '결과 행렬' });
    const rows = BUNDLE.benchmarks.flatMap((bench) => bench.tests.filter((item) => item.matrix));
    for (const row of rows) {
      const name = row.label.ko;
      const line = within(matrix)
        .getByRole('rowheader', { name: new RegExp(name.replace(/[()]/g, '\\$&')) })
        .closest('tr');
      expect(line, name).not.toBeNull();
      const bench = BUNDLE.benchmarks.find((b) => b.tests.includes(row))?.id ?? '';
      const digits = bench === 'agentdojo' ? 2 : 1;
      expect(line).toHaveTextContent(shareText(must(row.protected, name), 'ko', digits).value);
    }
    const strip = screen.getByLabelText('측정 요약');
    expect(strip).toHaveTextContent(`${BUNDLE.freezes.length}판`);
    expect(strip).toHaveTextContent(`$${BUNDLE.program.spendUsd.toFixed(2)}`);
    const limits = screen.getByRole('region', { name: '한계 — 이 결과가 말하지 않는 것' });
    expect(within(limits).getAllByRole('listitem')).toHaveLength(BUNDLE.limits.length);
  });

  it('writes a share below 1% as the point and the 95% upper bound apart, and a value fixed by the sample without an interval (ST-71, ST-72)', async () => {
    serve();
    open('/benchmarks');
    const matrix = await screen.findByRole('table', { name: '결과 행렬' });
    const base = test('injecagent', 'S-2base');
    const row = within(matrix)
      .getByRole('rowheader', { name: /S-2 base/ })
      .closest('tr') as HTMLElement;
    expect(row).toHaveTextContent(`95% 상한 ${shareText(must(base.protected, 'S-2base'), 'ko', 1).upper}`);
    const s4 = within(matrix).getByRole('rowheader', { name: /S-4/ }).closest('tr') as HTMLElement;
    expect(s4).toHaveTextContent('구성상 값');
    expect(s4).toHaveTextContent(`약점 변형 ${test('agentdojo', 'S-4').weakVariants}개`);
  });

  it('opens a benchmark with its own tabs, and a tab it lacks opens its results (ST-70)', async () => {
    serve();
    const first = open('/benchmarks/agentdojo?tab=cases');
    expect(
      await screen.findByRole('heading', { level: 1, name: 'AgentDojo — 간접 프롬프트 주입' }),
    ).toBeInTheDocument();
    const cases = must(
      BUNDLE.benchmarks.find((b) => b.id === 'agentdojo'),
      'agentdojo',
    ).cases as Record<string, readonly { userRequest: string }[]>;
    const s1a = must(cases['S-1a'], 'S-1a cases');
    expect(
      screen.getByRole('heading', { name: new RegExp(`보호를 켜고도 성공한 공격 ${s1a.length}건`) }),
    ).toBeInTheDocument();
    expect(screen.getByText(must(s1a[0], 'first case').userRequest)).toBeInTheDocument();
    first.unmount();
    serve();
    open('/benchmarks/promptfoo?tab=variants');
    const tabs = await screen.findByRole('tablist', { name: 'Promptfoo 결과 화면' });
    expect(within(tabs).queryByRole('tab', { name: '변형' })).not.toBeInTheDocument();
    expect(within(tabs).getByRole('tab', { name: '결과' })).toHaveAttribute('aria-selected', 'true');
  });

  it('opens every tab of every benchmark from the real bundle, each tab it has selected', async () => {
    const dictionary = ko as Record<string, string>;
    for (const bench of BUNDLE.benchmarks) {
      for (const tab of ['results', 'breakdown', 'variants', 'cases', 'settings']) {
        const name = must(dictionary[`ux.bench.view.${tab}`], `tab name ${tab}`);
        if (bench.id === 'promptfoo' && tab === 'variants') {
          continue;
        }
        serve();
        const shown = open(`/benchmarks/${bench.id}?tab=${tab}`);
        expect(
          await screen.findByRole('heading', { level: 1, name: bench.title.ko }),
          `${bench.id} ${tab}`,
        ).toBeInTheDocument();
        expect(screen.getByRole('tab', { name }), `${bench.id} ${tab}`).toHaveAttribute('aria-selected', 'true');
        shown.unmount();
        vi.unstubAllGlobals();
      }
    }
  });

  it("lists InjecAgent's attacks that still succeeded with every attacker tool of each (a list of tools, not one)", async () => {
    serve();
    open('/benchmarks/injecagent?tab=cases');
    const injecagent = must(
      BUNDLE.benchmarks.find((b) => b.id === 'injecagent'),
      'injecagent',
    );
    const rows = (injecagent.cases as { protected: readonly { attackerTools: readonly string[] }[] }).protected;
    expect(rows.length).toBeGreaterThan(0);
    const first = must(rows[0], 'first case');
    expect(first.attackerTools.length).toBeGreaterThan(1);
    const joined = first.attackerTools.join(', ');
    expect(
      (await screen.findAllByText((_, element) => element?.tagName === 'CODE' && element.textContent === joined))
        .length,
    ).toBeGreaterThan(0);
  });

  it('says a benchmark that does not exist, a bundle that cannot be read and one of another format (ST-67 ~ ST-69)', async () => {
    serve();
    const first = open('/benchmarks/nothing');
    expect(await screen.findByText('없는 벤치마크입니다.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '표준 벤치마크 개요' })).toHaveAttribute('href', '/benchmarks');
    first.unmount();
    serve({ [BUNDLE_PATH]: 500 });
    const second = open('/benchmarks');
    expect(await screen.findByText('결과 묶음을 불러오지 못했습니다.')).toBeInTheDocument();
    second.unmount();
    serve({ [BUNDLE_PATH]: { ...BUNDLE, format: 'contexa-benchmark-bundle/2' } });
    open('/benchmarks');
    expect(await screen.findByText('이 화면이 읽지 못하는 결과 묶음 형식입니다.')).toBeInTheDocument();
  });

  it('lists every frozen version and every file the bundle stands on', async () => {
    serve();
    open('/benchmarks/method');
    const freezes = await screen.findByRole('table', { name: '실행 전 동결' });
    expect(within(freezes).getAllByRole('row')).toHaveLength(BUNDLE.freezes.length + 1);
    const sources = screen.getByRole('table', { name: '결과 묶음의 원자료' });
    await waitFor(() => expect(within(sources).getAllByRole('row')).toHaveLength(BUNDLE.sources.length + 1));
  });

  it('keeps the words of the standard benchmarks free of claims of certification (PC-9)', () => {
    const banned = /인증|인정|공인|certif|accredit|endors/i;
    const words = (dictionary: Record<string, string>) =>
      Object.entries(dictionary).filter(
        ([key]) => key.startsWith('ux.bench.') || key.startsWith('ux.home.bench.'),
      );
    for (const [key, value] of [...words(ko), ...words(en)]) {
      expect(value, key).not.toMatch(banned);
    }
    const shown = [
      ...BUNDLE.limits.flatMap((limit) => [limit.ko, limit.en, limit.sourceLabel.ko, limit.sourceLabel.en]),
      ...BUNDLE.benchmarks.flatMap((bench) =>
        bench.cost.flatMap((cost) => [cost.sourceLabel.ko, cost.sourceLabel.en]),
      ),
      ...BUNDLE.benchmarks.flatMap((bench) => [
        bench.title.ko,
        bench.title.en,
        bench.description.ko,
        bench.description.en,
        ...bench.tests.flatMap((item) => [item.label.ko, item.label.en, item.note.ko, item.note.en]),
      ]),
    ];
    for (const value of shown) {
      expect(value).not.toMatch(banned);
    }
  });
});
