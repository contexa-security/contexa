import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { Histogram } from './Histogram';
import { ProofLines } from './ProofLines';

const KO: Readonly<Record<string, string>> = ko;
const word = (key: string): string => KO[key] ?? key;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('the five proof lines', () => {
  it("states what each criterion checks with the portal's counts and no mark of success", () => {
    render(
      <ProofLines
        totals={{
          attackRuns: 30,
          attackAllPassed: 30,
          contexaStopped: 24,
          contexaFullyStopped: 12,
          normalRuns: 25,
          normalAllPassed: 25,
          contexaPassed: 19,
        }}
        agreement={{ decisions: 410, modelAnswered: 380, asAnswered: 380, technical: 0, held: 30 }}
        reasons={null}
      />,
    );
    const list = screen.getByRole('list', { name: word('bench.chart.proof.title') });
    const items = within(list).getAllByRole('listitem');
    expect(items.map((item) => item.dataset.proof)).toEqual(['g1', 'g2', 'g3', 'g4', 'g5']);
    // P-30 of docs/showcase/영상전-검토.md: each criterion named in words, not as G1 to G5.
    expect(items.map((item) => item.querySelector('[data-label]')?.textContent)).toEqual([
      '기준 1',
      '기준 2',
      '기준 3',
      '기준 4',
      '기준 5',
    ]);
    expect(items[0]).toHaveTextContent('실행 30/30');
    // V-21: the criterion says what is checked, never that it held; the value says how far it did.
    expect(items[2]).toHaveTextContent(word('bench.chart.proof.g3'));
    expect(word('bench.chart.proof.g3')).toMatch(/는지$/);
    expect(items[2]).toHaveTextContent('공격 막음 24/30(첫 건부터 막음 12) · 정상 통과 19/25');
    // V-52, P-31: the model's last answer, unchanged by Contexa, and the requests that reused an earlier decision.
    expect(items[3]).toHaveTextContent(word('bench.chart.proof.g4'));
    expect(items[3]).toHaveTextContent('판정 380/380 · 새로 판단하지 않고 앞선 판정을 그대로 쓴 요청 30건');
    expect(items[4]).toHaveTextContent(word('bench.chart.proof.none'));
    expect(list).not.toHaveTextContent('✓');
  });
});

describe('the decision times', () => {
  it('draws a bar per bin with its count and marks the bins holding the median and the 95th percentile', () => {
    const { container } = render(
      <Histogram
        bins={[
          { fromMs: 0, toMs: 5000, decisions: 40 },
          { fromMs: 5000, toMs: 10000, decisions: 210 },
          { fromMs: 10000, toMs: 20000, decisions: 120 },
          { fromMs: 20000, toMs: null, decisions: 30 },
        ]}
        p50Ms={8200}
        p95Ms={21400}
        summary="판정 400건의 판단 시간"
      />,
    );
    expect(screen.getByRole('img', { name: '판정 400건의 판단 시간' })).toBeInTheDocument();
    expect(container.querySelectorAll('[data-bin]')).toHaveLength(4);
    expect(container.querySelector('[data-bin="5000"]')).toHaveTextContent('210');
    expect(container.querySelector('[data-bin="5000"]')).toHaveTextContent('▼ 중앙값 8.20초');
    expect(container.querySelector('[data-bin="20000"]')).toHaveTextContent('20초 이상');
    expect(container.querySelector('[data-bin="20000"]')).toHaveTextContent('▼ 95%가 21.40초 안');
    expect(screen.getByRole('row', { name: /^5~10초/ })).toHaveTextContent('210');
  });
});
