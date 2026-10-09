import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import '../../i18n';
import i18n from '../../i18n';
import type { RuleCase, RuleCaseStep } from '../../domain/rules';
import { RulesScene } from './RulesScene';

/** A night export of 4,831 items: C1 stops it at night, C2 passes it only with an approval. */
const night: RuleCaseStep = {
  stepNo: 1,
  operation: 'EXPORT',
  companyTime: '2026-09-30T03:17:00Z',
  c1Facts: { items: 4831, accessDaysLast30: 3 },
  c1Outcome: 'STOPPED',
  c1Rule: 'C1-NIGHT',
  c2Facts: { items: 4831, approval: { covered: false } },
  c2Outcome: 'STOPPED',
  c2Rule: 'C2-NO-CONTEXT',
  contexaOutcome: 'HELD',
  contexaVerdict: 'CHALLENGE',
};

const cases: RuleCase[] = [
  {
    scenario: 'A3',
    classification: 'THREAT',
    title: { ko: '새벽 대량 반출', en: 'Night bulk export' },
    runId: 'run-a',
    finishedAt: '2026-10-06T10:00:00Z',
    steps: [night],
  },
  {
    scenario: 'A3T',
    classification: 'NORMAL',
    title: { ko: '승인된 새벽 반출', en: 'Approved night export' },
    runId: 'run-l',
    finishedAt: '2026-10-06T10:01:00Z',
    steps: [
      {
        ...night,
        c2Facts: { items: 4831, approval: { covered: true } },
        c2Outcome: 'DELIVERED',
        c2Rule: 'C2-APPROVAL',
        contexaOutcome: 'DELIVERED',
        contexaVerdict: 'ALLOW',
      },
    ],
  },
];

function score(label: string): string {
  return screen.getByText(label).previousElementSibling?.textContent ?? '';
}

describe('RulesScene', () => {
  it('scores the published rules, moves the score as the visitor loosens them, and shows Contexa only on request', async () => {
    await i18n.changeLanguage('ko');
    render(<RulesScene cases={cases} onNext={vi.fn()} />);

    expect(score('막은 공격')).toBe('1/1');
    expect(score('막힌 정상 업무')).toBe('1/1');
    expect(screen.queryByText(/Contexa:/)).toBeNull();

    // Moving the night window off the request time and raising the export limit leave only C2: the attack is still
    // stopped, the approved work passes.
    await userEvent.selectOptions(screen.getByLabelText('야간 시작'), '4');
    expect(score('막힌 정상 업무')).toBe('1/1');
    fireEvent.change(screen.getByLabelText(/한 번에 허용할 건수/), { target: { value: '6' } });
    expect(screen.getByText(/10,000건/)).toBeInTheDocument();
    expect(score('막은 공격')).toBe('1/1');
    expect(score('막힌 정상 업무')).toBe('0/1');

    // Turning the approval switch off halts the approved work again.
    await userEvent.click(screen.getByLabelText('승인 기록이 있으면 통과'));
    expect(score('막힌 정상 업무')).toBe('1/1');

    await userEvent.click(screen.getByRole('button', { name: 'Contexa의 점수 보기' }));
    expect(screen.getByText(/막은 공격 1\/1 · 막힌 정상 업무 0\/1/)).toBeInTheDocument();
    const list = screen.getByRole('list');
    expect(within(list).getByText('Contexa: 막음')).toBeInTheDocument();
    expect(within(list).getByText('Contexa: 통과')).toBeInTheDocument();
    expect(within(list).getAllByText(/실제 실행 run-/)).toHaveLength(2);

    await userEvent.click(screen.getByRole('button', { name: '처음 설정으로' }));
    expect(score('막힌 정상 업무')).toBe('1/1');
  });
});
