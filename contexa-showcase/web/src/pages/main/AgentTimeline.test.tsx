import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import type { AgentRunStep } from '../../api/agentCase';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { layersOf } from './agentGroup';
import { AgentTimeline } from './AgentTimeline';
import type { TimelineRow } from './timelineFolding';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

function stored(no: number, d: string, path: string, verdict: boolean): TimelineRow {
  const delivered = { outcome: 'DELIVERED', deliveredItems: 0, rule: null };
  const step: AgentRunStep = {
    stepNo: no,
    sentBy: 'AGENT_WORK',
    tool: { tool: 'listDocuments', arguments: {} },
    path,
    companyTime: null,
    outcomes: { A: delivered, B: delivered, C1: delivered, C2: delivered, D: { ...delivered, outcome: d } },
    decision: verdict
      ? { final_action: 'ALLOW', risk_score: 0.1, model_calls: 1, total_tokens: 10 }
      : { final_action: null, risk_score: null, model_calls: null, total_tokens: null },
  };
  return { stepNo: no, step, layers: layersOf(step) };
}

describe('the agent timeline (AS-9)', () => {
  it('shows one row per request with the five approaches answers, in order', () => {
    const rows = [stored(1, 'DELIVERED', '/api/projects', false), stored(2, 'DELIVERED', '/api/a', false)];

    render(<AgentTimeline rows={rows} />);

    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    expect(within(table).getAllByText(word('main.agent.outcome.DELIVERED'))).toHaveLength(10);
  });

  it('folds a burst into one line that says how many requests it holds and how many had a verdict of their own', () => {
    const burst = Array.from({ length: 60 }, (_, i) => stored(i + 2, 'DELIVERED', '/api/same', i === 0));
    const rows = [stored(1, 'DELIVERED', '/api/projects', false), ...burst];

    render(<AgentTimeline rows={rows} />);

    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(3);
    const group = screen.getByRole('button', { name: new RegExp(word('main.agent.timeline.expand')) });
    expect(group).toHaveAttribute('aria-expanded', 'false');
    expect(group).toHaveTextContent('60');
    expect(screen.getByText(/자체 판정 1건 · 모델 호출 1번/)).toBeInTheDocument();
  });

  it('opens the folded requests row by row and folds them again', async () => {
    const burst = Array.from({ length: 6 }, (_, i) => stored(i + 1, 'DELIVERED', '/api/same', false));
    render(<AgentTimeline rows={burst} />);

    const toggle = screen.getByRole('button');
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(1 + 1 + 6);
    await userEvent.click(toggle);
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2);
  });

  it('draws a live run that has no stored steps row by row, waiting for the controls not yet answered', () => {
    const live: TimelineRow[] = [{ stepNo: 1, layers: {}, step: null }];

    render(<AgentTimeline rows={live} />);

    expect(within(screen.getByRole('table')).getAllByText(word('main.agent.outcome.WAITING'))).toHaveLength(5);
  });
});
