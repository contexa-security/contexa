import { describe, expect, it } from 'vitest';
import type { AgentRunStep } from '../../api/agentCase';
import { foldRows, groupFacts, type TimelineRow } from './timelineFolding';

function step(no: number, d: string, rule: string | null, path = '/api/projects/HX-310/documents', verdict = false): TimelineRow {
  const outcomes = {
    A: { outcome: 'DELIVERED', deliveredItems: 0, rule: null },
    B: { outcome: 'DELIVERED', deliveredItems: 0, rule: null },
    C1: { outcome: 'DELIVERED', deliveredItems: 0, rule: null },
    C2: { outcome: 'DELIVERED', deliveredItems: 0, rule: null },
    D: { outcome: d, deliveredItems: 0, rule },
  };
  const found: AgentRunStep = {
    stepNo: no,
    sentBy: 'AGENT_WORK',
    tool: { tool: 'listDocuments', arguments: { projectKey: 'HX-310' } },
    path,
    companyTime: null,
    outcomes,
    decision: verdict
      ? { final_action: 'ALLOW', risk_score: 0.1, model_calls: 1, total_tokens: 100 }
      : { final_action: null, risk_score: null, model_calls: null, total_tokens: null },
  };
  return { stepNo: no, layers: {}, step: found };
}

describe('folding a burst of identical requests (AS-9)', () => {
  it('folds a run of at least five requests answered alike into one group, keeping the others as rows', () => {
    const rows = [
      step(1, 'DELIVERED', null, '/api/projects'),
      ...Array.from({ length: 60 }, (_, i) => step(i + 2, 'DELIVERED', null)),
      step(62, 'REFUSED', 'ZERO_TRUST_BLOCK', '/api/documents/X'),
    ];

    const folded = foldRows(rows);

    expect(folded.map((entry) => entry.kind)).toEqual(['row', 'group', 'row']);
    const group = folded[1];
    expect(group?.kind === 'group' ? group.rows.length : 0).toBe(60);
  });

  it('does not fold fewer than five alike, nor requests answered differently', () => {
    const four = Array.from({ length: 4 }, (_, i) => step(i + 1, 'DELIVERED', null));
    expect(foldRows(four).every((entry) => entry.kind === 'row')).toBe(true);
    const mixed = Array.from({ length: 8 }, (_, i) =>
      step(i + 1, i % 2 === 0 ? 'DELIVERED' : 'REFUSED', i % 2 === 0 ? null : 'ZERO_TRUST_BLOCK'),
    );
    expect(foldRows(mixed).every((entry) => entry.kind === 'row')).toBe(true);
  });

  it('folds nothing of a live run that has no stored steps yet', () => {
    const live: TimelineRow[] = Array.from({ length: 9 }, (_, i) => ({ stepNo: i + 1, layers: {}, step: null }));
    expect(foldRows(live).every((entry) => entry.kind === 'row')).toBe(true);
  });

  it('tells how many of a group had a verdict of their own and how many model calls they made', () => {
    const rows = [
      ...Array.from({ length: 6 }, (_, i) => step(i + 1, 'DELIVERED', null, '/p', i === 0)),
    ];

    expect(groupFacts(rows)).toEqual({ count: 6, withVerdict: 1, modelCalls: 1 });
  });
});
