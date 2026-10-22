import { beforeEach, describe, expect, it } from 'vitest';
import type { DecisionAnatomyView } from '../../api/anatomy';
import type { InspectionCheck } from '../../api/promptQuality';
import i18n from '../../i18n';
import { inOrder, learnedCompared, learnedAdded, modelSummary } from './evidence';

// Review before the guide videos (2026-10-21): 4-4 put "+3" from the documents beside the arrow 49 -> 51.
describe('the learning of a run', () => {
  it('states the growth of the count the arrow shows, and the documents only without both counts', () => {
    expect(learnedAdded(49, 51, 3)).toBe(2);
    expect(learnedAdded(49, 49, 0)).toBe(0);
    expect(learnedAdded(null, 51, 3)).toBe(3);
  });
});

// Review before the guide videos (2026-10-21): 3-1 and 3-3 named the first or the last call's values beside "2 calls".
describe('the model calls of a decision', () => {
  it("states every call's tokens and the model time the server summed, not one call's", () => {
    const anatomy = {
      interpretation: {
        calls: [
          { model: 'gpt-6-luna', elapsedMs: 9743, promptTokens: 6203, completionTokens: 600 },
          { model: 'gpt-6-luna', elapsedMs: 6470, promptTokens: 6577, completionTokens: 425 },
        ],
        promptTokens: 12780,
        completionTokens: 1025,
        timings: {
          promptBuildMs: 107,
          ragVectorMs: 22,
          llmLatencyMs: 16358,
          totalAnalysisMs: 16358,
          events: [],
        },
      },
    } as unknown as DecisionAnatomyView;
    expect(modelSummary(anatomy)).toEqual({
      model: 'gpt-6-luna',
      calls: 2,
      promptTokens: 12780,
      completionTokens: 1025,
      ms: 16358,
    });
  });
});

// Review before the guide videos (2026-10-21): the same run's learning read 21 on one screen and 49 on the next.
describe('the learned requests a decision compared', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('ko');
  });
  const t = i18n.t.bind(i18n);

  it('names both counts and the window in days (V-08)', () => {
    const figures = { workProfileWindow: '7d', workProfileObservations: 21, baselineBefore: 49 };
    expect(learnedCompared(t, figures, 'ko')).toBe('학습 요청 49건 중 최근 7일 21건과 비교');
  });

  it('keeps a window it cannot read as the engine wrote it, and names no total it does not have', () => {
    const figures = { workProfileWindow: 'P7D', workProfileObservations: 21, baselineBefore: null };
    expect(learnedCompared(t, figures, 'ko')).toBe('최근 P7D 학습 요청 21건과 비교');
    expect(
      learnedCompared(
        t,
        { workProfileWindow: null, workProfileObservations: null, baselineBefore: 49 },
        'ko',
      ),
    ).toBeNull();
  });
});

// Review before the guide videos (2026-10-21): 2-3 and 3-3 listed the same checks in different orders.
describe("the inspector's checks", () => {
  it('come in one order on every screen (P-39)', () => {
    const check = (code: string): InspectionCheck => ({
      code,
      matched: 1,
      mismatched: 0,
      unverifiable: 0,
      mismatches: [],
    });
    const checks = ['REASON_MATCH', 'DECISION_FACT_MATCH', 'FACT_ACCURACY', 'SEAL_INTEGRITY', 'OTHER'].map(
      check,
    );
    expect(inOrder(checks).map((found) => found.code)).toEqual([
      'SEAL_INTEGRITY',
      'FACT_ACCURACY',
      'DECISION_FACT_MATCH',
      'REASON_MATCH',
    ]);
    expect(inOrder(checks, 3).map((found) => found.code)).toEqual([
      'SEAL_INTEGRITY',
      'FACT_ACCURACY',
      'DECISION_FACT_MATCH',
    ]);
  });
});
