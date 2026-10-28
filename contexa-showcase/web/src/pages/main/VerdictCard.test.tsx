import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { RunFacts } from '../../api/promptQuality';
import i18n from '../../i18n';
import { ReasonChain } from './VerdictCard';

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

/** The assignment line the attack run run-e7177ebe6785 cited (71 characters, more than two lines of its column). */
const FACTS: RunFacts = {
  runId: 'run-e7177ebe6785',
  stepNo: 1,
  available: true,
  reason: null,
  bundle: null,
  blocks: [
    {
      block: 'DECISION_FACTS',
      facts: [
        {
          line: 41,
          factId: 'F4',
          label: 'Assignment',
          value: 'assigned to HX-310 (DESIGN); worked on HX-310 on 21 of the last 30 days',
          source: 'HOST',
          grades: ['HOST'],
        },
      ],
    },
  ],
};

// Review before the guide videos (2026-10-21): the F4 line was cut at two lines without the link the other lines had.
describe('a cited line cut at two lines (B-19)', () => {
  it('offers the whole line whenever the line may not fit in two lines', () => {
    render(
      <ReasonChain codes={[{ code: 'ASSIGNED_TARGET', fact: 'F4' }]} facts={FACTS} action="CHALLENGE" />,
    );
    expect(screen.getByRole('button', { name: i18n.t('main.verdictCard.more') })).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, V-48): the code names showed without being marked as the original.
  it('marks the code name under the plain words as the original code', () => {
    render(
      <ReasonChain codes={[{ code: 'ASSIGNED_TARGET', fact: 'F4' }]} facts={FACTS} action="CHALLENGE" />,
    );
    const original = screen.getByText('ASSIGNED_TARGET').closest('[data-original]');
    expect(original).toHaveTextContent(i18n.t('main.verdictCard.codeOriginal'));
  });

  // 구현계획 AC-N6/N9 점검: while the plain words are not loaded yet the original code stands in their place, and
  // `PAST_RECORD_SAME_TARGET` broke inside a word and left its last letter alone on a line (main-audit, 3-3).
  it('lets a code that has no plain words yet break only after an underscore', () => {
    render(
      <ReasonChain codes={[{ code: 'NOT_YET_IN_THE_DICTIONARY', fact: 'F4' }]} facts={FACTS} action="CHALLENGE" />,
    );
    const stand = screen.getByText('NOT_YET_IN_THE_DICTIONARY');
    expect(stand.tagName).toBe('B');
    expect(stand.querySelectorAll('wbr')).toHaveLength(4);
  });
});
