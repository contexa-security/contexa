import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Hypothesis, RunFacts } from '../../api/promptQuality';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { Hypotheses } from './Hypotheses';

const KO: Readonly<Record<string, string>> = ko;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

/**
 * The explanations the real v21.3 decision of A3T weighed (run-9061d9f71432, step 1): H1 most likely for the approval
 * line F4, the other explanations possible or unlikely; an H5 named by the model is shown as its original.
 */
const HYPOTHESES: readonly Hypothesis[] = [
  { id: 'H1', name: null, assessment: 'MOST_LIKELY', for: ['F4'], against: ['F1'] },
  { id: 'H2', name: null, assessment: 'POSSIBLE', for: ['F1'], against: [] },
  { id: 'H5', name: 'scheduled transfer job', assessment: 'UNLIKELY', for: [], against: ['F4'] },
];

const FACTS: RunFacts = {
  runId: 'run-9061d9f71432',
  stepNo: 1,
  available: true,
  reason: null,
  bundle: {
    version: '2026.10.19-v21.3',
    hash: '60286ffafb20',
    selectionSource: 'CONFIGURATION',
    layout: 'v21-dictionary-blocks',
  },
  blocks: [
    {
      block: 'DECISION_FACTS',
      facts: [
        {
          line: 30,
          factId: 'F4',
          label: 'Approval',
          value: 'APR-9061d9f71432-1 by pm-11, APPROVED',
          source: 'HOST',
          grades: ['HOST'],
        },
      ],
    },
  ],
};

describe('the explanations a v21 decision weighed (SC-8)', () => {
  it('names each explanation with the assessment and the facts for and against it', () => {
    render(<Hypotheses hypotheses={HYPOTHESES} facts={FACTS} />);
    const rows = Array.from(document.querySelectorAll('li'));
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent(required(KO['hypothesis.H1'], 'H1'));
    expect(rows[0]).toHaveTextContent(required(KO['hypothesis.assessment.MOST_LIKELY'], 'most likely'));
    expect(rows[0]).toHaveTextContent(`F4 ${required(KO['fact.label.Approval'], 'Approval')}`);
    expect(rows[1]).toHaveTextContent(required(KO['hypothesis.H2'], 'H2'));
    expect(rows[2]).toHaveTextContent(required(KO['hypothesis.H5'], 'H5'));
    expect(screen.getByText('scheduled transfer job')).toHaveAttribute('data-original');
  });

  it('draws nothing for a decision before v21', () => {
    const { container } = render(<Hypotheses hypotheses={[]} facts={FACTS} />);
    expect(container).toBeEmptyDOMElement();
  });
});

// Review before the guide videos (2026-10-21): 3-3 and 5-3 showed "-" for an empty list, a fact on both sides without a
// word, and the most likely legitimate work first with nothing on why the verdict still asked for more.
describe('the explanations as a visitor reads them', () => {
  it('writes an empty list as none, never a placeholder (V-47)', () => {
    render(<Hypotheses hypotheses={HYPOTHESES} facts={FACTS} />);
    const rows = Array.from(document.querySelectorAll('li'));
    expect(rows[1]).toHaveTextContent(required(KO['main.3-3.hypothesisNone'], 'none'));
    expect(rows[1]?.textContent).not.toMatch(/\s-(\s|$)/);
  });

  it('says the AI named a fact both for and against one explanation (V-47)', () => {
    const both: readonly Hypothesis[] = [
      { id: 'H3', name: null, assessment: 'POSSIBLE', for: ['R4', 'F4'], against: ['F3', 'F4'] },
    ];
    render(<Hypotheses hypotheses={both} facts={FACTS} />);
    const note = required(KO['main.3-3.hypothesisBoth'], 'both').replace(
      '{{facts}}',
      `F4 ${required(KO['fact.label.Approval'], 'Approval')}`,
    );
    expect(screen.getByText(note)).toBeInTheDocument();
  });

  it('says the verdict weighs the other possibilities, not the most likely one alone (V-59)', () => {
    render(<Hypotheses hypotheses={HYPOTHESES} facts={FACTS} />);
    expect(screen.getByText(required(KO['main.3-3.hypothesesLead'], 'lead'))).toBeInTheDocument();
  });
});
