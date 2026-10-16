import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { LabDelta, OtherBundleView, RunFacts, RunQuality } from '../../api/promptQuality';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { DeltaLines } from './DeltaLines';
import { FactCard } from './FactCard';
import { compareOffered, ribbonLines } from './factWords';
import { PromptChunks } from './PromptChunks';
import { PromptCompare } from './PromptCompare';
import { QualityRibbon } from './QualityRibbon';
import { ReasonChain } from './ReasonChain';
import { SourceChip } from './SourceChip';
import { VerifyParts } from './VerifyParts';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

/**
 * The facts of the A3 sample's step 1 as the portal's facts view gives them (labels and values of the real v20 prompt
 * of control D, docs/showcase-portal test resource anatomy/v20-prompts.json; line numbers and fact IDs as drawn).
 */
const facts: RunFacts = {
  runId: 'run-a3',
  stepNo: 1,
  available: true,
  reason: null,
  bundle: { version: 'v20.23', hash: 'abcdef0123456789', selectionSource: 'REGISTRY', layout: 'V20_BLOCKS' },
  blocks: [
    {
      block: 'USER_BASELINE',
      facts: [
        {
          line: 3,
          factId: 'B1',
          label: 'BaselineStatus',
          value: 'ESTABLISHED (25 learned requests, personal baseline AVAILABLE)',
          source: 'LEARNED',
          grades: ['LEARNED'],
        },
        { line: 4, factId: 'B2', label: 'UsualHours', value: '10-11, 13-14, 17', source: 'LEARNED', grades: ['LEARNED'] },
      ],
    },
    {
      block: 'SESSION',
      facts: [
        { line: 19, factId: 'S1', label: 'SessionAge', value: '2 min since login', source: 'COMPUTED', grades: ['COMPUTED'] },
      ],
    },
    {
      block: 'REQUEST',
      facts: [
        {
          line: 26,
          factId: 'R1',
          label: 'Subject',
          value: 'v66fc0ee75c8f-adm-a (HUMAN_USER)',
          source: 'HOST',
          grades: ['HOST'],
        },
        {
          line: 27,
          factId: 'R2',
          label: 'Roles',
          value: 'SC_ADMIN; source SECURITY_CONTEXT',
          source: 'HOST',
          grades: ['HOST'],
        },
        { line: 28, factId: 'R3', label: 'Time', value: 'Wed 03:17', source: 'COMPUTED', grades: ['COMPUTED'] },
      ],
    },
    {
      block: 'DECISION_FACTS',
      facts: [
        {
          line: 37,
          factId: 'F1',
          label: 'DeviationsFromBaseline',
          value: '4 of 10 compared -> time 03 seen 0 of 25 (unexplained)',
          source: 'COMPUTED',
          grades: ['COMPUTED'],
        },
        {
          line: 40,
          factId: 'F4',
          label: 'PolicySatisfied',
          value: 'no — no approval for GB-500',
          source: 'COMPUTED',
          grades: ['COMPUTED'],
        },
        {
          line: 41,
          factId: 'F5',
          label: 'Assignment',
          value: 'not assigned to GB-500',
          source: 'HOST',
          grades: ['HOST'],
        },
      ],
    },
    {
      block: 'PAST_RECORDS',
      facts: [
        {
          line: 50,
          factId: 'P1',
          label: 'PastRecordsState',
          value: 'not retrieved (TIMEOUT)',
          source: 'LEARNED',
          grades: ['LEARNED'],
        },
      ],
    },
    {
      block: 'UNKNOWN',
      facts: [{ line: 53, factId: null, label: 'Unknown', value: 'ClientSignals, PeerCohort', source: null, grades: [] }],
    },
    {
      block: 'UNTRUSTED_TEXT',
      facts: [
        {
          line: 56,
          factId: null,
          label: 'UntrustedText1',
          value: 'source=request path (requester); "/api/projects/GB-500/exports"',
          source: 'UNTRUSTED',
          grades: ['UNTRUSTED'],
        },
      ],
    },
  ],
};

const quality: RunQuality = {
  available: true,
  reason: null,
  bundle: facts.bundle,
  seal: { packageId: 'pkg-1', packageHash: 'sha256:aa11bb22', capturedAt: '2026-10-16T03:17:10Z' },
  inspection: {
    verdict: 'FAIL',
    inspectorVersion: 'prompt-inspector-v2',
    inspectedAt: '2026-10-16T03:18:00Z',
    checks: [
      { code: 'SEAL_INTEGRITY', matched: 4, mismatched: 0, unverifiable: 0, mismatches: [] },
      {
        code: 'FACT_ACCURACY',
        matched: 11,
        mismatched: 1,
        unverifiable: 2,
        mismatches: [
          {
            block: 'REQUEST',
            entry: 'Time',
            factId: 'R3',
            line: 28,
            expected: 'Wed 03:17',
            actual: 'Wed 03:18',
            reason: 'value differs',
          },
        ],
      },
      { code: 'REASON_MATCH', matched: 2, mismatched: 0, unverifiable: 1, mismatches: [] },
    ],
  },
  reasonCodes: [
    { code: 'MIN_P3_POLICY_NOT_SATISFIED', fact: 'F4' },
    { code: 'DEVIATION_TIME', fact: 'F1' },
    { code: 'APPROVAL_COVERS', fact: null },
    { code: 'DEVIATION_TARGET', fact: 'F9' },
  ],
  ribbon: { facts: 12, withSource: 11, factAccuracy: { matched: 11, total: 12 }, contradictions: 0, unknown: 2 },
};

function fact(block: string, line: number) {
  const entry = required(
    facts.blocks.find((candidate) => candidate.block === block),
    block,
  );
  return { block: entry.block, fact: required(entry.facts.find((candidate) => candidate.line === line), `${line}`) };
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

/** U-1: the source chip, the same look for the five sources, told apart by words. */
describe('source chip', () => {
  it('names each of the five sources and a line without one by words, in one look', () => {
    render(
      <>
        {(['HOST', 'LEARNED', 'COMPUTED', 'INFERRED', 'UNTRUSTED', null] as const).map((source) => (
          <SourceChip key={source ?? 'none'} source={source} />
        ))}
      </>,
    );
    const words = ['회사 기록', '학습', '계산', '추정', '외부 글', word('fact.source.NONE')];
    const chips = words.map((text) => required(screen.getByText(text).parentElement, text));
    expect(new Set(chips.map((chip) => chip.className)).size).toBe(1);
    expect(chips.map((chip) => chip.dataset.source)).toEqual([
      'HOST',
      'LEARNED',
      'COMPUTED',
      'INFERRED',
      'UNTRUSTED',
      'NONE',
    ]);
  });
});

/** U-1: the fact card with its ID, plain words, source and the original in place. */
describe('fact card', () => {
  it('shows the ID, the plain words of the entry and of the value, and the source chip', () => {
    const { block, fact: policy } = fact('DECISION_FACTS', 40);
    render(<FactCard fact={policy} block={block} />);
    expect(screen.getByText('F4')).toBeInTheDocument();
    expect(screen.getByText(word('fact.label.PolicySatisfied'))).toBeInTheDocument();
    expect(screen.getByText(word('prompt.plain.approvalMissing'))).toBeInTheDocument();
    expect(screen.getByText('계산')).toBeInTheDocument();
    expect(screen.queryByText('PolicySatisfied: no — no approval for GB-500')).not.toBeInTheDocument();
  });

  it('opens the original line, its line number and the dictionary meaning in place', async () => {
    const { block, fact: policy } = fact('DECISION_FACTS', 40);
    render(<FactCard fact={policy} block={block} />);
    await userEvent.click(screen.getByRole('button', { name: word('source.original') }));
    const box = screen.getByRole('group', { name: word('source.original') });
    const line = within(box).getByText('PolicySatisfied: no — no approval for GB-500');
    expect(line).toHaveAttribute('data-original');
    expect(box).toHaveTextContent(fill('fact.lineNo', { n: 40 }));
    expect(box).toHaveTextContent(word('fact.meaning.PolicySatisfied'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('names a numbered line by its entry', () => {
    const { block, fact: text } = fact('UNTRUSTED_TEXT', 56);
    render(<FactCard fact={text} block={block} />);
    // The entry's name and the source chip of an outside text say the same words; the label is not 'other'.
    expect(word('fact.label.UntrustedText')).toBe('외부 글');
    expect(screen.getAllByText('외부 글')).toHaveLength(2);
    expect(screen.queryByText(word('fact.label.other'))).not.toBeInTheDocument();
    expect(screen.queryByText(/UntrustedText1/)).not.toBeInTheDocument();
  });
});

/** U-1: the quality ribbon, the server's counts with a cross for an item that does not hold. */
describe('quality ribbon', () => {
  it("states the server's counts and leads a failing item to the fact behind it", async () => {
    const ribbon = required(quality.ribbon, 'ribbon');
    const onShow = vi.fn();
    render(<QualityRibbon ribbon={ribbon} lines={ribbonLines(quality, facts)} onShow={onShow} />);
    const group = screen.getByRole('group', { name: word('quality.ribbon.title') });
    expect(group).toHaveTextContent(fill('quality.ribbon.source', { n: 11, total: 12 }));
    expect(group).toHaveTextContent(fill('quality.ribbon.accuracy', { n: 11, total: 12 }));
    expect(group).toHaveTextContent(fill('quality.ribbon.contradictions', { n: 0 }));
    expect(group).toHaveTextContent(fill('quality.ribbon.unknown', { n: 2 }));
    // Two items do not hold: each is a button with its counts; the one that holds is not.
    const failing = within(group).getAllByRole('button');
    expect(failing).toHaveLength(2);
    expect(failing.map((button) => button.closest('li')?.dataset.ok)).toEqual(['false', 'false']);
    await userEvent.click(required(failing[1], 'accuracy'));
    expect(onShow).toHaveBeenCalledWith('accuracy', 28);
    await userEvent.click(required(failing[0], 'source'));
    expect(onShow).toHaveBeenCalledWith('source', 53);
  });

  it('says the inspection has not run yet instead of a mark while the seal has none', () => {
    render(
      <QualityRibbon
        ribbon={{ facts: 12, withSource: 12, factAccuracy: null, contradictions: null, unknown: 2 }}
        onShow={vi.fn()}
      />,
    );
    const group = screen.getByRole('group', { name: word('quality.ribbon.title') });
    expect(group).toHaveTextContent(word('quality.ribbon.accuracyPending'));
    expect(group).toHaveTextContent(word('quality.ribbon.contradictionsPending'));
    expect(group.querySelectorAll('li[data-ok="pending"]')).toHaveLength(2);
    expect(group.querySelectorAll('li[data-ok="false"]')).toHaveLength(0);
    expect(within(group).queryByRole('button')).not.toBeInTheDocument();
  });

  it('states a failing item as text where nothing can be opened', () => {
    render(<QualityRibbon ribbon={required(quality.ribbon, 'ribbon')} />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getAllByText(word('quality.ribbon.failed'))).toHaveLength(2);
  });
});

/** U-2: the five parts in reading order, their fact cards in place, and the two folds. */
describe('prompt parts', () => {
  it('shows the five parts in the order the AI reads them and the two folds', () => {
    render(<PromptChunks facts={facts} quality={quality} />);
    const list = screen.getByRole('list', { name: word('prompt.chunks') });
    expect(list.querySelectorAll(':scope > li > button[aria-expanded]')).toHaveLength(5);
    const names = Array.from(list.querySelectorAll(':scope > li > button'), (button) =>
      button.querySelector('span:nth-child(2)')?.textContent,
    );
    expect(names).toEqual(['이 요청', '이 세션', '평소 모습', '판정 사실', '모르는 것']);
    const folds = screen.getByRole('group', { name: word('prompt.folds') });
    expect(Array.from(folds.querySelectorAll('summary'), (summary) => summary.textContent)).toEqual([
      `${word('prompt.block.PAST_RECORDS')} · ${word('prompt.blockWhat.PAST_RECORDS')}`,
      `${word('prompt.block.UNTRUSTED_TEXT')} · ${word('prompt.blockWhat.UNTRUSTED_TEXT')}`,
    ]);
  });

  it('opens a part with its fact cards below it, not in a window, one part at a time', async () => {
    render(<PromptChunks facts={facts} quality={quality} />);
    // The decision facts are open first.
    expect(screen.getByRole('list', { name: '판정 사실' })).toHaveTextContent('F4');
    await userEvent.click(screen.getByRole('button', { name: /이 요청/ }));
    const request = screen.getByRole('list', { name: '이 요청' });
    expect(within(request).getAllByText(/^R\d$/)).toHaveLength(3);
    expect(screen.queryByRole('list', { name: '판정 사실' })).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    // A part's source chips are its facts' sources, each once.
    expect(screen.getByRole('button', { name: /이 요청/ })).toHaveTextContent(/회사 기록.*계산/);
  });

  it('leads a failing ribbon item to the marked fact card in its part', async () => {
    render(<PromptChunks facts={facts} quality={quality} />);
    const group = screen.getByRole('group', { name: word('quality.ribbon.title') });
    await userEvent.click(within(group).getAllByRole('button')[1] ?? group);
    const card = required(document.getElementById('fact-line-28'), 'card of line 28');
    expect(card).toHaveAttribute('data-highlight');
    expect(card).toHaveTextContent('R3');
  });
});

/** U-3, C-21: the facts the AI received, the reason codes and the decision, joined. */
describe('reason chain', () => {
  it("puts each reason on its fact's row and says no link where a reason cites no received fact", () => {
    render(
      <ReasonChain
        reasonCodes={quality.reasonCodes}
        facts={facts}
        verdict="CHALLENGE"
        check={quality.inspection?.checks.find((check) => check.code === 'REASON_MATCH') ?? null}
      />,
    );
    const rows = Array.from(document.querySelectorAll('ol > li'));
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent('F4');
    expect(rows[0]).toHaveTextContent(word('reasonCode.MIN_P3_POLICY_NOT_SATISFIED'));
    expect(rows[1]).toHaveTextContent('F1');
    expect(rows[1]).toHaveTextContent(word('reasonCode.DEVIATION_TIME'));
    // A reason without a fact and a reason citing a fact the AI did not receive (F9).
    expect(rows[2]).toHaveTextContent(word('reasonChain.noLink'));
    expect(rows[3]).toHaveTextContent(word('reasonChain.noLink'));
    expect(screen.getAllByText(word('reasonChain.noLink'))).toHaveLength(2);
    expect(screen.getByText(word('verdict.verify'))).toBeInTheDocument();
    expect(screen.getByText(fill('reasonChain.check', { matched: 2, mismatched: 0, unverifiable: 1 }))).toBeInTheDocument();
  });

  it('marks the fact card of a pressed reason code', async () => {
    render(<ReasonChain reasonCodes={quality.reasonCodes} facts={facts} verdict="CHALLENGE" />);
    const code = screen.getByRole('button', { name: new RegExp(word('reasonCode.DEVIATION_TIME')) });
    await userEvent.click(code);
    expect(code).toHaveAttribute('aria-pressed', 'true');
    const marked = Array.from(document.querySelectorAll('[data-highlight]'));
    expect(marked.map((card) => (card as HTMLElement).dataset.fact)).toEqual(['F1']);
  });

  it('shows the cited fact ID without a card when the facts cannot be read', () => {
    render(<ReasonChain reasonCodes={quality.reasonCodes} facts={null} verdict="CHALLENGE" />);
    expect(screen.getAllByText(word('reasonChain.noCard'))).toHaveLength(3);
    expect(screen.getAllByText(word('reasonChain.noLink'))).toHaveLength(1);
  });
});

/** U-5, C-22: what the changed condition changed in the AI input, and the delivery check. */
describe('lab changed lines', () => {
  const delta: LabDelta = {
    runId: 'run-2',
    baseRunId: 'run-1',
    condition: 'approval',
    value: 'False',
    available: true,
    reason: null,
    steps: [
      {
        stepNo: 1,
        changed: [
          {
            label: 'PolicySatisfied',
            before: ['yes — approval APR-1'],
            after: ['no — no approval for GB-500'],
          },
        ],
        expected: ['PolicySatisfied', 'Approval'],
        unexpected: [],
        valueMatches: true,
        passed: true,
        notCompared: null,
      },
    ],
  };

  it('joins the changed condition, the changed line and the decision, and says the value went into that line only', () => {
    render(<DeltaLines delta={delta} verdict="CHALLENGE" />);
    const section = screen.getByRole('region', { name: word('labDelta.title') });
    expect(section).toHaveTextContent(word('lab.fieldInline.approval'));
    const lines = screen.getByRole('list', { name: word('labDelta.lines') });
    expect(lines).toHaveTextContent(word('fact.label.PolicySatisfied'));
    expect(within(lines).getByText('PolicySatisfied: yes — approval APR-1 → no — no approval for GB-500')).toHaveAttribute(
      'data-original',
    );
    expect(section).toHaveTextContent(word('labDelta.passed'));
    expect(section).toHaveTextContent(word('verdict.verify'));
  });

  it('counts the other lines the change left as they were when the server says how many', () => {
    const counted: LabDelta = { ...delta, steps: delta.steps.map((step) => ({ ...step, unchangedLines: 37 })) };
    render(<DeltaLines delta={counted} verdict="CHALLENGE" />);
    expect(screen.getByText(fill('labDelta.passedCount', { n: 37 }))).toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.passed'))).not.toBeInTheDocument();
  });

  it('leaves the count out when the server does not say it', () => {
    const unsaid: LabDelta = { ...delta, steps: delta.steps.map((step) => ({ ...step, unchangedLines: null })) };
    render(<DeltaLines delta={unsaid} verdict="CHALLENGE" />);
    expect(screen.getByText(word('labDelta.passed'))).toBeInTheDocument();
  });

  it('shows a cross with the lines that changed though not expected to', () => {
    const failed: LabDelta = {
      ...delta,
      steps: [
        {
          stepNo: 1,
          changed: [
            { label: 'PolicySatisfied', before: ['yes — approval APR-1'], after: ['no — no approval for GB-500'] },
            { label: 'Time', before: ['Wed 03:17'], after: ['Wed 03:18'] },
          ],
          expected: ['PolicySatisfied', 'Approval'],
          unexpected: ['Time'],
          valueMatches: true,
          passed: false,
          notCompared: null,
        },
      ],
    };
    render(<DeltaLines delta={failed} verdict="CHALLENGE" />);
    expect(screen.getByText(word('labDelta.failed'))).toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.passed'))).not.toBeInTheDocument();
    const unexpected = screen.getByRole('list', { name: word('labDelta.unexpected') });
    expect(unexpected).toHaveTextContent(word('fact.label.Time'));
    expect(screen.getByRole('list', { name: word('labDelta.lines') }).querySelectorAll('li[data-unexpected]')).toHaveLength(1);
  });

  it('says in one line that the request does not look the condition up, not that no line changed', () => {
    const notLookedUp: LabDelta = {
      ...delta,
      steps: [
        {
          stepNo: 1,
          changed: [],
          expected: ['Subject'],
          unexpected: [],
          valueMatches: null,
          passed: true,
          notCompared: null,
          unchangedLines: 37,
          notLookedUp: 'APPROVAL',
        },
      ],
    };
    render(<DeltaLines delta={notLookedUp} verdict="CHALLENGE" />);
    expect(screen.getByText(word('labDelta.notLookedUp.APPROVAL'))).toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.none'))).not.toBeInTheDocument();
    expect(screen.queryByText(fill('labDelta.passedCount', { n: 37 }))).not.toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.passed'))).not.toBeInTheDocument();
  });

  it('shows the cross and the lines when a condition the request does not look up changed lines', () => {
    const changedAnyway: LabDelta = {
      ...delta,
      steps: [
        {
          stepNo: 1,
          changed: [{ label: 'OnCall', before: ['not on call'], after: ['on call (ops)'] }],
          expected: ['Subject'],
          unexpected: ['OnCall'],
          valueMatches: null,
          passed: false,
          notCompared: null,
          notLookedUp: 'ON_CALL',
        },
      ],
    };
    const { container } = render(<DeltaLines delta={changedAnyway} verdict="CHALLENGE" />);
    expect(screen.getByText(word('labDelta.failed'))).toBeInTheDocument();
    expect(screen.getByRole('list', { name: word('labDelta.unexpected') })).toHaveTextContent(
      word('fact.label.OnCall'),
    );
    expect(container).not.toHaveTextContent(
      KO['labDelta.notLookedUp.ON_CALL'] ?? 'labDelta.notLookedUp.ON_CALL',
    );
  });

  it('shows a step the server did not compare as not compared, never as passed', () => {
    const notCompared: LabDelta = {
      ...delta,
      steps: [
        {
          stepNo: 1,
          changed: [],
          expected: ['PolicySatisfied'],
          unexpected: [],
          valueMatches: null,
          passed: false,
          notCompared: 'NOT_SEALED',
        },
      ],
    };
    render(<DeltaLines delta={notCompared} verdict="CHALLENGE" />);
    expect(screen.getByText(word('labDelta.notCompared.NOT_SEALED'))).toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.passed'))).not.toBeInTheDocument();
    expect(screen.queryByText(word('labDelta.failed'))).not.toBeInTheDocument();
  });

  it('says why only one of the two runs sealed a step, never as passed', () => {
    for (const reason of ['NOT_SEALED_ONE_SIDE', 'NOT_SEALED_AFTER_DIFFERENT_DECISION'] as const) {
      const oneSide: LabDelta = {
        ...delta,
        steps: [
          {
            stepNo: 2,
            changed: [],
            expected: ['PolicySatisfied'],
            unexpected: [],
            valueMatches: null,
            passed: false,
            notCompared: reason,
          },
        ],
      };
      const { container } = render(<DeltaLines delta={oneSide} verdict="CHALLENGE" />);
      const flow = within(container);
      expect(flow.getByText(word(`labDelta.notCompared.${reason}`))).toBeInTheDocument();
      expect(flow.queryByText(word('labDelta.notCompared.NOT_SEALED'))).not.toBeInTheDocument();
      expect(flow.queryByText(word('labDelta.passed'))).not.toBeInTheDocument();
    }
  });

  it('says why a run has no changed lines', () => {
    render(<DeltaLines delta={{ ...delta, available: false, reason: 'DESIGNED', steps: [] }} verdict="ALLOW" />);
    expect(screen.getByText(word('labDelta.reason.DESIGNED'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('labDelta.lines') })).not.toBeInTheDocument();
  });
});

/** U-4: the decision details' checks, the failed checks first, and a part the server has no record of. */
describe('decision checks', () => {
  it('shows the bundle, the seal and its check, and the checks with the failed ones on top', () => {
    render(<VerifyParts quality={quality} />);
    expect(screen.getByText('v20.23')).toHaveAttribute('data-original');
    expect(screen.getByText('abcdef012345')).toBeInTheDocument();
    expect(screen.getByText(word('detail.verify.sealed'))).toBeInTheDocument();
    expect(screen.getByText('pkg-1')).toHaveAttribute('data-original');
    // The seal check: the package hash, the seal integrity row's counts, and the sentence only with no mismatch.
    const sealCheck = screen.getByRole('region', { name: word('detail.verify.sealCheck') });
    expect(within(sealCheck).getByText('sha256:aa11bb22')).toHaveAttribute('data-original');
    expect(sealCheck).toHaveTextContent(fill('detail.verify.sealCheckCounts', { matched: 4, mismatched: 0, unverifiable: 0 }));
    expect(sealCheck).toHaveTextContent(word('detail.verify.sealSame'));
    expect(screen.getByText(fill('detail.verify.inspected', { verdict: word('quality.verdict.FAIL') }))).toBeInTheDocument();
    const rows = Array.from(document.querySelectorAll('tbody > tr'), (row) => row.querySelector('th')?.firstChild?.textContent);
    expect(rows).toEqual([word('quality.check.FACT_ACCURACY'), word('quality.check.SEAL_INTEGRITY'), word('quality.check.REASON_MATCH')]);
    expect(document.querySelector('tbody > tr')).toHaveAttribute('data-failed');
    expect(screen.getByRole('list', { name: word('detail.verify.mismatches') })).toHaveTextContent('Wed 03:18');
  });

  it('names why the quality view is not there', () => {
    render(
      <VerifyParts
        quality={{ ...quality, available: false, reason: 'NOT_SEALED', seal: null, inspection: null, ribbon: null }}
      />,
    );
    expect(screen.getByText(word('factsReason.NOT_SEALED'))).toBeInTheDocument();
    expect(screen.getByText(word('detail.verify.sealNone'))).toBeInTheDocument();
  });

  it('never says the sealed text is the one sent when the seal check found a mismatch', () => {
    const broken: RunQuality = {
      ...quality,
      inspection: {
        verdict: 'FAIL',
        inspectorVersion: 'prompt-inspector-v2',
        inspectedAt: '2026-10-16T03:18:00Z',
        checks: [{ code: 'SEAL_INTEGRITY', matched: 3, mismatched: 1, unverifiable: 0, mismatches: [] }],
      },
    };
    render(<VerifyParts quality={broken} />);
    expect(screen.getByText(word('detail.verify.sealCheckFailed'))).toBeInTheDocument();
    expect(screen.queryByText(word('detail.verify.sealSame'))).not.toBeInTheDocument();
  });

  it('says so for every part the server has no record of', () => {
    render(<VerifyParts quality={null} />);
    expect(screen.getByText(word('detail.verify.bundleNone'))).toBeInTheDocument();
    expect(screen.getByText(word('detail.verify.sealCheckNone'))).toBeInTheDocument();
    expect(screen.getByText(word('detail.verify.sealNone'))).toBeInTheDocument();
    expect(screen.getByText(word('detail.verify.inspectionNone'))).toBeInTheDocument();
  });
});

/** U-2: the same case under the other bundle, offered only when the server found a measured run of it. */
describe('the same case under the other bundle', () => {
  const side = (runId: string, version: string, hash: string, selectionSource: string) => ({
    runId,
    stepNo: 1,
    bundle: { version, hash, selectionSource },
    userPrompt: `=== REQUEST ===\nTime: Wed 03:17 (${version})`,
    systemPromptLines: 106,
  });
  const view: OtherBundleView = {
    available: true,
    reason: null,
    current: side('run-a3', 'v20.23', 'abcdef0123456789', 'REGISTRY'),
    other: side('run-measured-v19', 'v19', '0123456789abcdef', 'CONFIG'),
  };

  it('shows each side under its bundle name, hash, selection source and run, and says it is not the same request', () => {
    render(<PromptCompare view={view} />);
    expect(screen.getByText(word('prompt.compare.lead'))).toBeInTheDocument();
    const current = screen.getByRole('region', { name: word('prompt.compare.current') });
    expect(current).toHaveTextContent('v20.23');
    expect(current).toHaveTextContent('abcdef012345');
    expect(current).toHaveTextContent('REGISTRY');
    expect(within(current).getByText('run-a3')).toHaveAttribute('data-original');
    expect(current).toHaveTextContent(fill('prompt.compare.systemLines', { n: 106 }));
    const other = screen.getByRole('region', { name: word('prompt.compare.other') });
    expect(other).toHaveTextContent('v19');
    expect(other).toHaveTextContent('0123456789ab');
    expect(other).toHaveTextContent('CONFIG');
    expect(within(other).getByText('run-measured-v19')).toHaveAttribute('data-original');
    expect(within(other).getByText(/Time: Wed 03:17 \(v19\)/)).toHaveAttribute('data-original');
  });

  it('is offered only when the server found the other bundle run', () => {
    expect(compareOffered(view)).toBe(true);
    for (const reason of ['NO_OTHER_BUNDLE_RUN', 'NOT_SEALED', 'NO_ENGINE', 'NO_STEP'] as const) {
      const missing: OtherBundleView = { available: false, reason, current: view.current, other: null };
      expect(compareOffered(missing), reason).toBe(false);
      const { container } = render(<PromptCompare view={missing} />);
      expect(container).toBeEmptyDOMElement();
    }
    expect(compareOffered(null)).toBe(false);
  });
});
