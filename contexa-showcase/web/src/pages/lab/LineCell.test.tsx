import { render } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { BeforeSendView } from '../../api/anatomy';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { LineCell } from './LineCell';

const WORDS: Readonly<Record<string, string>> = ko;

/** The words of a dictionary key the cell shows; a key the dictionary lacks fails here. */
function word(key: string): string {
  expect(WORDS[key]?.trim(), key).toBeTruthy();
  return WORDS[key] ?? '';
}

/** The rule lines of the v20.23 system text the demo's engine sends (its lines 19 to 21), and their reason codes. */
const LINES: readonly string[] = [
  'P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained. Floor: CHALLENGE.',
  'P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT: Action is EXPORT, ResourceClass is SENSITIVE or CRITICAL, and DeviationsFromBaseline names the device or the network as unexplained. Floor: CHALLENGE.',
  'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: ESCALATE (a verified user does not supply the missing record).',
];
const P3_CHALLENGE = 'P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: CHALLENGE.';
const CODES = [
  'MIN_P1_IDENTITY_DEVIATION',
  'MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT',
  'MIN_P3_POLICY_NOT_SATISFIED',
];

type MinimumRules = NonNullable<BeforeSendView['minimumRules']>;

/** The rules as the portal gives them: each line with its floor and the engine's finding, and the engine's verdict. */
function minimumRules(
  met: readonly (boolean | null)[],
  applies: boolean | null,
  lines: readonly string[] = LINES,
): MinimumRules {
  return {
    rules: lines.map((line, index) => ({
      code: CODES[index] ?? '',
      line,
      floor: /Floor: ([A-Z]+)/.exec(line)?.[1] ?? null,
      met: met[index] ?? null,
    })),
    applies,
  };
}

function view(line: Pick<BeforeSendView, 'boundary' | 'minimumRules'>): BeforeSendView {
  return {
    runId: 'run-a',
    stepNo: 1,
    startedAt: null,
    companyTime: null,
    usualVsNow: [],
    usual: {},
    departures: [],
    departureCount: 0,
    companyAdverse: [],
    companyAdverseCount: 0,
    company: {},
    companyFacts: [],
    businessFacts: [],
    sensitivity: 'CRITICAL',
    ...line,
  };
}

/** What the cell shows: its states (before and now, or now) and its condition rows with their marks. */
function shown(container: HTMLElement) {
  return {
    states: Array.from(container.querySelectorAll('p > span'), (span) => span.textContent),
    rows: Array.from(container.querySelectorAll('li'), (row) => ({
      text: row.textContent,
      met: row.hasAttribute('data-met'),
    })),
  };
}

const BOUNDARY = { sensitive: true, established: null, departs: true, approvalMissing: true, applies: null };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('the cell of the lines the rules always keep, before sending (N-K5-1)', () => {
  it('lists the minimum action rules of a v20 input with the engine findings, in the words of their lines', () => {
    const now = view({ boundary: null, minimumRules: minimumRules([false, false, true], true) });
    const { container } = render(<LineCell designed={null} now={now} changed={false} />);

    expect(shown(container)).toEqual({
      states: [word('labBefore.line.applies')],
      rows: [
        { text: word('gRules.plain.minP1'), met: false },
        { text: word('gRules.plain.minP2'), met: false },
        { text: word('gRules.plain.minP3'), met: true },
      ],
    });
  });

  it('shows a rule of other settings by its line as sent', () => {
    const lines = [LINES[0] ?? '', LINES[1] ?? '', P3_CHALLENGE];
    const now = view({ boundary: null, minimumRules: minimumRules([false, false, true], true, lines) });
    const { container } = render(<LineCell designed={null} now={now} changed={false} />);

    expect(shown(container).rows.map((row) => row.text)).toEqual([
      word('gRules.plain.minP1'),
      word('gRules.plain.minP2'),
      P3_CHALLENGE,
    ]);
  });

  it('says no line applies when the engine found no rule met, and unknown without its record', () => {
    const designed = view({ boundary: null, minimumRules: minimumRules([false, false, false], false) });
    const now = view({ boundary: null, minimumRules: minimumRules([null, null, null], null) });
    const { container } = render(<LineCell designed={designed} now={now} changed />);

    expect(shown(container).states).toEqual([word('labBefore.line.clear'), word('labBefore.line.unknown')]);
    expect(shown(container).rows.map((row) => row.met)).toEqual([false, false, false]);
  });

  it('compares an input without minimum action rules with a v20 one by the line each states', () => {
    const designed = view({
      boundary: { ...BOUNDARY, established: true, applies: true },
      minimumRules: null,
    });
    const now = view({ boundary: null, minimumRules: minimumRules([false, false, false], false) });
    const { container } = render(<LineCell designed={designed} now={now} changed />);

    expect(shown(container).states).toEqual([word('labBefore.line.applies'), word('labBefore.line.clear')]);
  });

  it('keeps the four boundary conditions of an input without minimum action rules', () => {
    const now = view({
      boundary: { ...BOUNDARY, approvalMissing: false, applies: false },
      minimumRules: null,
    });
    const { container } = render(<LineCell designed={null} now={now} changed={false} />);

    expect(shown(container)).toEqual({
      states: [word('labBefore.line.clear')],
      rows: [
        { text: word('labBefore.condition.sensitive'), met: true },
        { text: word('labBefore.condition.established'), met: false },
        { text: word('labBefore.condition.departs'), met: true },
        { text: word('labBefore.condition.approvalMissing'), met: false },
      ],
    });
  });
});
