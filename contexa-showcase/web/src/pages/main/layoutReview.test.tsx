import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LabRequest } from '../../api/lab';
import { MainScreen } from '../../components/main/MainScreen';
import i18n from '../../i18n';
import { CheckCounts } from './CheckCounts';
import { riskText } from './consoleData';
import { Lane } from './consoleParts';
import { Hypotheses } from './Hypotheses';
import { readsAgain } from './mainCases';
import { CheckRecord } from './RequestSteps';

/*
 * Review before the guide videos (2026-10-21, 10절 L): the alignment, spacing and contrast of the main-flow screens
 * filmed at 1440 px. jsdom lays nothing out, so the stylesheets' rules are read where the fix is a rule.
 */
const files = await vi.importActual<{ readFileSync: (path: string, encoding: 'utf-8') => string }>('node:fs');
const sheet = (name: string) => files.readFileSync(`src/pages/main/${name}`, 'utf-8').replace(/\r\n/g, '\n');

/** The declarations of one rule of a stylesheet, by its exact selector. */
function rule(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const found = new RegExp(`(?:^|\\n)${escaped} \\{([^}]*)\\}`).exec(css)?.[1];
  if (found === undefined) {
    throw new Error(`missing ${selector}`);
  }
  return found;
}

const console_ = sheet('ConsolePage.module.css');
const evidence = sheet('EvidencePages.module.css');
const proof = sheet('ProofPanel.module.css');
const check = sheet('CheckPage.module.css');

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubFetch(bodies: Readonly<Record<string, unknown>>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
}

function wrap(node: ReactNode, path = '/attack/console') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={node} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// L-02: the fixed-width font spaces Korean words wide apart ("480건  유출", "가장  그럴듯함", "(세계  표준시)"); words and
// numbers take the body font with even digits, and only codes, IDs and raw lines stay fixed-width.
describe('Korean words on 2-2, 2-3, 3-1 and 3-3 (L-02)', () => {
  it('are set in the body font with even digits wherever a line mixes words and numbers', () => {
    for (const [css, selector] of [
      [console_, '.fillLabel'],
      [console_, '.laneMeta'],
      [console_, '.riskValue'],
      [console_, '.riskNote'],
      [proof, '.barValue'],
      [proof, '.sealTime'],
      [proof, '.ledgerValue'],
      [evidence, '.callBadge'],
      [evidence, '.sealLine'],
      [evidence, '.sealTime'],
      [evidence, '.stageRawLabel'],
    ] as const) {
      const declarations = rule(css, selector);
      expect(declarations, selector).not.toContain('--font-mono');
      expect(declarations, selector).toMatch(/font-variant-numeric: tabular-nums;|font-family: var\(--font-sans\);/);
    }
    // A model name is a code and keeps the fixed-width font.
    expect(rule(evidence, ".callBadge[data-code]")).toContain('--font-mono');
  });
});

// L-04: a card stretched to its neighbour's height left most of it empty (3-2's input cards), or a short card left a
// hole beside two tall ones (2-3's learning card).
describe('card heights on 2-3 and 3-2 (L-04)', () => {
  it('keeps the input cards of 3-2 as tall as their words', () => {
    expect(rule(evidence, '.sources')).toContain('align-content: start;');
  });

  it('lays the learning card of 2-3 across the whole row under the two tall cards', () => {
    expect(rule(proof, '.grid')).toContain('grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr);');
    expect(rule(proof, '.card[data-row]')).toContain('grid-column: 1 / -1;');
  });
});

// L-30: while the decision is made the footer said "판단이 끝나면 다음으로" twice and its button grew a second line, and the
// risk score showed only "…".
describe('the console while Contexa decides (L-30)', () => {
  it('says what the waiting button waits for once, beside a one-line button', () => {
    stubFetch({});
    wrap(
      <MainScreen
        title="2-2"
        waiting={{ label: i18n.t('main.console.deciding'), hint: i18n.t('main.console.decidingHint') }}
        nextNote={i18n.t('main.console.decidingHint')}
      >
        {null}
      </MainScreen>,
    );
    expect(screen.getAllByText(i18n.t('main.console.decidingHint'))).toHaveLength(1);
    const button = document.querySelector('[data-zone="actions"] [data-main]');
    expect(button).toHaveTextContent(i18n.t('main.console.deciding'));
    expect(button).not.toHaveTextContent(i18n.t('main.console.decidingHint'));
  });

  it('names the risk score as being decided instead of a placeholder', () => {
    const t = i18n.t.bind(i18n);
    expect(riskText(t, null, false)).toBe(t('main.lane.deciding'));
    expect(riskText(t, 0.32, false)).toBe('0.32');
    expect(riskText(t, null, true)).toBe('—');
  });
});

// L-34: every count of the inspector was green, "could not be checked" too, and the explanations' assessments looked
// alike.
describe('the checks and the explanations on 3-3 (L-34)', () => {
  it('greens only what matched; what could not be checked reads quietly and a mismatch red', () => {
    const { rerender } = render(<CheckCounts matched={17} mismatched={0} unverifiable={2} />);
    expect(screen.getByText('17건 일치')).toHaveAttribute('data-tone', 'ok');
    expect(screen.getByText('불일치 0')).toHaveAttribute('data-tone', 'quiet');
    expect(screen.getByText('확인 불가 2')).toHaveAttribute('data-tone', 'unknown');
    rerender(<CheckCounts matched={16} mismatched={1} unverifiable={0} />);
    expect(screen.getByText('불일치 1')).toHaveAttribute('data-tone', 'bad');
  });

  it('marks each assessment by its strength', () => {
    render(
      <Hypotheses
        hypotheses={[
          { id: 'H1', name: null, assessment: 'MOST_LIKELY', for: [], against: [] },
          { id: 'H2', name: null, assessment: 'POSSIBLE', for: [], against: [] },
          { id: 'H3', name: null, assessment: 'UNLIKELY', for: [], against: [] },
        ]}
        facts={null}
      />,
    );
    for (const level of ['MOST_LIKELY', 'POSSIBLE', 'UNLIKELY']) {
      expect(screen.getByText(i18n.t(`hypothesis.assessment.${level}`))).toHaveAttribute('data-level', level);
    }
  });
});

/** The real user's three requests on 4-4 (S14): two drawings of HX-310 and an export of twelve items. */
const S14_REQUESTS: readonly LabRequest[] = [
  {
    operation: 'DOCUMENT_READ',
    project: null,
    document: { project: 'HX-310', type: 'DRAWING', position: 5, fact: null },
    target: 'ASSIGNED',
    customer: null,
    items: null,
    claimedTicket: null,
    visitorSends: false,
  },
  {
    operation: 'DOCUMENT_READ',
    project: null,
    document: { project: 'HX-310', type: 'DRAWING', position: 6, fact: null },
    target: 'ASSIGNED',
    customer: null,
    items: null,
    claimedTicket: null,
    visitorSends: false,
  },
  {
    operation: 'EXPORT',
    project: 'HX-310',
    document: null,
    target: 'ASSIGNED',
    customer: null,
    items: 12,
    claimedTicket: null,
    visitorSends: false,
  },
];

const CHECK_RUN = 'run-b9b8c11c8759';

// L-36: requests 1 and 2 had the same name, the finished screen kept nothing of the extra check, and request 3's chips
// wrapped differently from the other two.
describe('the real user checked on the way (4-4, L-36)', () => {
  it('names the second drawing as another one', () => {
    expect(S14_REQUESTS.map((_, index) => readsAgain(S14_REQUESTS, index))).toEqual([false, true, false]);
  });

  it('keeps the extra check as the run recorded it once the run is over', async () => {
    stubFetch({
      [`/api/runs/${CHECK_RUN}/steps/2/anatomy`]: {
        runId: CHECK_RUN,
        stepNo: 2,
        recovery: {
          challenge: {
            answered: true,
            reason: null,
            challenged_at: '2026-10-20T23:32:27.780642Z',
            code_requested_at: '2026-10-20T23:32:28.135794Z',
            verified_at: '2026-10-20T23:32:30.246258Z',
            reissue_sent_at: '2026-10-20T23:32:30.246258Z',
            reissue_outcome: 'DELIVERED',
            reissue_status: 200,
            reissue_delivered: 1,
            reissue_elapsed_ms: 54,
          },
          release: null,
        },
      },
    });
    wrap(
      <div>
        <CheckRecord runId={CHECK_RUN} stepNo={1} />
        <CheckRecord runId={CHECK_RUN} stepNo={2} />
      </div>,
      '/normal/check',
    );
    expect(await screen.findByText(i18n.t('main.4-4.record', { n: 2 }))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.recovery.asked'))).toBeInTheDocument();
    expect(screen.getByText('23:32:27')).toBeInTheDocument();
    expect(screen.getByText('23:32:30', { selector: '[data-step="check"] *' })).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.4-4.record', { n: 1 }))).toBeNull();
  });

  it('sets the four existing approaches of every request in the same two columns', () => {
    expect(rule(check, '.existing')).toContain('grid-template-columns: repeat(2, minmax(0, 1fr));');
  });
});

// L-38 (7-2): before the send the right half held one grey line; the five lanes now wait there, each "not sent".
describe('the lanes before a send (7-2, L-38)', () => {
  it('reads as not sent yet, not as sent', () => {
    render(
      <ul>
        <Lane control="A" sub="" layer={null} threat={null} idle />
        <Lane control="D" sub="" layer={null} threat={null} idle holding />
      </ul>,
    );
    expect(screen.getAllByText(i18n.t('main.4-4.notYet'))).toHaveLength(2);
    expect(screen.queryByText(i18n.t('main.lane.sent'))).toBeNull();
    expect(screen.queryByText(i18n.t('main.lane.holding'))).toBeNull();
  });
});
