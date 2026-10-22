import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { LiveLayer } from '../../api/types';
import i18n from '../../i18n';
import { CompareStrip, Lane } from './consoleParts';

function lane(layer: LiveLayer, threat: boolean | null) {
  return render(
    <ul>
      <Lane control="D" sub="" threat={threat} layer={layer} />
    </ul>,
  );
}

describe("Contexa's lane without a decision of its own (FU-1)", () => {
  it('shows the refusal of a decision already in force as the result', async () => {
    await i18n.changeLanguage('ko');
    lane(
      { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 101, ruleId: 'ACCOUNT_BLOCKED' },
      true,
    );
    expect(screen.getByText(i18n.t('main.lane.stopped'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.lane.sent'))).toBeNull();
  });

  it('names a real user stopped that way a stopped piece of work', async () => {
    await i18n.changeLanguage('ko');
    lane(
      { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 40, ruleId: 'ACCOUNT_BLOCKED' },
      false,
    );
    expect(screen.getByText(i18n.t('main.lane.halted'))).toBeInTheDocument();
  });

  // Review before the guide videos (2026-10-21, V-05): a run with a condition changed has no set answer.
  it('names a lane of a run without a set answer by what it did, its bar neither a leak nor work passed', async () => {
    await i18n.changeLanguage('ko');
    const { container } = render(
      <ul>
        <Lane
          control="C2"
          sub=""
          threat={null}
          layer={{ outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 480, elapsedMs: 30, ruleId: null }}
        />
      </ul>,
    );
    expect(screen.getByText(i18n.t('main.lane.allowed'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('main.lane.through'))).toBeNull();
    expect(container.querySelector('[data-full]')).toHaveAttribute('data-tone', 'plain');
  });

  it('keeps waiting for the decision of a request the engine is still deciding', async () => {
    await i18n.changeLanguage('ko');
    lane({ outcome: 'STOPPED', httpStatus: 423, deliveredItems: 0, elapsedMs: 8000, ruleId: null }, true);
    expect(screen.getByText(i18n.t('main.lane.sent'))).toBeInTheDocument();
  });
});

describe('a count of one item', () => {
  it('reads in the singular in English and as it is in Korean', async () => {
    await i18n.changeLanguage('en');
    const { unmount } = lane(
      { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 1, elapsedMs: 30, ruleId: null },
      false,
    );
    expect(screen.getByText('1 item exported')).toBeInTheDocument();
    unmount();
    await i18n.changeLanguage('ko');
    lane({ outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 4831, elapsedMs: 30, ruleId: null }, false);
    expect(screen.getByText('4,831건 반출')).toBeInTheDocument();
  });
});

// Review before the guide videos (2026-10-21): the console's bars and its comparison at a glance.
describe('the bar of a request that let nothing out (B-03)', () => {
  it("leaves Contexa's bar empty with its words when it handed over nothing", async () => {
    await i18n.changeLanguage('ko');
    const { container } = render(
      <ul>
        <Lane
          control="D"
          sub=""
          threat
          layer={{ outcome: 'STOPPED', httpStatus: 401, deliveredItems: 0, elapsedMs: 16500, ruleId: null }}
          decision={{
            finalAction: 'CHALLENGE',
            proposedAction: 'CHALLENGE',
            unresolved: false,
            riskScore: 0.32,
            confidence: 0.82,
            applied: 'BEFORE_RESPONSE',
            reason: null,
            adverseLabels: [],
            adverseMet: 0,
            adverseChecked: 0,
            totalAnalysisMs: 16358,
            modelCalls: 2,
            promptTokens: 12780,
            completionTokens: 1025,
          }}
        />
      </ul>,
    );
    expect(container.querySelector('[data-full]')).toBeNull();
    expect(screen.getByText('16.4초 판단 → 0건')).toBeInTheDocument();
  });
});

// Review before the guide videos (2026-10-21, T-04): the deck names data that left an attack's leak, a normal export.
describe('the items a lane let out', () => {
  it("names them a leak for an attack and an export for normal work, in the deck's words", async () => {
    await i18n.changeLanguage('ko');
    const out = {
      outcome: 'DELIVERED',
      httpStatus: 200,
      deliveredItems: 480,
      elapsedMs: 20,
      ruleId: null,
    } as const;
    const { unmount } = render(
      <ul>
        <Lane control="A" sub="" threat layer={out} />
      </ul>,
    );
    expect(screen.getByText(i18n.t('main.lane.leaked', { items: '480', count: 480 }))).toBeInTheDocument();
    unmount();
    render(
      <ul>
        <Lane control="A" sub="" threat={false} layer={out} />
      </ul>,
    );
    expect(screen.getByText(i18n.t('main.lane.exported', { items: '480', count: 480 }))).toBeInTheDocument();
  });
});

describe('the comparison at a glance (V-10)', () => {
  const row = (dimension: string, inUsual: string) => ({ dimension, now: 'x', inUsual, labels: [] });

  it('names the items it could not compare this time beside the ones that differ', async () => {
    await i18n.changeLanguage('ko');
    render(
      <CompareStrip
        rows={[
          row('device', 'false'),
          row('size', 'false'),
          row('accessHour', 'true'),
          row('rate', 'UNKNOWN'),
        ]}
        departures={2}
      />,
    );
    expect(screen.getByText(i18n.t('main.facts.compared', { n: 4, d: 2, count: 2 }))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.facts.unknown', { names: i18n.t('dim.rate') }))).toBeInTheDocument();
  });

  it("states the portal's count of the items the engine compared (V-10)", async () => {
    await i18n.changeLanguage('ko');
    render(
      <CompareStrip
        rows={[
          row('device', 'false'),
          row('size', 'false'),
          row('accessHour', 'true'),
          row('rate', 'UNKNOWN'),
        ]}
        departures={2}
        compared={3}
      />,
    );
    expect(
      screen.getByText(i18n.t('main.facts.comparedOf', { n: 4, c: 3, d: 2, count: 2 })),
    ).toBeInTheDocument();
  });

  it('says plainly when no item differs from the usual', async () => {
    await i18n.changeLanguage('ko');
    render(<CompareStrip rows={[row('device', 'true'), row('accessHour', 'true')]} departures={0} />);
    expect(screen.getByText(i18n.t('main.facts.comparedNone', { n: 2 }))).toBeInTheDocument();
  });
});
