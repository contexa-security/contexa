import { render, screen } from '@testing-library/react';
import { beforeAll, describe, expect, it } from 'vitest';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { count, seconds } from '../../../journey/format';
import { LAB_BAR_WORDS } from '../../lab/labPlace';
import { required } from '../../../test/required';
import { Bar } from './LiveRunBar';
import { verdictKey } from './liveRun';

const KO: Readonly<Record<string, string>> = ko;

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return Object.entries(values).reduce(
    (text, [name, value]) => text.replaceAll(`{{${name}}}`, value),
    required(KO[key], key),
  );
}

const CUT = {
  outcome: 'CUT',
  httpStatus: 200,
  deliveredItems: 744,
  elapsedMs: 5800,
  ruleId: 'ENGINE_CUT',
} as const;

// 판정층 8절 9: a block of Contexa cuts a streamed export while it is sent; the bar says where it stopped.
describe('the live bar of a streamed export', () => {
  beforeAll(async () => {
    await i18n.changeLanguage('ko');
  });

  it("names where Contexa's block cut the stream, after its judgment", () => {
    render(
      <ul>
        <Bar
          control="D"
          layer={CUT}
          axis={37000}
          held={false}
          verdict="BLOCK"
          stream={{ total: 4831, delivered: 740, atMs: 5700 }}
        />
      </ul>,
    );
    const decided = fill('e1.run.decided', {
      seconds: seconds(5800),
      verdict: required(KO[verdictKey('BLOCK')], 'BLOCK'),
    });
    expect(
      screen.getByText(
        `${decided} · ${fill('p1.run.cutAtOf', { items: count(744, 'ko'), total: count(4831, 'ko') })}`,
      ),
    ).toBeInTheDocument();
  });

  it('names the cut by its items alone when the export did not say its total', () => {
    render(
      <ul>
        <Bar control="D" layer={CUT} axis={37000} held={false} verdict={null} />
      </ul>,
    );
    expect(screen.getByText(fill('p1.run.cutAt', { items: count(744, 'ko') }))).toBeInTheDocument();
  });

  it('draws a stream still read as far as its items got, not as a full bar', () => {
    const { container } = render(
      <ul>
        <Bar
          control="A"
          layer={null}
          axis={9000}
          held={false}
          verdict={null}
          stream={{ total: 4831, delivered: 1057, atMs: 9000 }}
        />
      </ul>,
    );
    expect(container.querySelector<HTMLElement>('[data-outcome]')?.style.width).toBe('22%');
  });

  // B-07: while Contexa's AI judges a streamed export, the export keeps going; the lab says so with the seconds.
  it("says Contexa's AI is still judging while the stream keeps going, in the lab's words", () => {
    render(
      <ul>
        <Bar
          control="D"
          layer={null}
          axis={9000}
          held={false}
          verdict={null}
          deciding
          words={LAB_BAR_WORDS}
          stream={{ total: 4831, delivered: 1089, atMs: 9000 }}
        />
      </ul>,
    );
    expect(
      screen.getByText(
        fill('lab.r7.run.judgingStream', {
          seconds: '9.0',
          items: count(1089, 'ko'),
          total: count(4831, 'ko'),
        }),
      ),
    ).toBeInTheDocument();
  });

  // B-07, T-01: the cut is the moment the lab shows; it reads as the result chip "partly out, then blocked".
  it('names a cut by the result chip and marks it, in the lab', () => {
    const { container } = render(
      <ul>
        <Bar
          control="D"
          layer={CUT}
          axis={37000}
          held={false}
          verdict="BLOCK"
          words={LAB_BAR_WORDS}
          stream={{ total: 4831, delivered: 740, atMs: 5700 }}
        />
      </ul>,
    );
    expect(
      screen.getByText(
        fill('lab.r7.run.cutAtOf', {
          seconds: seconds(5800),
          items: count(744, 'ko'),
          total: count(4831, 'ko'),
        }),
      ),
    ).toBeInTheDocument();
    expect(container.querySelector('[data-control="D"]')).toHaveAttribute('data-cut', 'true');
  });

  // T-01: an existing approach's refusal is "blocked" in the lab, as the result chips say, never "denied".
  it("names an approach's refusal by the result chip in the lab", () => {
    render(
      <ul>
        <Bar
          control="C1"
          layer={{ outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 20 }}
          axis={37000}
          held={false}
          verdict={null}
          words={LAB_BAR_WORDS}
        />
      </ul>,
    );
    expect(screen.getByText(fill('lab.r7.run.denied', { seconds: '0.02' }))).toBeInTheDocument();
    expect(screen.queryByText(fill('e1.run.denied', { seconds: '0.02' }))).not.toBeInTheDocument();
  });

  it('shows how many items have left while a stream is still read', () => {
    render(
      <ul>
        <Bar
          control="A"
          layer={null}
          axis={12000}
          held={false}
          verdict={null}
          stream={{ total: 4831, delivered: 1520, atMs: 12000 }}
        />
      </ul>,
    );
    expect(
      screen.getByText(fill('p1.run.streamingOf', { items: count(1520, 'ko'), total: count(4831, 'ko') })),
    ).toBeInTheDocument();
  });
});
