import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, describe, expect, it } from 'vitest';
import type { BeforeSendView, UsualVsNow } from '../../api/anatomy';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { Comparison } from './Comparison';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

function row(dimension: string, now: string, inUsual: 'true' | 'false'): UsualVsNow {
  const labels = [inUsual === 'false' ? 'DeviationsFromBaseline' : 'SameAsBaseline'];
  return { dimension, now, inUsual, labels };
}

/**
 * N-DEP-1 and N-DEP-2 (W7-12 C-2, C-5): the comparison of a v20 step as the portal gives it (BeforeSend,
 * from the anatomy): step 1 of the representative attack run-3766bd77c869 (portal test resource
 * anatomy/v20-deviations.json), whose seal states 4 of 10 compared as different and its company policy as
 * not met. The usual of each dimension is the BaselineView the engine sealed, one value per item; the
 * company facts are the run's stored business lookup.
 */
const hour = row('accessHour', '03', 'false');
const target = row('target', 'projectKey', 'false');
const resourceClass = row('resourceFamily', 'CRITICAL', 'false');
const size = row('size', '4,831 items', 'false');
const comparison: BeforeSendView = {
  runId: 'run-3766bd77c869',
  stepNo: 1,
  startedAt: null,
  companyTime: null,
  usualVsNow: [
    hour,
    row('dayOfWeek', 'Wed', 'true'),
    row('network', '10.40.12.0/24', 'true'),
    row('device', 'Chrome/140 on WINDOWS', 'true'),
    row('authenticationType', 'PASSWORD+ONE_TIME_CODE', 'true'),
    target,
    row('actionFamily', 'EXPORT', 'true'),
    resourceClass,
    size,
    row('rate', '1 requests in the last 60 min', 'true'),
  ],
  usual: {
    accessHour: { label: 'UsualHours', values: ['10', '11', '13', '14', '17'] },
    dayOfWeek: { label: 'UsualDays', values: ['1', '2', '3', '4', '5'] },
    network: { label: 'UsualNetworks', values: ['10.40.12.0/24'] },
    device: { label: 'UsualDevices', values: ['Chrome/140 on WINDOWS'] },
    authenticationType: { label: 'UsualLoginMethods', values: ['PASSWORD', 'PASSWORD+ONE_TIME_CODE'] },
    target: { label: 'UsualTargets', values: ['projectKey=PLM-OPS'] },
    actionFamily: { label: 'UsualActions', values: ['READ', 'EXPORT'] },
    resourceFamily: { label: 'UsualResourceClass', values: ['NORMAL'] },
    size: { label: 'UsualExportSize', values: ['29'] },
    rate: { label: 'UsualRequestRate', values: ['1'] },
  },
  departures: [hour, target, resourceClass, size],
  departureCount: 4,
  companyAdverse: [
    {
      label: 'policysatisfied',
      condition: 'NOT_SATISFIED',
      values: ['no — no approval for GB-500'],
      met: true,
    },
  ],
  companyAdverseCount: 1,
  company: { approvalRequired: true, approvalMissing: true },
  companyFacts: [],
  businessFacts: [
    { code: 'NOT_ASSIGNED', value: 'GB-500' },
    { code: 'NO_APPROVAL', value: null },
    { code: 'NO_TICKET', value: null },
    { code: 'NOT_ON_CALL', value: null },
    { code: 'ACCESS_DAYS_LAST_30', value: '0' },
    { code: 'ITEMS', value: '4831' },
    { code: 'NETWORK_OFFICE', value: null },
  ],
  sensitivity: 'CRITICAL',
  boundary: null,
  minimumRules: null,
};

beforeAll(async () => {
  await i18n.changeLanguage('ko');
});

/** The cells of one difference: its name, the usual and now with their labels (the arrow is an icon). */
function cells(item: HTMLElement): readonly (string | null)[] {
  return Array.from(item.children)
    .filter((child) => child.tagName === 'SPAN')
    .map((child) => child.textContent);
}

/** The names the screen check allows in English (e2e/screenCheck.mjs, D-29). */
const ALLOWED = (
  'contexa waf spring security chrome windows mac safari cloudflare turnstile plm-ops gb-500 ' +
  'hx administrator run protocol gb pm pc ai db sha'
).split(' ');

/** English words outside the originals, as the screen check counts them (e2e/screenCheck.mjs, C-5). */
function english(container: HTMLElement): readonly string[] {
  const clone = container.cloneNode(true) as HTMLElement;
  clone.querySelectorAll('[data-original]').forEach((element) => element.remove());
  return (clone.textContent?.match(/[A-Za-z][A-Za-z/-]{2,}/g) ?? []).filter(
    (found) => !ALLOWED.includes(found.replace(/[/-]+$/, '').toLowerCase()),
  );
}

describe('comparison with the usual', () => {
  it('lists the differences of a v20 seal in plain words, originals one press away (N-DEP-1)', async () => {
    const targetName = word('dim.target');
    const usual = word('e1.compare.usual');
    const now = word('e1.compare.now');
    const original = word('source.original');
    const hours = ['10', '11', '13', '14', '17']
      .map((value) => fill('dim.hours', { hours: value }))
      .join(' · ');
    const expected = [
      [word('dim.accessHour'), `${usual}${hours}`, `${now}${fill('dim.hours', { hours: '03' })}${original}`],
      [
        targetName,
        `${usual}${fill('dim.target.projectKey', { value: 'PLM-OPS' })}`,
        `${now}${word('dim.targetKind.projectKey')}${original}`,
      ],
      [
        word('dim.resourceFamily'),
        `${usual}${word('dim.sensitivity.NORMAL')}`,
        `${now}${word('dim.sensitivity.CRITICAL')}${original}`,
      ],
      [
        word('dim.size'),
        `${usual}${fill('dim.items.upTo', { n: '29' })}`,
        `${now}${fill('dim.items', { n: '4,831' })}${original}`,
      ],
    ];
    const { container } = render(<Comparison comparison={comparison} level="h2" />);

    const heading = screen.getByRole('heading', { name: fill('e1.compare.differentTitle', { n: 4 }) });
    const differences = required(heading.parentElement?.querySelector<HTMLElement>('ul'), 'the differences');
    const items = within(differences).getAllByRole('listitem');
    expect(items.map(cells)).toEqual(expected);
    expect(english(container)).toEqual([]);

    const first = required(items[0], 'the hour');
    await userEvent.click(within(first).getByRole('button', { name: original }));
    expect(required(first.querySelector('[data-original]'), 'the original').textContent).toBe(
      'DeviationsFromBaseline · 03 | UsualHours · 10, 11, 13, 14, 17',
    );
  });

  it('names the rest in plain words and flags the policy a v20 seal states as not met (N-DEP-2)', () => {
    const rest = ['dim.dayOfWeek', 'dim.network', 'dim.device', 'dim.authenticationType', 'dim.actionFamily'];
    const names = [...rest, 'dim.rate'].map(word).join(' · ');
    const login = `${word('dim.auth.PASSWORD')}+${word('dim.auth.ONE_TIME_CODE')}`;
    render(<Comparison comparison={comparison} level="h2" />);

    expect(screen.getByText(fill('e1.compare.rest', { names }))).toBeInTheDocument();
    for (const text of [
      word('dim.day.Wed'),
      `Chrome/140 · ${word('dim.os.WINDOWS')}`,
      login,
      fill('dim.rate.recent', { n: '1', minutes: '60' }),
    ]) {
      expect(screen.getByText(text)).toBeInTheDocument();
    }
    const company = screen.getByRole('heading', { name: fill('e1.compare.companyTitle', { n: 1 }) });
    const flags = required(company.parentElement?.querySelector<HTMLElement>('ul'), 'the flags');
    const flagged = within(flags).getAllByRole('listitem');
    expect(flagged).toHaveLength(1);
    expect(flagged[0]).toHaveTextContent(word('prompt.plain.approvalMissing'));
  });
});
