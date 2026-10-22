import { describe, expect, it } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { inputLine } from './inputLine';

const KO: Readonly<Record<string, string>> = ko;

/** 4-3's engine input lines (IN-8): the portal's comparison key in plain words, every other input as it came. */
describe('an engine input line of 4-3', () => {
  it('names a comparison with the usual pattern by its dimension and its membership in words', async () => {
    await i18n.changeLanguage('ko');
    const t = i18n.t.bind(i18n);
    expect(inputLine(t, 'dim.device', 'Safari/18 on MAC · false')).toBe(
      `${KO['dim.device']}: Safari/18 on MAC · ${KO['dim.different']}`,
    );
    expect(inputLine(t, 'dim.size', '480 · true')).toBe(`${KO['dim.size']}: 480 · ${KO['dim.same']}`);
    expect(inputLine(t, 'dim.rate', 'UNKNOWN · UNKNOWN - no usual rate in the view')).toBe(
      `${KO['dim.rate']}: UNKNOWN · UNKNOWN - no usual rate in the view`,
    );
    expect(inputLine(t, 'dim.device', null)).toBe(`${KO['dim.device']}: -`);
  });

  it('keeps an input the engine received under its own label as it came', async () => {
    await i18n.changeLanguage('ko');
    const t = i18n.t.bind(i18n);
    expect(inputLine(t, 'ApprovalMissing', 'true')).toBe('ApprovalMissing: true');
    expect(inputLine(t, 'Sensitivity', null)).toBe('Sensitivity: -');
  });
});
