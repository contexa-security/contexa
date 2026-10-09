import { beforeAll, describe, expect, it } from 'vitest';
import i18n from '../../i18n';
import { CASES, companyClock, membership, modeOf, plainPath, plainValue, stepPath } from './experience';

beforeAll(async () => {
  await i18n.changeLanguage('ko');
});

/** The try's cases and the plain words of the recorded values (7.1, words slides); nothing here decides or counts. */
describe('try helpers', () => {
  it('sends the designed case of the decision mode and keeps the mode in the steps of the try', () => {
    expect(CASES.attacker).toEqual({ sync: 'A3', async: 'A3A' });
    expect(modeOf(new URLSearchParams('mode=async'))).toBe('async');
    expect(modeOf(new URLSearchParams(''))).toBe('sync');
    expect(stepPath('attacker', 'run', 'async')).toBe('/try/attacker/run?mode=async');
    expect(stepPath('attacker', 'run', 'sync')).toBe('/try/attacker/run');
  });

  it('names recorded values in the visitor words', () => {
    const t = i18n.t.bind(i18n);
    expect(plainValue(t, 'accessHour', '3')).toBe('3시');
    expect(plainValue(t, 'dayOfWeek', '3')).toBe('수');
    expect(plainValue(t, 'authenticationType', 'TOKEN')).toBe('토큰');
    expect(plainValue(t, 'actionFamily', 'WRITE')).toBe('쓰기');
    expect(plainValue(t, 'resourceFamily', 'CRITICAL')).toBe('최고');
    expect(plainValue(t, 'network', '10.40.12.0/24')).toBe('10.40.12.0/24');
    expect(plainValue(t, 'operatingSystem', 'WINDOWS')).toBe('Windows');
    expect(plainValue(t, 'operatingSystem', 'Windows')).toBe('Windows');
    expect(plainPath(t, '/api/projects/GB-500/exports/*')).toBe('GB-500 반출');
    expect(plainPath(t, '/api/documents/PLM-OPS-NTE-00284/download/*')).toBe('PLM-OPS 문서 내려받기');
    expect(plainPath(t, '/api/documents/PLM-OPS-SPC-00175')).toBe('PLM-OPS 문서 열람');
  });

  it("reads the engine's membership label and the company clock as recorded", () => {
    expect(membership('true')).toBe('same');
    expect(membership('false')).toBe('different');
    expect(membership('UNKNOWN - insufficient comparison evidence; do not infer')).toBe('unknown');
    expect(companyClock('2026-09-30T03:17:00Z', 'ko')).toBe('수요일 03:17');
    expect(companyClock('2026-09-30T03:17:00Z', 'en')).toBe('Wednesday 03:17');
  });
});
