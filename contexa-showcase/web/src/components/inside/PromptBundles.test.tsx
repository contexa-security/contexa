import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import samples from '../../../../showcase-portal/src/test/resources/anatomy/v20-prompts.json';
import type { DecisionAnatomyView, ExchangeCall } from '../../api/anatomy';
import '../../i18n';
import i18n from '../../i18n';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { PromptBundles } from './PromptBundles';
import { BLOCKS, BUNDLES, countedCall, plainLinesOf, sectionsOf, shownBundles } from './promptSections';

type Lines = NonNullable<DecisionAnatomyView['promptLines']>;

function sample(caseKey: string) {
  const found = samples.samples.find((entry) => entry.case === caseKey);
  if (!found) {
    throw new Error(`no sample ${caseKey}`);
  }
  return found;
}

function callOf(caseKey: string): ExchangeCall {
  const found = sample(caseKey);
  return {
    callNo: found.callNo,
    model: found.model,
    systemPrompt: found.systemPrompt,
    userPrompt: found.userPrompt,
    answer: null,
    finishReason: null,
    providerResponse: null,
    maskedPlaces: 0,
    capturedAt: null,
  };
}

/**
 * The server's count of the A3 sample (a real v20 decision of control D, 2026-10-12): the portal's PromptLinesTest
 * holds the same numbers, counted apart by an independent script on the same text.
 */
const a3Lines: Lines = {
  layout: 'V20_BLOCKS',
  total: 157,
  system: 106,
  user: 51,
  systemPhysical: 118,
  userPhysical: 57,
  sections: [
    { name: 'USER BASELINE', bundle: 'USER_BASELINE', lines: 16 },
    { name: 'SESSION', bundle: 'SESSION', lines: 6 },
    { name: 'REQUEST', bundle: 'REQUEST', lines: 10 },
    { name: 'DECISION FACTS', bundle: 'DECISION_FACTS', lines: 12 },
    { name: 'PAST RECORDS (scope NO_COMPARABLE_EVIDENCE)', bundle: 'PAST_RECORDS', lines: 2 },
    { name: 'UNKNOWN', bundle: 'UNKNOWN', lines: 3 },
    { name: 'UNTRUSTED TEXT', bundle: 'UNTRUSTED_TEXT', lines: 2 },
  ],
  bundles: [
    { bundle: 'RULES', lines: 106 },
    { bundle: 'REQUEST', lines: 10 },
    { bundle: 'SESSION', lines: 6 },
    { bundle: 'USER_BASELINE', lines: 16 },
    { bundle: 'DECISION_FACTS', lines: 12 },
    { bundle: 'UNKNOWN', lines: 3 },
    { bundle: 'PAST_RECORDS', lines: 2 },
    { bundle: 'UNTRUSTED_TEXT', lines: 2 },
    { bundle: 'SECOND_PASS', lines: 0 },
    { bundle: 'OTHER', lines: 0 },
  ],
};

function blockLines(caseKey: string, header: string): readonly string[] {
  return sectionsOf(sample(caseKey).userPrompt).get(header) ?? [];
}

/** W3-10: the prompt screen reads a v20 prompt by its blocks (docs/showcase/프롬프트-최종-구현계획.md). */
describe('v20 prompt blocks', () => {
  it('cuts the stored text at the block headers the server counts, with the same lines', () => {
    const sections = sectionsOf(sample('A3').userPrompt);
    expect([...sections.keys()]).toEqual(a3Lines.sections.map((section) => section.name));
    for (const section of a3Lines.sections) {
      const content = (sections.get(section.name) ?? []).filter((line) => line.trim() !== '');
      expect(content, section.name).toHaveLength(section.lines);
    }
  });

  it('shows the blocks in the screen order, the second pass only when the prompt has one', () => {
    expect(shownBundles(a3Lines)).toEqual([
      'RULES',
      'REQUEST',
      'SESSION',
      'USER_BASELINE',
      'DECISION_FACTS',
      'UNKNOWN',
      'PAST_RECORDS',
      'UNTRUSTED_TEXT',
    ]);
    const secondPass: Lines = {
      ...a3Lines,
      bundles: a3Lines.bundles.map((entry) => (entry.bundle === 'SECOND_PASS' ? { ...entry, lines: 4 } : entry)),
    };
    expect(shownBundles(secondPass)).toEqual([...shownBundles(a3Lines), 'SECOND_PASS']);
    expect(shownBundles({ ...a3Lines, layout: 'V19_SECTIONS' })).toEqual(BUNDLES);
  });

  it('gives the plain words only to the v20 lines whose meaning they state', () => {
    const keys = (caseKey: string, block: (typeof BLOCKS)[number], header: string) =>
      plainLinesOf('V20_BLOCKS', block, blockLines(caseKey, header)).map((entry) => entry.key);
    expect(keys('A3', 'USER_BASELINE', 'USER BASELINE')).toEqual(['prompt.plain.baseline']);
    expect(keys('A3', 'REQUEST', 'REQUEST')).toEqual(['prompt.plain.roles']);
    expect(keys('A3', 'DECISION_FACTS', 'DECISION FACTS')).toEqual([
      'prompt.plain.approvalMissing',
      'prompt.plain.allowed',
    ]);
    // A3T holds an approval whose use outside the session is not known: no "no matching approval" note.
    expect(keys('A3T', 'DECISION_FACTS', 'DECISION FACTS')).toEqual(['prompt.plain.allowed']);
    const rules = plainLinesOf('V20_BLOCKS', 'RULES', sample('A3').systemPrompt.split('\n')).map((entry) => entry.key);
    expect(rules).toEqual([
      'gRules.plain.ALLOW',
      'gRules.plain.CHALLENGE',
      'gRules.plain.ESCALATE',
      'gRules.plain.BLOCK',
      'gRules.plain.elevated',
    ]);
  });

  it('reads a decision fact line by its label after the fact ID the line starts with (W3-13)', () => {
    const withIds = blockLines('A3', 'DECISION FACTS').map((line, index) =>
      line.trim() === '' || line.startsWith('=== ') ? line : `[F${index + 1}] ${line}`,
    );
    const noted = plainLinesOf('V20_BLOCKS', 'DECISION_FACTS', withIds);
    expect(noted.map((entry) => entry.key)).toEqual(['prompt.plain.approvalMissing', 'prompt.plain.allowed']);
    expect(noted.every((entry) => /^\[F\d+] /.test(entry.line))).toBe(true);
  });

  it('reads the call whose texts the server counted: the last one, where a second pass adds its block', () => {
    const first = callOf('A3');
    const second = { ...first, callNo: 2, userPrompt: `${first.userPrompt ?? ''}
=== SECOND PASS ===` };
    expect(countedCall([first, second])).toBe(second);
    expect(countedCall([first])).toBe(first);
    expect(countedCall([])).toBeNull();
  });

  it('names and describes every block in both languages', () => {
    const dictionaries: readonly Record<string, string>[] = [ko, en];
    for (const dictionary of dictionaries) {
      expect(dictionary['prompt.blocks']).toBeTruthy();
      for (const block of BLOCKS) {
        expect(dictionary[`prompt.block.${block}`], block).toBeTruthy();
        expect(dictionary[`prompt.blockWhat.${block}`], block).toBeTruthy();
      }
    }
  });

  it('opens the pressed block with its original lines and the server count', async () => {
    await i18n.changeLanguage('ko');
    render(<PromptBundles lines={a3Lines} call={callOf('A3')} />);
    const list = screen.getByRole('list', { name: ko['prompt.blocks'] });
    expect(list.querySelectorAll('button')).toHaveLength(8);
    expect(screen.getByRole('heading', { name: ko['prompt.block.DECISION_FACTS'] })).toBeInTheDocument();
    expect(screen.getByRole('list', { name: '원문 12줄' })).toBeInTheDocument();
    expect(screen.getByText(ko['prompt.plain.approvalMissing'])).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: new RegExp(ko['prompt.block.PAST_RECORDS']) }));
    expect(screen.getByRole('heading', { name: ko['prompt.block.PAST_RECORDS'] })).toBeInTheDocument();
    const original = screen.getByRole('list', { name: '원문 2줄' });
    expect(original).toHaveTextContent('PastRecordsState: not retrieved (TIMEOUT)');
  });
});
