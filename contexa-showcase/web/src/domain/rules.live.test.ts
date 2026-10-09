import { describe, expect, it } from 'vitest';
import type { RuleCasesView } from './rules';
import { DEFAULT_SETTINGS, recordRule, thresholdRule } from './rules';

/**
 * E-3 of the scene: with the published settings, the screen's formulas reproduce every decision the two rule
 * controls recorded in the real runs the portal serves. Runs only against a live portal:
 * RULES_CASES_URL=http://127.0.0.1:19180/api/rules/cases npx vitest run src/domain/rules.live.test.ts
 */
// Vitest exposes the process environment on import.meta.env.
const url = import.meta.env.RULES_CASES_URL as string | undefined;

describe.skipIf(!url)('the rule controls on the screen against the real runs', () => {
  it('reproduce every recorded decision and rule with the published settings', async () => {
    const response = await fetch(url ?? '');
    expect(response.status).toBe(200);
    const view = (await response.json()) as RuleCasesView;
    expect(view.cases.length).toBeGreaterThan(0);
    const mismatches: string[] = [];
    let steps = 0;
    for (const rule of view.cases) {
      for (const step of rule.steps) {
        steps += 1;
        const c1 = thresholdRule(step, DEFAULT_SETTINGS);
        const c2 = recordRule(step, DEFAULT_SETTINGS);
        if (c1.rule !== step.c1Rule || c1.allowed !== (step.c1Outcome === 'DELIVERED')) {
          mismatches.push(`${rule.scenario}#${step.stepNo} C1 ${step.c1Outcome}/${step.c1Rule} -> ${c1.rule}`);
        }
        if (c2.rule !== step.c2Rule || c2.allowed !== (step.c2Outcome === 'DELIVERED')) {
          mismatches.push(`${rule.scenario}#${step.stepNo} C2 ${step.c2Outcome}/${step.c2Rule} -> ${c2.rule}`);
        }
      }
    }
    expect(steps).toBeGreaterThan(0);
    expect(mismatches).toEqual([]);
  });
});
