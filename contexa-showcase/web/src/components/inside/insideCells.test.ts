import { describe, expect, it } from 'vitest';
import type { AnalysisStage } from '../../api/types';
import { analysedCells } from './insideCells';

const stage = (type: string): AnalysisStage => ({
  type,
  atMs: null,
  action: null,
  layer: null,
  riskScore: null,
  confidence: null,
  elapsedMs: null,
  mitre: null,
});

/** The panel's cells light up only as far as the engine's own events of the request go (panel slide, C-12). */
describe('analysed cells', () => {
  it('waits for the engine before the request reached it', () => {
    expect(analysedCells(null, false)).toEqual({
      request: 'active',
      usual: 'waiting',
      company: 'waiting',
      history: 'waiting',
      prompt: 'waiting',
      judgement: 'waiting',
      decision: 'waiting',
    });
  });

  it('follows the events in order and lights the decision cell only with the decision itself', () => {
    expect(analysedCells([], false).usual).toBe('active');
    const collected = analysedCells([stage('CONTEXT_COLLECTED')], false);
    expect([collected.history, collected.prompt, collected.judgement]).toEqual(['done', 'active', 'waiting']);
    const judging = analysedCells([stage('CONTEXT_COLLECTED'), stage('LAYER1_START')], false);
    expect([judging.prompt, judging.judgement, judging.decision]).toEqual(['done', 'active', 'waiting']);
    const applied = [
      stage('CONTEXT_COLLECTED'),
      stage('LAYER1_START'),
      stage('LAYER1_COMPLETE'),
      stage('DECISION_APPLIED'),
    ];
    expect(analysedCells(applied, false).decision).toBe('active');
    expect(analysedCells(applied, true)).toMatchObject({ judgement: 'done', decision: 'decision' });
  });

  it('closes the judgement on an analysis error without a decision', () => {
    const failed = analysedCells(
      [stage('CONTEXT_COLLECTED'), stage('LAYER1_START'), stage('ANALYSIS_ERROR')],
      false,
    );
    expect([failed.judgement, failed.decision]).toEqual(['done', 'active']);
  });
});
