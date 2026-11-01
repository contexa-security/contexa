import { useQuery } from '@tanstack/react-query';
import { getJson } from '../../api/http';
import { formatNumber } from '../format';

/**
 * The public result bundle of the standard benchmarks (DEC-7, DEC-48, DEC-54): written by `contexa-benchmark/bench/
 * publish_bundle.py` from the pinned report files and served as a static file. The screens read it and count nothing.
 */
export const BUNDLE_PATH = '/data/benchmarks/bundle-v1.json';
export const BUNDLE_FORMAT = 'contexa-benchmark-bundle/1';

export interface Words {
  readonly ko: string;
  readonly en: string;
}

/** k of n with its 95% interval; `derived` names a value no report file held (DEC-54). */
export interface BenchShare {
  readonly k: number;
  readonly n: number;
  readonly rate: number;
  readonly low: number | null;
  readonly high: number | null;
  readonly upper95: number | null;
  readonly method: 'clopper-pearson' | 'wilson' | null;
  readonly derived?: { readonly kind: 'by-construction' | 'computed'; readonly from: string };
}

/** The same cases with and without protection: how many held only without it, only with it, and McNemar's exact p. */
export interface BenchPaired {
  readonly cases: number;
  readonly onlyUnprotected: number;
  readonly onlyProtected: number;
  readonly p: number;
}

/** The warm-state run against the cold-state run on the same pairs: neither side is unprotected. */
export interface WarmPaired {
  readonly cases: number;
  readonly onlyWarm: number;
  readonly onlyCold: number;
  readonly p: number;
}

export interface BenchTest {
  readonly id: string;
  readonly label: Words;
  readonly note: Words;
  readonly freeze: string;
  readonly metric: string;
  readonly direction: 'lower' | 'higher';
  readonly matrix: boolean;
  readonly unprotected: BenchShare | null;
  readonly protected: BenchShare | null;
  readonly executedOnly: BenchShare | null;
  readonly paired: BenchPaired | null;
  readonly sample: number;
  readonly weakVariants?: number;
}

export interface BenchImpact {
  readonly test: string;
  readonly metric: string;
  readonly direction: 'lower' | 'higher';
  readonly overview: boolean;
  readonly own?: boolean;
  readonly unprotected: BenchShare | null;
  readonly protected: BenchShare | null;
  readonly paired: BenchPaired | null;
}

export interface BenchCost {
  readonly label: Words;
  readonly usd: number;
  /** The judgement document's line the figure stands on, and the name the screens give it (PC-9). */
  readonly source: string;
  readonly sourceLabel: Words;
}

interface BenchmarkBase {
  readonly name: string;
  readonly version: string;
  readonly title: Words;
  readonly description: Words;
  readonly tests: readonly BenchTest[];
  readonly impact: readonly BenchImpact[];
  readonly cost: readonly BenchCost[];
  readonly limits: readonly string[];
}

export interface AgentDojoEnvironment {
  readonly suite: string;
  readonly unprotected: BenchShare | null;
  readonly 'S-1a': BenchShare | null;
  readonly 'S-1b': BenchShare | null;
  readonly benign: {
    readonly unprotected: BenchShare | null;
    readonly 'S-1a': BenchShare | null;
    readonly 'S-1b': BenchShare | null;
  };
}

export interface InjectionTaskRow {
  readonly suite: string;
  readonly injectionTask: string;
  readonly cases: number;
  readonly succeeded: number;
  readonly executed: number;
  readonly textOnly: boolean;
}

export interface AgentDojoCase {
  readonly suite: string;
  readonly userTask: string;
  readonly injectionTask: string;
  readonly executed: boolean;
  readonly textOnly: boolean;
  readonly userRequest: string;
  readonly attackGoal: string;
}

export interface Remeasure {
  readonly test: string;
  readonly freeze: string;
  readonly protected: BenchShare | null;
  readonly executedOnly: BenchShare | null;
  readonly benign: BenchShare | null;
  readonly utilityUnderAttack: BenchShare | null;
  readonly againstFirst: Readonly<
    Record<
      string,
      {
        readonly cases: number;
        readonly onlyRemeasured: number;
        readonly onlyFirst: number;
        readonly p: number;
      }
    >
  >;
}

export interface AttackVariant {
  readonly variant: string;
  readonly fallenFor: BenchShare | null;
  readonly executedOnly: BenchShare | null;
  readonly control: BenchShare | null;
}

export interface AgentDojoBench extends BenchmarkBase {
  readonly id: 'agentdojo';
  readonly breakdown: {
    readonly environments: readonly AgentDojoEnvironment[];
    readonly injectionTasks: Readonly<Record<string, readonly InjectionTaskRow[]>>;
  };
  readonly variants: {
    readonly owners: readonly {
      readonly test: string;
      readonly owner: 'none' | 'llm' | 'all';
      readonly asked?: number;
      readonly approved?: number;
    }[];
    readonly remeasure: readonly Remeasure[];
    readonly attackVariants: {
      readonly overall: {
        readonly fallenFor: BenchShare | null;
        readonly executedOnly: BenchShare | null;
        readonly control: BenchShare | null;
      };
      readonly base: { readonly variant: string; readonly fallenFor: BenchShare | null };
      readonly weaknesses: readonly string[];
      readonly variants: readonly AttackVariant[];
    };
    readonly warm: {
      readonly freeze: string;
      readonly pairs: number;
      readonly warm: BenchShare | null;
      readonly cold: BenchShare | null;
      readonly paired: WarmPaired;
      readonly benignWarm: BenchShare | null;
      readonly benignCold: BenchShare | null;
      readonly benignPaired: WarmPaired;
    };
  };
  readonly cases: Readonly<Record<string, readonly AgentDojoCase[]>>;
  readonly settings: {
    readonly attack: string;
    readonly split: { readonly file: string; readonly part: string };
    readonly freezes: readonly string[];
  };
}

export interface InjecAgentSetting {
  readonly setting: 'base' | 'enhanced';
  readonly official: {
    readonly unprotected: Readonly<Record<string, string | number>>;
    readonly protected: Readonly<Record<string, string | number>>;
  };
  readonly directHarm: {
    readonly unprotected: BenchShare;
    readonly protected: BenchShare;
    readonly paired: BenchPaired;
  };
  readonly dataStealingStep1: {
    readonly unprotected: BenchShare;
    readonly protected: BenchShare;
    readonly paired: BenchPaired;
  };
  readonly attackerCallsRefused: BenchShare | null;
}

export interface EvidencePair {
  readonly with: BenchShare | null;
  readonly without: BenchShare | null;
  readonly paired: { readonly cases: number; readonly p_exact: number } & Readonly<Record<string, number>>;
}

export interface InjecAgentBench extends BenchmarkBase {
  readonly id: 'injecagent';
  readonly breakdown: { readonly settings: readonly InjecAgentSetting[] };
  readonly variants: {
    readonly evidence: readonly {
      readonly setting: string;
      readonly attackerCallsRefused: EvidencePair;
      readonly benignCallsRefused: EvidencePair;
    }[];
  };
  readonly cases: {
    readonly protected: readonly {
      readonly setting: string;
      readonly attackType: string;
      readonly userTool: string;
      readonly attackerTools: readonly string[];
    }[];
  };
  readonly settings: {
    readonly firstStepOnly: boolean;
    readonly benignCallSample: number;
    readonly seed: string;
    readonly argumentOriginsEvidence: boolean | string;
    readonly reusedOutputsFrom: string;
    readonly freezes: readonly string[];
  };
}

export interface PromptfooRow {
  readonly name: string;
  readonly unprotected: BenchShare;
  readonly protected: BenchShare;
  readonly notGenerated?: readonly string[];
}

export interface PromptfooBench extends BenchmarkBase {
  readonly id: 'promptfoo';
  readonly breakdown: {
    readonly plugins: readonly PromptfooRow[];
    readonly strategies: readonly PromptfooRow[];
    readonly categories: readonly PromptfooRow[];
    readonly riskyToolCalls: {
      readonly own: boolean;
      readonly tools: readonly {
        readonly tool: string;
        readonly unprotected: number;
        readonly protected: number;
      }[];
      readonly unprotected: number;
      readonly protected: number;
    };
  };
  readonly variants: null;
  readonly cases: {
    readonly fixed: readonly { readonly test: number; readonly plugin: string; readonly strategy: string }[];
    readonly broken: readonly { readonly test: number; readonly plugin: string; readonly strategy: string }[];
  };
  readonly settings: {
    readonly preset: string;
    readonly cases: number;
    readonly plugins: number;
    readonly generationAndGrading: string;
    readonly freezes: readonly string[];
  };
}

export type Benchmark = AgentDojoBench | InjecAgentBench | PromptfooBench;
export type BenchId = Benchmark['id'];
export const BENCH_IDS: readonly BenchId[] = ['agentdojo', 'injecagent', 'promptfoo'];
/** The benchmarks' own names, shown as they are in every language. */
export const BENCH_NAMES: Readonly<Record<string, string>> = {
  agentdojo: 'AgentDojo',
  injecagent: 'InjecAgent',
  promptfoo: 'Promptfoo',
};

export interface Freeze {
  readonly id: string;
  readonly sha256: string;
  readonly frozenAt: string;
  readonly release: string;
  readonly coreCommit: string;
  readonly coreChangedFiles: number;
  readonly decisionPathFiles: number;
  readonly decisionPathHash: string;
  readonly promptBundle: string;
  readonly usedBy: readonly string[];
}

export interface BenchLimit extends Words {
  readonly id: string;
  readonly source: string;
  readonly sourceLabel: Words;
}

export interface Bundle {
  readonly format: string;
  readonly program: {
    readonly spendUsd: number;
    readonly spendSource: string;
    readonly harness: {
      readonly checkedAt: string;
      readonly clean: boolean;
      readonly packages: readonly {
        readonly name: string;
        readonly version: string;
        readonly filesChecked?: number;
        readonly filesChanged: number;
      }[];
      readonly promptfoo: { readonly version: string; readonly fileProof: boolean };
    };
    readonly models: {
      readonly victim: string;
      readonly victimImage: string;
      readonly victimBase: string;
      readonly layer1: string;
      readonly layer2: string;
      readonly owner: string;
    };
  };
  readonly freezes: readonly Freeze[];
  readonly headline: readonly { readonly benchmark: BenchId; readonly test: string }[];
  readonly benchmarks: readonly Benchmark[];
  readonly limits: readonly BenchLimit[];
  readonly sources: readonly { readonly path: string; readonly sha256: string }[];
}

export function useBundle() {
  return useQuery({
    queryKey: ['benchmark-bundle'],
    queryFn: () => getJson<Bundle>(BUNDLE_PATH),
    staleTime: Infinity,
    retry: false,
  });
}

/** The bundle the screens can read: one of this format only (ST-68). */
export function readable(bundle: Bundle | undefined): bundle is Bundle {
  return bundle?.format === BUNDLE_FORMAT;
}

export function words(value: Words, language: string): string {
  return language === 'ko' ? value.ko : value.en;
}

export function benchOf(bundle: Bundle, id: string): Benchmark | null {
  return bundle.benchmarks.find((bench) => bench.id === id) ?? null;
}

export function testOf(bundle: Bundle, bench: string, test: string): BenchTest | null {
  return benchOf(bundle, bench)?.tests.find((found) => found.id === test) ?? null;
}

/** Decimals a benchmark's shares are written with: AgentDojo's results carry two, the others print one. */
export function digitsOf(bench: string): number {
  return bench === 'agentdojo' ? 2 : 1;
}

export function percent(value: number, language: string, digits: number): string {
  return `${formatNumber(value * 100, language, digits)}%`;
}

/**
 * A share as the screens write it (PC-9, DEC-57): the point, the counts, and the 95% interval; below 1% the one-sided
 * 95% upper bound stands apart (ST-71); a value fixed by how the sample was built has no interval (ST-72).
 */
export interface ShareText {
  readonly value: string;
  readonly counts: string;
  readonly interval: string | null;
  readonly upper: string | null;
  readonly construction: boolean;
}

export function shareText(share: BenchShare, language: string, digits: number): ShareText {
  const construction = share.derived?.kind === 'by-construction';
  const below = share.rate < 0.01;
  const pct = (value: number) => formatNumber(value * 100, language, digits);
  return {
    value: percent(share.rate, language, digits),
    counts: `${formatNumber(share.k, language)} / ${formatNumber(share.n, language)}`,
    interval:
      construction || below || share.low === null || share.high === null
        ? null
        : `${pct(share.low)}–${pct(share.high)}`,
    upper:
      !construction && below && share.upper95 !== null
        ? percent(share.upper95, language, digits === 1 ? 2 : digits)
        : null,
    construction,
  };
}

/** McNemar's p as the judgement record writes it: below 0.0001 as a bound, else its value (0.0008, 0.013, 0.382). */
export function pText(p: number, language: string): string {
  if (p < 0.0001) {
    return '< 0.0001';
  }
  return `= ${formatNumber(p, language, p < 0.01 ? 4 : 3)}`;
}
