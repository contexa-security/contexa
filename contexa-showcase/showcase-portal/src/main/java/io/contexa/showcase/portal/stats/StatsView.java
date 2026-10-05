package io.contexa.showcase.portal.stats;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The public execution statistics (deck p.17): an operations record of the real runs, separate from the benchmark.
 * Every number is counted from the stored runs; runs with a development-only forced decision are left out.
 *
 * @param engineActions the engine's resolved decisions by final action
 * @param layers        each control's result at the decisive step of the runs whose scenario has a ground truth
 * @param specCount     distinct execution specifications among the counted runs
 */
public record StatsView(Instant computedAt, Runs runs, DecisionTime decisionTime, Map<String, Long> engineActions,
                        Unresolved unresolved, Agreement agreement, Scope scope, List<LayerStats> layers, Spec spec,
                        long specCount) {

    /**
     * @param completed real runs that finished
     * @param failed    real runs that stopped on a technical failure
     * @param today     completed runs started since midnight UTC
     * @param live      completed runs started by visitors (live runs)
     */
    public record Runs(long completed, long failed, long today, long live, Instant firstAt, Instant lastAt) {
    }

    /** Analysis time of the engine's resolved decisions, from the request to the stored decision. */
    public record DecisionTime(long decisions, Long p50Ms, Long p95Ms) {
    }

    /**
     * @param technical     analyses the engine could not complete (response contract failure, technical fallback,
     *                      unsuccessful analysis): counted apart, never as a decision
     * @param noNewAnalysis requests the engine did not analyse again because an earlier decision still applied
     */
    public record Unresolved(long technical, long noNewAnalysis) {
    }

    /** Repeated-decision agreement of the published recordings: k of n repetitions gave the same outcome. */
    public record Agreement(long agreeing, long repetitions, List<Recording> recordings) {
    }

    public record Recording(String pairKey, String scene, int agreeing, int repetitions, Instant recordedAt) {
    }

    /**
     * @param threatRuns runs of scenarios whose ground truth is a threat
     * @param normalRuns runs of scenarios whose ground truth is normal work
     * @param otherRuns  runs without a ground truth (condition grid cells, uncertain scenarios), left out of the
     *                   miss and false-block counts
     */
    public record Scope(long threatRuns, long normalRuns, long otherRuns) {
    }

    public record LayerStats(String control, Threat threat, Normal normal) {
    }

    /**
     * @param leaked     the data left at the decisive step (a miss)
     * @param stopped    refused, cut mid-response, or held for a check or a review
     * @param unresolved the request itself failed
     */
    public record Threat(long runs, long leaked, long stopped, long unresolved) {
    }

    /**
     * @param challenged held for an extra check (control D), which normal work may meet
     * @param blocked    refused, cut mid-response or held for a review (a false block)
     */
    public record Normal(long runs, long passed, long challenged, long blocked, long unresolved) {
    }

    /** The execution specification of the latest counted run. */
    public record Spec(String specHash, String codeCommit, String engineVersion, String effectiveMode,
                       String chatModel, String embeddingModel, String timeZone) {
    }
}
