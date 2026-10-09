package io.contexa.showcase.portal.stats;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The public execution statistics (deck p.17): an operations record of the real runs, separate from the benchmark.
 * Every number is counted from the stored runs; runs with a development-only forced decision are left out.
 *
 * @param engineActions the engine's resolved decisions by final action
 * @param layers        each control's business result over the whole case of the runs with a ground truth, by the
 *                      one scoring rule (docs/showcase/데모-재설계.md 5.0)
 * @param specCount     distinct execution specifications among the counted runs
 * @param releases      block releases recorded for the counted runs (the follow-up map's block line, D-32)
 */
public record StatsView(Instant computedAt, Runs runs, DecisionTime decisionTime, Map<String, Long> engineActions,
                        Unresolved unresolved, Agreement agreement, Scope scope, List<LayerStats> layers, Spec spec,
                        long specCount, long releases) {

    /** The engine's resolved decisions of every final action together, counted here so the screen adds nothing. */
    @JsonProperty(value = "engineDecisions", access = JsonProperty.Access.READ_ONLY)
    public long engineDecisions() {
        return engineActions == null ? 0L : engineActions.values().stream().mapToLong(Long::longValue).sum();
    }

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
     * @param threatRuns runs whose ground truth is a threat
     * @param normalRuns runs whose ground truth is normal work
     * @param otherRuns  runs without a ground truth (condition grid cells, uncertain scenarios, runs whose executed
     *                   definition is no longer known), left out of the miss and false-block counts
     */
    public record Scope(long threatRuns, long normalRuns, long otherRuns) {
    }

    public record LayerStats(String control, Threat threat, Normal normal) {
    }

    /**
     * @param stopped       no data left at any step
     * @param partlyStopped some data left before the case was stopped or cut
     * @param missed        the data left at every step
     * @param unresolved    a request failed
     * @param exposedItems  items that left over all these runs
     */
    public record Threat(long runs, long stopped, long partlyStopped, long missed, long unresolved,
                         long exposedItems) {
    }

    /**
     * @param passedAfterCheck control D asked for an additional check, the run principal answered it and the work went
     *                         on
     * @param halted           a step was refused, cut or left on hold (a false block)
     */
    public record Normal(long runs, long passed, long passedAfterCheck, long halted, long unresolved) {
    }

    /** The execution specification of the latest counted run. */
    public record Spec(String specHash, String codeCommit, String engineVersion, String effectiveMode,
                       String chatModel, String embeddingModel, String timeZone) {
    }
}
