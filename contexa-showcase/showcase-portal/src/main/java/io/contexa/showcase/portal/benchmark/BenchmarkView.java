package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.ToLongFunction;

/**
 * The benchmark (docs/showcase/데모-재설계.md 5A.2, W5): scores of one engine setting from its measurement protocol
 * runs only (R-13, R-14), with Wilson 95% intervals and per-case averages, the runs Contexa got wrong, the engine's
 * operations figures, and, apart from the scores, what visitors observed and said (R-26). Every number is counted
 * from stored runs by the one scoring rule.
 *
 * @param notices                    fairness notices the screen states first (R-07, R-19), as stable codes
 * @param wrongRuns                  every run Contexa got wrong (an attack let through, a normal task stopped),
 *                                   newest first and not cut
 * @param unresolvedRuns             runs with a ground truth where the engine made no real decision, counted apart
 *                                   from the wrong runs
 * @param suites                     the control scores of each named case group apart (work 13), such as the cases
 *                                   the rule controls were not written for; the overall scores include them
 * @param riskJudged                 Contexa's attack runs the model judged risky, and how many of them were stopped
 * @param judgmentTiming             Contexa's attack runs by how its answer came about (the names of the scoring
 *                                   JudgmentTiming kinds in their order, every kind present): a limit of timing or of
 *                                   judgement
 * @param protocolRunsWithoutSetting completed, unforced protocol runs that recorded no measurement setting and so
 *                                   belong to no setting's scores (H-22); stated, not hidden
 */
public record BenchmarkView(Instant computedAt, List<String> notices, List<Spec> specs, Spec spec, Scope scope,
                            List<ControlScore> controls, List<CaseRow> cases, List<WrongRun> wrongRuns,
                            long unresolvedRuns, List<Suite> suites, RiskJudged riskJudged,
                            Map<String, Long> judgmentTiming, Engine engine,
                            Observations observations, long protocolRunsWithoutSetting) {

    /** How many runs Contexa got wrong; the whole list's length, so a title and its list never differ. */
    @JsonProperty("wrongRunCount")
    public int wrongRunCount() {
        return wrongRuns.size();
    }

    /** How many measured cases each ground truth classification has: the case list's tabs (S10, T-27). */
    @JsonProperty("caseCounts")
    public Map<String, Long> caseCounts() {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String classification : List.of("THREAT", "NORMAL", "UNCERTAIN")) {
            counts.put(classification, cases.stream()
                    .filter(row -> classification.equals(row.classification())).count());
        }
        return counts;
    }

    /** How many cases of each classification Contexa got wrong in at least one scored run: the case list's filter. */
    @JsonProperty("contexaWrongCases")
    public Map<String, Long> contexaWrongCases() {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String classification : List.of("THREAT", "NORMAL", "UNCERTAIN")) {
            counts.put(classification, cases.stream()
                    .filter(row -> classification.equals(row.classification()) && row.contexaWrong()).count());
        }
        return counts;
    }

    /** The attack cases Contexa let through in every run, in case order: the limits screen's cards. */
    @JsonProperty("missedEveryRunCases")
    public List<String> missedEveryRunCases() {
        return cases.stream().filter(CaseRow::missedEveryRun).map(CaseRow::key).toList();
    }

    /** The summary's three questions answered from these scores (bench-1). */
    @JsonProperty("conclusions")
    public Conclusions conclusions() {
        return Conclusions.of(controls);
    }

    /**
     * The summary's three questions (bench-1), answered from the scores: the sentence frames are the design's, the
     * approaches and numbers are the measurement's (plan 8). A tie names every tied approach, in control order.
     *
     * @param mostStopped      the approaches that stopped the most attack runs at some step
     * @param mostFalseBlock   the approaches that halted the most normal runs; no approach when none halted any
     * @param cleanMostStopped among the approaches that halted no normal run, those that stopped the most attack runs
     *                         at some step; no approach when every approach halted some
     */
    public record Conclusions(Pick mostStopped, Pick mostFalseBlock, Pick cleanMostStopped) {

        static Conclusions of(List<ControlScore> controls) {
            List<ControlScore> clean = controls.stream().filter(score -> score.falseBlock().hits() == 0).toList();
            return new Conclusions(
                    Pick.top(controls, score -> score.stoppedAny().hits(), score -> score.stoppedAny().total()),
                    Pick.top(controls, score -> score.falseBlock().hits(), score -> score.falseBlock().total()),
                    Pick.top(clean, score -> score.stoppedAny().hits(), score -> score.stoppedAny().total()));
        }
    }

    /**
     * The approaches with the highest count and that count.
     *
     * @param controls the tied approaches in control order; empty when the highest count is zero
     */
    public record Pick(List<String> controls, long hits, long total) {

        static Pick top(List<ControlScore> scores, ToLongFunction<ControlScore> hits,
                        ToLongFunction<ControlScore> total) {
            long best = scores.stream().mapToLong(hits).max().orElse(0);
            List<String> named = new ArrayList<>();
            long of = 0;
            for (ControlScore score : scores) {
                if (best > 0 && hits.applyAsLong(score) == best) {
                    named.add(score.control());
                    of = total.applyAsLong(score);
                }
            }
            return new Pick(List.copyOf(named), best, of);
        }
    }

    /**
     * A measurement setting that has protocol runs (V-13): the execution specification without the per-employee
     * template and the system prompt hash, plus the version the templates were learned under.
     *
     * @param templates        the templates the setting's runs were cloned from (one per protagonist)
     * @param templateVersions the versions those templates were learned under (one when the setting is sound)
     * @param promptHashes     the system prompt hashes of its runs ({@code NO_MODEL_CALL} for runs without a call)
     */
    public record Spec(String settingHash, String chatModel, Map<String, Object> modelSettings, String codeCommit,
                       String engineVersion, String ruleVersion, String contractVersion, List<String> templates,
                       List<String> templateVersions, List<String> promptHashes, long protocolRuns,
                       Instant firstRunAt, Instant lastRunAt) {
    }

    /**
     * @param protocols the protocols whose runs are counted, with how many times each case was run
     */
    public record Scope(long runs, long attackRuns, long normalRuns, long otherRuns, int cases,
                        List<Protocol> protocols) {
    }

    /**
     * A measurement protocol and what became of its runs: each listed case {@code repeat} times was planned; only the
     * completed, unforced runs make the scores, and the others are stated.
     *
     * @param plannedRuns   listed cases times {@code repeat}
     * @param completedRuns completed runs without a forced decision
     * @param failedRuns    runs that did not complete
     * @param forcedRuns    runs with a forced decision (refused by the protocol, counted should one appear)
     */
    public record Protocol(String protocolId, int repeat, int cases, long plannedRuns, Instant startedAt,
                           Instant finishedAt, long completedRuns, long failedRuns, long forcedRuns) {
    }

    /** Below this many counted runs a rate is marked preliminary on the screens (the Arena pattern of 7.10). */
    static final long PRELIMINARY_BELOW = 10;

    /** A rate with its counts and Wilson 95% interval; null rate when nothing was counted. */
    public record Rate(long hits, long total, Double rate, Double low, Double high) {

        /** Counted over fewer runs than {@link #PRELIMINARY_BELOW}: the screen marks it preliminary. */
        @JsonProperty("preliminary")
        public boolean preliminary() {
            return total > 0 && total < PRELIMINARY_BELOW;
        }
    }

    /**
     * @param stopped      attacks stopped at every step (full stop) over resolved attack runs
     * @param stoppedAny   attacks stopped at some step, a partial stop included
     * @param falseBlock   legitimate work halted over resolved legitimate runs
     * @param friction     legitimate work that passed only after an identity check
     * @param stoppedMacro the mean of the per-case full-stop rates (each case counts once)
     * @param stoppedAnyMacro the mean of the per-case rates of attacks stopped at some step (the detection bar's rule)
     * @param falseBlockMacro the mean of the per-case false-block rates
     * @param exposedItems items that left in attack runs
     */
    public record ControlScore(String control, Rate stopped, Rate stoppedAny, Double stoppedMacro,
                               Double stoppedAnyMacro, Rate falseBlock,
                               Rate friction, Double falseBlockMacro, long attackUnresolved, long normalUnresolved,
                               long exposedItems) {

        /** Attack runs stopped only after some items left (T-27: counted here, never on the screen). */
        @JsonProperty("partlyStopped")
        public long partlyStopped() {
            return stoppedAny.hits() - stopped.hits();
        }

        /** Attack runs that nothing stopped. */
        @JsonProperty("missed")
        public long missed() {
            return stoppedAny.total() - stoppedAny.hits();
        }

        /** Normal runs that went through without an additional check. */
        @JsonProperty("normalPassed")
        public long normalPassed() {
            return falseBlock.total() - falseBlock.hits() - friction.hits();
        }

        /**
         * Normal runs not halted (passed with or without an additional check) over resolved normal runs, with the
         * interval: the summary table's third column (bench-1).
         */
        @JsonProperty("notBlocked")
        public Rate notBlocked() {
            return BenchmarkService.rate(falseBlock.total() - falseBlock.hits(), falseBlock.total());
        }
    }

    /**
     * @param runs    attack runs with a result where at least one model decision was not to allow
     * @param stopped of them, the runs stopped fully or after some items left
     */
    public record RiskJudged(long runs, long stopped) {
    }

    /**
     * A named group of cases scored apart (ScenarioDefinition.suite).
     *
     * @param cases the case keys of the group that have runs in the setting
     * @param runs  the group's runs in the setting
     */
    public record Suite(String suite, List<String> cases, int runs, List<ControlScore> controls) {

        /** The summary's three questions over the group alone. */
        @JsonProperty("conclusions")
        public Conclusions conclusions() {
            return Conclusions.of(controls);
        }
    }

    /**
     * @param definitionSha256 the hashes of the definitions the case's runs executed (frozen, R-33)
     * @param results          per control: business result name to count
     * @param engineActions    control D's model decisions by action, over every step
     * @param engineVerdicts   control D's verdict scores by result, over every step
     * @param decisionSources  where control D's answers came from, over every step
     * @param runIds           the case's runs, oldest first (each opens its anatomy)
     * @param risk             the spread of the model's risk scores over the case's repeated runs (V-17)
     * @param cells            per control, the runs handled as the ground truth says over the scored runs, by the
     *                         scorecard's own rule (an attack stopped at some step, normal work passed with or without
     *                         a check); empty for a case without a ground truth
     */
    public record CaseRow(String key, String classification, Map<String, String> title, long runs,
                          List<String> definitionSha256, Map<String, Map<String, Long>> results,
                          Map<String, Long> engineActions, Map<String, Long> engineVerdicts,
                          Map<String, Long> decisionSources, List<String> runIds, RiskSpread risk,
                          Map<String, Cell> cells) {

        /** Whether Contexa got at least one scored run of the case wrong (the case list's filter). */
        @JsonProperty("contexaWrong")
        public boolean contexaWrong() {
            Cell cell = cells == null ? null : cells.get("D");
            return cell != null && cell.counted() > 0 && cell.right() < cell.counted();
        }

        /** An attack case Contexa let through in every run (the limits screen). */
        @JsonProperty("missedEveryRun")
        public boolean missedEveryRun() {
            Map<String, Long> contexa = results == null ? null : results.get("D");
            return "THREAT".equals(classification) && runs > 0 && contexa != null
                    && contexa.getOrDefault("MISSED", 0L) == runs;
        }
    }

    /** Runs of a case handled as the ground truth says, over its scored runs (unresolved and unscored left out). */
    public record Cell(long right, long counted) {

        /** NONE without counted runs, RIGHT when all were right, WRONG when none were, MIXED otherwise. */
        @JsonProperty("state")
        public String state() {
            return counted == 0 ? "NONE" : right == counted ? "RIGHT" : right == 0 ? "WRONG" : "MIXED";
        }
    }

    /**
     * The model's risk scores over a case's decisions, every step, unresolved decisions left out.
     *
     * @param scored    decisions that carry a risk score (the response contract leaves it optional)
     * @param decisions resolved model decisions of the case
     */
    public record RiskSpread(Double min, Double max, long scored, long decisions) {
    }

    /**
     * A protocol run whose business result for control D is wrong: an attack let through or a normal task stopped.
     *
     * @param stepNo        the step of the anatomy to open (the first step with a decision)
     * @param coreAdverseMet labels of the core inspector's adverse-evidence rule that the prompt met, from the stored
     *                      anatomy of that step; null when the anatomy holds none
     */
    public record WrongRun(String runId, String caseKey, String classification, String result, long exposedItems,
                           Integer stepNo, String finalAction, Double riskScore, String reasoning,
                           Integer coreAdverseMet, Instant startedAt) {
    }

    /**
     * @param analysisMeasured      resolved decisions with an analysis time (the p50 and p95 are over these)
     * @param costPerDecisionUsd    measured tokens (cached input included) times the configured price; null when the
     *                              price of the model is not configured
     * @param tokensPerDecision     the mean of the tokens the engine recorded per decision
     * @param tokensMeasured        decisions with recorded tokens
     * @param modelCallsPerDecision the mean of the model calls the engine recorded per decision
     * @param modelCalls            model calls captured as raw exchanges
     */
    public record Engine(long decisions, Map<String, Long> actions, long unresolved, Long analysisP50Ms,
                         Long analysisP95Ms, long analysisMeasured, Double costPerDecisionUsd, String priceSource,
                         long promptTokens, long cachedTokens, long completionTokens, Double tokensPerDecision,
                         long tokensMeasured, Double modelCallsPerDecision, long modelCalls) {
    }

    /**
     * What visitors did and said under the same setting, kept apart from the scores (R-14, R-26). Assessments count
     * only when older than {@code delayHours}; each visitor weighs one in the share.
     *
     * @param predictionsAll    every call visitors made before sending, cases without a ground truth included
     * @param predictions       calls on runs with a ground truth (attack or normal work), "unsure" left out
     * @param unsurePredictions "unsure" calls on runs with a ground truth
     */
    public record Observations(long liveRuns, long labRuns, long composedRuns, long predictionsAll, Rate predictions,
                               long unsurePredictions, long assessments, long assessors, Double soundShareWeighted,
                               Map<String, Long> verdicts, Map<String, Long> reasons, int delayHours) {

        /** Calls on designed cases: the scored ones and the "unsure" ones. */
        @JsonProperty("designedPredictions")
        public long designedPredictions() {
            return predictions.total() + unsurePredictions;
        }
    }
}
