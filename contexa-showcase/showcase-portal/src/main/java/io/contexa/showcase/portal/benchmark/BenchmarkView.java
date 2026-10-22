package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
 * @param judgmentExposure           the items that left in those runs over every step, before and after a decision (a
 *                                   run judged to pass lets its items out after the decision), by the same kinds
 *                                   (BM-S3)
 * @param judgmentOthers             the runs of the kind OTHER, each with its case, its result and the shape of every
 *                                   step, so a screen words the shape instead of a fixed sentence (V-01 of
 *                                   docs/showcase/영상전-검토.md)
 * @param protocolRunsWithoutSetting completed, unforced protocol runs that recorded no measurement setting and so
 *                                   belong to no setting's scores (H-22); stated, not hidden
 */
public record BenchmarkView(Instant computedAt, List<String> notices, List<Spec> specs, Spec spec, Scope scope,
                            List<ControlScore> controls, List<CaseRow> cases, List<WrongRun> wrongRuns,
                            long unresolvedRuns, List<Suite> suites, RiskJudged riskJudged,
                            Map<String, Long> judgmentTiming, Map<String, Long> judgmentExposure,
                            List<JudgmentRun> judgmentOthers, Engine engine,
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

    /** The existing approaches a blind-spot run is let through by (G1 of the v21 plan), Contexa left out. */
    static final List<String> EXISTING = List.of("A", "B", "C1", "C2");

    /** The results of an existing approach that let an attack's data out at every step. */
    static final Set<String> LET_THROUGH = Set.of("MISSED");

    /** The results of an existing approach that let normal work go on. */
    static final Set<String> LET_PASS = Set.of("PASSED", "PASSED_AFTER_CHECK");

    /** Contexa's results that stopped an attack, fully or after some items left. */
    static final Set<String> CONTEXA_STOPPED = Set.of("STOPPED", "PARTLY_STOPPED");

    /**
     * BM-S2 of docs/showcase/벤치마크-구현계획.md: the pairs designed in 4.6 of docs/showcase/프롬프트-v21-구현계획.md, each
     * blind-spot attack and the normal work of the same conditions (S18's is S16T), in the demo's two themes: someone
     * holding a stolen account, and the insider (the account's owner acts, the oracle actor OWNER).
     */
    static final List<BlindSpotPair> PAIRS = List.of(
            new BlindSpotPair("STOLEN_ACCOUNT", "S13", "S13T"),
            new BlindSpotPair("STOLEN_ACCOUNT", "S17", "S17T"),
            new BlindSpotPair("STOLEN_ACCOUNT", "S19", "S19T"),
            new BlindSpotPair("INSIDER", "S16", "S16T"),
            new BlindSpotPair("INSIDER", "S18", "S16T"));

    /**
     * PB-1 and PB-2 of 4.8 in docs/showcase/프롬프트-v21-구현계획.md (G1 to G3 of its 0.1), from each run's own results:
     * per attack case, the runs every existing approach let through and what Contexa did in those same runs (a case
     * without such a run is left out); per normal case of the rule-blind suite, the runs every existing approach let
     * pass and what Contexa did in them; the designed pairs whose attack was measured and the totals of G1 to G3 over
     * them (BM-S2). Nothing is judged here beyond the recorded results.
     */
    @JsonProperty("blindSpot")
    public BlindSpot blindSpot() {
        Set<String> ruleBlind = new HashSet<>();
        for (Suite suite : suites == null ? List.<Suite>of() : suites) {
            if ("RULE_BLIND".equals(suite.suite())) {
                ruleBlind.addAll(suite.cases());
            }
        }
        List<BlindSpotCase> attacks = new ArrayList<>();
        List<BlindSpotCase> normals = new ArrayList<>();
        Map<String, CaseRow> byKey = new HashMap<>();
        for (CaseRow row : cases == null ? List.<CaseRow>of() : cases) {
            byKey.put(row.key(), row);
            if ("THREAT".equals(row.classification())) {
                BlindSpotCase found = BlindSpotCase.of(row, LET_THROUGH);
                if (found.allPassed() > 0) {
                    attacks.add(found);
                }
            } else if ("NORMAL".equals(row.classification()) && ruleBlind.contains(row.key())) {
                normals.add(BlindSpotCase.of(row, LET_PASS));
            }
        }
        List<BlindSpotPair> pairs = PAIRS.stream().filter(pair -> byKey.containsKey(pair.attack())).toList();
        return new BlindSpot(List.copyOf(attacks), List.copyOf(normals), pairs, BlindSpotTotals.of(pairs, byKey));
    }

    /**
     * @param attacks the attack cases with a run every existing approach let through, in case order
     * @param normals the normal cases of the rule-blind suite, in case order
     * @param pairs   the designed pairs whose attack was measured, in their order
     * @param totals  G1 to G3 over the pairs' runs
     */
    public record BlindSpot(List<BlindSpotCase> attacks, List<BlindSpotCase> normals, List<BlindSpotPair> pairs,
                            BlindSpotTotals totals) {

        /**
         * V-64 of docs/showcase/영상전-검토.md: the normal cases more than one pair names (S16T for S16 and S18), in pair
         * order; the totals count such a case once.
         */
        @JsonProperty("sharedNormals")
        public List<String> sharedNormals() {
            Map<String, Integer> named = new LinkedHashMap<>();
            for (BlindSpotPair pair : pairs == null ? List.<BlindSpotPair>of() : pairs) {
                if (pair.normal() != null) {
                    named.merge(pair.normal(), 1, Integer::sum);
                }
            }
            return named.entrySet().stream().filter(entry -> entry.getValue() > 1).map(Map.Entry::getKey).toList();
        }
    }

    /** A designed blind-spot attack and the normal work of the same conditions, in its group. */
    public record BlindSpotPair(String group, String attack, String normal) {
    }

    /** A run every existing approach let through (or let pass), with Contexa's business result in it. */
    public record BlindSpotRun(String runId, String result) {
    }

    /**
     * G1 to G3 of the v21 plan over the designed pairs' runs.
     *
     * @param attackRuns          the attack runs of the pairs
     * @param attackAllPassed     of those, the runs every existing approach let through
     * @param contexaStopped      of those, the runs Contexa stopped, fully or after some items left
     * @param contexaFullyStopped of those, the runs Contexa stopped from the start
     * @param normalRuns          the normal runs of the pairs (a normal case two pairs share is counted once)
     * @param normalAllPassed     of those, the runs every existing approach let pass
     * @param contexaPassed       of those, the runs Contexa let pass, with or without an extra check
     */
    public record BlindSpotTotals(long attackRuns, long attackAllPassed, long contexaStopped, long contexaFullyStopped,
                                  long normalRuns, long normalAllPassed, long contexaPassed) {

        static BlindSpotTotals of(List<BlindSpotPair> pairs, Map<String, CaseRow> byKey) {
            long[] attack = new long[4];
            for (String key : pairs.stream().map(BlindSpotPair::attack).distinct().toList()) {
                BlindSpotCase found = BlindSpotCase.of(byKey.get(key), LET_THROUGH);
                attack[0] += found.runs();
                attack[1] += found.allPassed();
                attack[2] += found.passedRuns().stream().filter(run -> CONTEXA_STOPPED.contains(run.result())).count();
                attack[3] += found.passedRuns().stream().filter(run -> "STOPPED".equals(run.result())).count();
            }
            long[] normal = new long[3];
            for (String key : pairs.stream().map(BlindSpotPair::normal).filter(byKey::containsKey).distinct().toList()) {
                BlindSpotCase found = BlindSpotCase.of(byKey.get(key), LET_PASS);
                normal[0] += found.runs();
                normal[1] += found.allPassed();
                normal[2] += found.passedRuns().stream().filter(run -> LET_PASS.contains(run.result())).count();
            }
            return new BlindSpotTotals(attack[0], attack[1], attack[2], attack[3], normal[0], normal[1], normal[2]);
        }
    }

    /**
     * @param runs      the case's runs with every approach's result recorded
     * @param allPassed the runs every existing approach let through (an attack) or let go on (normal work)
     * @param contexa    Contexa's results in those same runs, by result
     * @param passedRuns those runs with Contexa's result in each, in the case's run order (BM-S2)
     */
    public record BlindSpotCase(String key, long runs, long allPassed, Map<String, Long> contexa,
                                List<BlindSpotRun> passedRuns) {

        static BlindSpotCase of(CaseRow row, Set<String> through) {
            Map<String, Map<String, String>> results = row.runResults() == null ? Map.of() : row.runResults();
            long allPassed = 0;
            Map<String, Long> contexa = new TreeMap<>();
            List<BlindSpotRun> passedRuns = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> entry : results.entrySet()) {
                Map<String, String> run = entry.getValue();
                if (EXISTING.stream().allMatch(control -> through.contains(run.get(control)))) {
                    allPassed++;
                    contexa.merge(run.getOrDefault("D", "NONE"), 1L, Long::sum);
                    passedRuns.add(new BlindSpotRun(entry.getKey(), run.getOrDefault("D", "NONE")));
                }
            }
            return new BlindSpotCase(row.key(), results.size(), allPassed, Map.copyOf(contexa), List.copyOf(passedRuns));
        }
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
     * @param promptBundles    SC-12 (docs/showcase/프롬프트-v21-구현계획.md): the prompt bundles its runs' engine ran, as
     *                         their execution specifications state; a screen names the facts of that bundle's
     *                         measurement, never those of another
     */
    public record Spec(String settingHash, String chatModel, Map<String, Object> modelSettings, String codeCommit,
                       String engineVersion, String ruleVersion, String contractVersion, List<String> templates,
                       List<String> templateVersions, List<String> promptHashes, long protocolRuns,
                       Instant firstRunAt, Instant lastRunAt, List<String> promptBundles) {
    }

    /**
     * @param protocols         the protocols whose runs are counted, with how many times each case was run
     * @param fewestRunsPerCase the counted runs of the case sent the fewest times (BM-S9: a protocol stopped before its
     *                          plan sent its cases fewer times than its repeat)
     * @param mostRunsPerCase   the counted runs of the case sent the most times
     */
    public record Scope(long runs, long attackRuns, long normalRuns, long otherRuns, int cases,
                        List<Protocol> protocols, int fewestRunsPerCase, int mostRunsPerCase) {
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
     * @param runs       attack runs with a result where at least one model decision was not to allow
     * @param stopped    of them, the runs stopped fully or after some items left
     * @param kinds      those runs by their judgment-and-timing kind, every kind present in its order, so the line
     *                   that states them names the bars they sit in (V-01 of docs/showcase/영상전-검토.md)
     * @param notStopped the cases of those runs that were not stopped, in run order
     */
    public record RiskJudged(long runs, long stopped, Map<String, Long> kinds, List<String> notStopped) {
    }

    /**
     * An attack run of the kind OTHER (V-01): its case, Contexa's business result and the items that left, and how
     * each step was answered.
     */
    public record JudgmentRun(String runId, String caseKey, String result, long exposedItems,
                              List<JudgmentStep> steps) {
    }

    /**
     * A step of such a run as scored: the engine's action (null without a decision of this step), when it applied
     * (BEFORE_RESPONSE, NEXT_REQUEST or NONE), where the answer came from (a RunScores decision source) and whether
     * the decision could still change the case (false for a decision from the next request after the last step).
     */
    public record JudgmentStep(int stepNo, String action, String applied, String source, boolean applicable) {
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
     * @param runResults       each run's business result per control, by run (최종화면-구현계획 FP-4: a dot of the run
     *                         matrix opens its own run)
     */
    public record CaseRow(String key, String classification, Map<String, String> title, long runs,
                          List<String> definitionSha256, Map<String, Map<String, Long>> results,
                          Map<String, Long> engineActions, Map<String, Long> engineVerdicts,
                          Map<String, Long> decisionSources, List<String> runIds, RiskSpread risk,
                          Map<String, Cell> cells, Map<String, Map<String, String>> runResults) {

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
     * @param agreement             the decisions against the model's own answers (PB-3, G4 of the v21 plan)
     * @param analysisBins          the timed decisions in fixed bins of their analysis time (BM-S4)
     * @param reasoning             the decisions' explanations, retries and moved answers (BM-S6)
     */
    public record Engine(long decisions, Map<String, Long> actions, long unresolved, Long analysisP50Ms,
                         Long analysisP95Ms, long analysisMeasured, Double costPerDecisionUsd, String priceSource,
                         long promptTokens, long cachedTokens, long completionTokens, Double tokensPerDecision,
                         long tokensMeasured, Double modelCallsPerDecision, long modelCalls, ModelAgreement agreement,
                         List<AnalysisBin> analysisBins, Reasoning reasoning) {
    }

    /**
     * BM-S6 of docs/showcase/벤치마크-구현계획.md: what the model's answers show of its judgment.
     *
     * @param mostLikely      per run truth (THREAT, NORMAL, UNCERTAIN), the decisions by the explanation their last
     *                        answer judged most likely: its id (H1 to H5), SEVERAL, or NONE when no explanation was
     *                        judged most likely; a decision without a model answer is left out
     * @param retried         the decisions the response check asked again at least once
     * @param retryKinds      of those, the decisions by each kind of what was wrong (REASON_CODE_MISMATCH and so on)
     * @param topRetryReasons the five most frequent reasons, each with its decisions, fact IDs read as their kind (P#)
     * @param flips           the asked-again decisions whose last answer named another action than the first, by
     *                        FIRST->LAST
     * @param mostLikelyActions the decisions of {@code mostLikely} by the action each applied (NONE without one), per
     *                        run truth and explanation (V-46 of docs/showcase/영상전-검토.md: an attack decision that
     *                        judged legitimate work most likely may still have refused)
     */
    public record Reasoning(Map<String, Map<String, Long>> mostLikely, long retried, Map<String, Long> retryKinds,
                            List<RetryReason> topRetryReasons, Map<String, Long> flips,
                            Map<String, Map<String, Map<String, Long>>> mostLikelyActions) {

        static final Reasoning NONE = new Reasoning(Map.of(), 0, Map.of(), List.of(), Map.of(), Map.of());
    }

    /** A reason the response check gave for asking again, with the decisions it was given for. */
    public record RetryReason(String reason, long decisions) {
    }

    /** A bin of decision times: from (inclusive) to (exclusive; null for the last, open bin), and its decisions. */
    public record AnalysisBin(long fromMs, Long toMs, long decisions) {

        /** The bin edges in milliseconds (BM-S4): 0, 5, 10, 15, 20, 30 and 60 s, the last bin open. */
        static final List<Long> EDGES = List.of(0L, 5000L, 10000L, 15000L, 20000L, 30000L, 60000L);

        /** The given times in the bins, every bin present (an empty one with 0). */
        static List<AnalysisBin> of(List<Long> times) {
            List<AnalysisBin> bins = new ArrayList<>();
            for (int index = 0; index < EDGES.size(); index++) {
                long from = EDGES.get(index);
                Long to = index + 1 < EDGES.size() ? EDGES.get(index + 1) : null;
                long decisions = times.stream().filter(time -> time >= from && (to == null || time < to)).count();
                bins.add(new AnalysisBin(from, to, decisions));
            }
            return List.copyOf(bins);
        }
    }

    /**
     * PB-3 of 4.8 in docs/showcase/프롬프트-v21-구현계획.md (G4): the decision records of the setting's runs against the
     * action in the last model call's answer of each.
     *
     * @param decisions     every decision record
     * @param modelAnswered the decisions with a model answer that names an action
     * @param asAnswered    of those, the decisions whose applied action is the answer's, with no technical failure
     * @param technical     of those, the decisions an unresolved answer or a technical or parser fallback decided
     * @param held          the decisions without a model answer: a decision before held the request
     */
    public record ModelAgreement(long decisions, long modelAnswered, long asAnswered, long technical, long held) {
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
