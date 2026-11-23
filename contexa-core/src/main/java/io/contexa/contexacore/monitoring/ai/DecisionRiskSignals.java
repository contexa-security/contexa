/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.monitoring.ai;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/**
 * The signs that an allowed decision may be a miss (quality plan 3.6), defined once over the columns of the decision
 * record ({@link DecisionConsoleColumns}), so that the sealing of allowed decisions and the review sample choose by
 * the same rule: the sealing reads them from the columns it computes for the decision, the review sample from the same
 * columns as the decision row keeps them ({@link #sqlCondition}, {@link #sqlCount}).
 *
 * <ul>
 * <li>{@link Signal#NOT_LEGITIMATE_WORK}: the explanation the model marked most likely is not legitimate work
 * ({@code H1}).</li>
 * <li>{@link Signal#SECOND_ANALYSIS}: the second analysis decided (the analysis depth is 2).</li>
 * <li>{@link Signal#ASKED_AGAIN}: an answer broke the output contract and the model was asked again: more model calls
 * than one per layer that ran, as the console counts a decision asked again.</li>
 * <li>{@link Signal#MANY_UNKNOWN_FACTS}: at least the threshold of decision facts were unknown.</li>
 * <li>{@link Signal#IMMATURE_BASELINE}: the personal baseline is not established.</li>
 * </ul>
 *
 * A value the decision did not keep is no signal. That a user was blocked after the decision is a sign known only
 * later; the review sample looks back for it, the sealing cannot.
 */
public final class DecisionRiskSignals {

    /** A sign that an allowed decision may be a miss. */
    public enum Signal {
        NOT_LEGITIMATE_WORK,
        SECOND_ANALYSIS,
        ASKED_AGAIN,
        MANY_UNKNOWN_FACTS,
        IMMATURE_BASELINE
    }

    /** The explanation that the account owner is doing their own work, as the product's prompt names it. */
    public static final String LEGITIMATE_WORK = "H1";

    /** The analysis depth of a decision the second analysis decided. */
    public static final String SECOND_ANALYSIS_DEPTH = "2";

    /** The decision stage of a decision the second layer set. */
    private static final String SECOND_LAYER_STAGE = "LAYER2";

    private static final String ESTABLISHED = "ESTABLISHED";

    private DecisionRiskSignals() {
    }

    /** Whether the second analysis decided: the analysis depth of the decision record is 2. */
    public static boolean secondAnalysis(String analysisDepth) {
        return analysisDepth != null && SECOND_ANALYSIS_DEPTH.equals(analysisDepth.trim());
    }

    /**
     * Whether the model was asked again: more model calls than one per layer that ran (two when the second layer set
     * the decision). The decision detail and the hourly table count a decision asked again the same way.
     */
    public static boolean askedAgain(Integer modelCallCount, String decisionStage) {
        return modelCallCount != null && modelCallCount > (SECOND_LAYER_STAGE.equals(decisionStage) ? 2 : 1);
    }

    /**
     * The signs of the decision; none when it did not allow.
     *
     * @param action               the action the decision ended in
     * @param unknownFactThreshold the unknown decision facts from which they are many, at least 1
     */
    public static Set<Signal> of(String action, String mostLikelyHypothesis, boolean secondAnalysis,
                                 boolean askedAgain, Integer unknownFactCount, String baselineStatus,
                                 int unknownFactThreshold) {
        Set<Signal> signals = EnumSet.noneOf(Signal.class);
        if (action == null || !ZeroTrustAction.ALLOW.name().equals(action.trim().toUpperCase(Locale.ROOT))) {
            return signals;
        }
        if (mostLikelyHypothesis != null && !mostLikelyHypothesis.isBlank()
                && !LEGITIMATE_WORK.equalsIgnoreCase(mostLikelyHypothesis.trim())) {
            signals.add(Signal.NOT_LEGITIMATE_WORK);
        }
        if (secondAnalysis) {
            signals.add(Signal.SECOND_ANALYSIS);
        }
        if (askedAgain) {
            signals.add(Signal.ASKED_AGAIN);
        }
        if (unknownFactCount != null && unknownFactCount >= Math.max(1, unknownFactThreshold)) {
            signals.add(Signal.MANY_UNKNOWN_FACTS);
        }
        if (baselineStatus != null && !baselineStatus.isBlank() && !ESTABLISHED.equals(baselineStatus.trim())) {
            signals.add(Signal.IMMATURE_BASELINE);
        }
        return signals;
    }

    /** The signs of a decision as its record's columns hold them. */
    public static Set<Signal> of(DecisionConsoleColumns.Values columns, String action, int unknownFactThreshold) {
        return of(action, columns.mostLikelyHypothesis(), secondAnalysis(columns.analysisDepth()),
                askedAgain(columns.modelCallCount(), columns.decisionStage()), columns.unknownFactCount(),
                columns.baselineStatus(), unknownFactThreshold);
    }

    /**
     * The SQL condition of one sign over the decision row of the given alias, the same as {@link #of}; the threshold
     * is written into it as a number. It is true or false, never null, so that it can be negated.
     */
    public static String sqlCondition(Signal signal, String alias, int unknownFactThreshold) {
        String o = alias + ".";
        return switch (signal) {
            case NOT_LEGITIMATE_WORK -> "(NULLIF(TRIM(" + o + "most_likely_hypothesis), '') IS NOT NULL AND UPPER(TRIM("
                    + o + "most_likely_hypothesis)) <> '" + LEGITIMATE_WORK + "')";
            case SECOND_ANALYSIS -> "(" + o + "analysis_depth IS NOT NULL AND TRIM(" + o + "analysis_depth) = '"
                    + SECOND_ANALYSIS_DEPTH + "')";
            case ASKED_AGAIN -> "(" + o + "model_call_count IS NOT NULL AND " + o + "model_call_count > (CASE WHEN "
                    + o + "decision_stage = '" + SECOND_LAYER_STAGE + "' THEN 2 ELSE 1 END))";
            case MANY_UNKNOWN_FACTS -> "(" + o + "unknown_fact_count IS NOT NULL AND " + o + "unknown_fact_count >= "
                    + Math.max(1, unknownFactThreshold) + ")";
            case IMMATURE_BASELINE -> "(NULLIF(TRIM(" + o + "baseline_status), '') IS NOT NULL AND TRIM(" + o
                    + "baseline_status) <> '" + ESTABLISHED + "')";
        };
    }

    /** The SQL condition that an allowed decision row of the alias carries at least one sign. */
    public static String sqlCondition(String alias, int unknownFactThreshold) {
        StringBuilder condition = new StringBuilder("(").append(alias).append(".final_action = 'ALLOW' AND (");
        Signal[] signals = Signal.values();
        for (int index = 0; index < signals.length; index++) {
            condition.append(index == 0 ? "" : " OR ").append(sqlCondition(signals[index], alias, unknownFactThreshold));
        }
        return condition.append("))").toString();
    }

    /** The SQL number of the signs a decision row of the alias carries, whatever its action. */
    public static String sqlCount(String alias, int unknownFactThreshold) {
        StringBuilder count = new StringBuilder("(");
        Signal[] signals = Signal.values();
        for (int index = 0; index < signals.length; index++) {
            count.append(index == 0 ? "" : " + ").append("(CASE WHEN ")
                    .append(sqlCondition(signals[index], alias, unknownFactThreshold)).append(" THEN 1 ELSE 0 END)");
        }
        return count.append(")").toString();
    }
}
