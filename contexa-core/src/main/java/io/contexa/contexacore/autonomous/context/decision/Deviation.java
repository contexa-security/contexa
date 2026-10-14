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
package io.contexa.contexacore.autonomous.context.decision;

/**
 * The request compared with the usual behaviour on one dimension (W2-5).
 *
 * @param dimension   the dimension
 * @param current     the request's value as the prompt names it ({@code 03}, {@code Chrome/140 on WINDOWS})
 * @param compared    whether there was a usual behaviour to compare with; without one the difference is unknown
 * @param different   whether the value was not seen in the usual behaviour (false when not compared)
 * @param seen        how many observations of the usual behaviour held the value, null when not counted
 * @param of          how many observations were counted, null when not counted
 * @param usual       the usual value when a count does not say it ({@code up to 29 items per export}), else null
 * @param explanation EXPLAINED, UNEXPLAINED, NOT_ESTABLISHED while the personal baseline is still learned (LU-1) or,
 *                    without a usual behaviour, UNKNOWN; null for a value seen before
 * @param explainedBy the record that explains the difference ({@code APR-...}, a trip), null otherwise
 */
public record Deviation(
        DeviationDimension dimension,
        String current,
        boolean compared,
        boolean different,
        Integer seen,
        Integer of,
        String usual,
        Explanation explanation,
        String explainedBy) {

    public enum Explanation {
        EXPLAINED,
        UNEXPLAINED,
        NOT_ESTABLISHED,
        UNKNOWN
    }

    /** A dimension that could not be compared: no usual behaviour, or no value of the request. */
    public static Deviation notCompared(DeviationDimension dimension, String current) {
        return new Deviation(dimension, current, false, false, null, null, null, Explanation.UNKNOWN, null);
    }

    /** The comparison as the prompt states it: {@code time 03 seen 0 of 25 (unexplained)}. */
    public String describe() {
        StringBuilder text = new StringBuilder(dimension.label());
        if (current != null) {
            text.append(' ').append(current);
        }
        if (seen != null && of != null) {
            text.append(" seen ").append(seen).append(" of ").append(of);
        }
        if (usual != null) {
            text.append(", usual ").append(usual);
        }
        if (explanation != null) {
            text.append(" (").append(switch (explanation) {
                case EXPLAINED -> "explained by " + explainedBy;
                case UNEXPLAINED -> "unexplained";
                case NOT_ESTABLISHED -> "baseline not established";
                case UNKNOWN -> "unknown: no usual behaviour to compare with";
            }).append(')');
        }
        return text.toString();
    }
}
