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
package io.contexa.contexacore.std.components.prompt.quality;

/**
 * The paired comparison of one rate between the version in use and a candidate (plan 3.3), with the numbers behind
 * the verdict. Both rates are taken over the cases both measurements scored.
 *
 * @param metric            the rate
 * @param verdict           better, the same, worse, or undecidable
 * @param currentValue      the rate of the version in use over the paired cases; NaN when nothing is paired
 * @param candidateValue    the rate of the candidate over the paired cases; NaN when nothing is paired
 * @param noiseWidth        how far two measurements of the same version differ on this rate; NaN when not measured
 * @param pairedCases       the cases both measurements scored for this rate
 * @param pairedRoots       the distinct roots of those cases
 * @param worseRoots        the roots where the candidate is worse
 * @param betterRoots       the roots where the candidate is better
 * @param worseProbability  the exact one-sided chance of at least this many worse roots among those that differ, if
 *                          a root were as likely to turn either way
 * @param betterProbability the same for the better roots
 */
public record QualityComparison(QualityMetric metric, QualityVerdict verdict, double currentValue,
                                double candidateValue, double noiseWidth, int pairedCases, int pairedRoots,
                                int worseRoots, int betterRoots, double worseProbability, double betterProbability) {

    /** The candidate's rate less the rate of the version in use; NaN when nothing is paired. */
    public double difference() {
        return candidateValue - currentValue;
    }
}
