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
 * One rate of a measurement with its sample (plan 3.3): the count the rate is made of, the cases behind it and the
 * distinct roots among them, which the 95% interval is taken over.
 *
 * @param events         the count in the numerator: answers for most rates, cited facts for the citation accuracy,
 *                       cases for the consistency
 * @param trials         the count in the denominator
 * @param cases          the cases with at least one trial
 * @param casesWithEvent the cases with at least one event: the share of cases where it happened in any run, which
 *                       grows with the number of runs and is shown only beside the rate
 * @param roots          the distinct roots of those cases: the effective sample of the interval
 */
public record QualityRate(long events, long trials, int cases, int casesWithEvent, int roots) {

    /** Whether there is anything to take the rate of. */
    public boolean defined() {
        return trials > 0;
    }

    /** The rate, or NaN when nothing was counted. */
    public double value() {
        return defined() ? (double) events / trials : Double.NaN;
    }

    /** The share of cases where the event happened in at least one run, or NaN when nothing was counted. */
    public double anyRunValue() {
        return cases > 0 ? (double) casesWithEvent / cases : Double.NaN;
    }

    /** The lower end of the 95% interval over the roots, or NaN when nothing was counted. */
    public double lower() {
        return QualityStatistics.wilson(value(), roots)[0];
    }

    /** The upper end of the 95% interval over the roots, or NaN when nothing was counted. */
    public double upper() {
        return QualityStatistics.wilson(value(), roots)[1];
    }
}
