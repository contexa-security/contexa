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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

/**
 * The statistics of the quality measurement (plan 3.3). Everything is a closed form or an exact count, so the same
 * input always gives the same number.
 */
public final class QualityStatistics {

    /** The normal quantile of a two-sided 95% interval. */
    public static final double Z_95 = 1.959963984540054;

    private QualityStatistics() {
    }

    /**
     * The 95% Wilson interval of a proportion over a sample, as lower and upper end; both NaN when there is no sample
     * or no proportion. The rates of a measurement pass the number of distinct roots as the sample: the variants of
     * one root are not independent, so the interval counts a root once however many variants and runs it has. This
     * takes the answers under one root as fully dependent, which is the widest reading; adding variants of roots
     * already counted does not narrow it, and at 0% or 100% it still has a width, where an interval from the spread
     * between roots would collapse.
     */
    public static double[] wilson(double proportion, int sample) {
        if (sample <= 0 || Double.isNaN(proportion)) {
            return new double[] {Double.NaN, Double.NaN};
        }
        double n = sample;
        double z2 = Z_95 * Z_95;
        double denominator = 1 + z2 / n;
        double centre = (proportion + z2 / (2 * n)) / denominator;
        double half = Z_95 * Math.sqrt(proportion * (1 - proportion) / n + z2 / (4 * n * n)) / denominator;
        // The ends at 0% and 100% are exact: rounding must not leave the proportion itself outside its interval.
        double lower = proportion <= 0 ? 0 : Math.max(0, centre - half);
        double upper = proportion >= 1 ? 1 : Math.min(1, centre + half);
        return new double[] {lower, upper};
    }

    /**
     * The exact sign test, one sided: the chance that at least {@code successes} of {@code trials} fall on one side
     * when either side is as likely. With no trials it is 1.
     */
    public static double signTestTail(int successes, int trials) {
        if (successes < 0 || trials < 0 || successes > trials) {
            throw new IllegalArgumentException("Not a count of trials: " + successes + " of " + trials);
        }
        if (successes == 0) {
            return 1.0;
        }
        BigInteger term = BigInteger.ONE;
        BigInteger tail = BigInteger.ZERO;
        // C(trials, k) for k from 0 up, added from the first k of the tail on.
        for (int k = 0; k <= trials; k++) {
            if (k >= successes) {
                tail = tail.add(term);
            }
            term = term.multiply(BigInteger.valueOf(trials - k)).divide(BigInteger.valueOf(k + 1L));
        }
        return ratio(tail, BigInteger.TWO.pow(trials));
    }

    /**
     * The exact test of Fisher, one sided: with the totals of both groups and of the marked units fixed, the chance
     * that the first group holds at least {@code firstMarked} of the marked units.
     */
    public static double fisherTail(int firstMarked, int firstTotal, int secondMarked, int secondTotal) {
        if (firstMarked < 0 || secondMarked < 0 || firstMarked > firstTotal || secondMarked > secondTotal) {
            throw new IllegalArgumentException("Not a table of counts: " + firstMarked + " of " + firstTotal + ", "
                    + secondMarked + " of " + secondTotal);
        }
        int marked = firstMarked + secondMarked;
        BigInteger[] first = binomials(firstTotal);
        BigInteger[] second = binomials(secondTotal);
        BigInteger tail = BigInteger.ZERO;
        BigInteger all = BigInteger.ZERO;
        for (int x = Math.max(0, marked - secondTotal); x <= Math.min(firstTotal, marked); x++) {
            BigInteger ways = first[x].multiply(second[marked - x]);
            all = all.add(ways);
            if (x >= firstMarked) {
                tail = tail.add(ways);
            }
        }
        return ratio(tail, all);
    }

    private static BigInteger[] binomials(int n) {
        BigInteger[] row = new BigInteger[n + 1];
        row[0] = BigInteger.ONE;
        for (int k = 0; k < n; k++) {
            row[k + 1] = row[k].multiply(BigInteger.valueOf(n - k)).divide(BigInteger.valueOf(k + 1L));
        }
        return row;
    }

    private static double ratio(BigInteger part, BigInteger whole) {
        return new BigDecimal(part).divide(new BigDecimal(whole), MathContext.DECIMAL64).doubleValue();
    }
}
