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
package io.contexa.contexaiam.admin.promptquality.screen;

/**
 * Quality plan 3.2, "how many are needed": the chance that the cases tell apart a version that misses fewer cases,
 * computed exactly rather than simulated. It is the chance of the comparison the quality gate makes
 * (QualityComparator): the exact sign test, one sided at the significance level, over the distinct roots whose result
 * the two versions turn. Each root to stop is taken as independent; the version in use misses with the base rate and
 * the better one with the base rate less the difference; the two versions' results on one root go together with a
 * correlation of their latent scores (a bivariate normal), so a root both miss is likelier than chance.
 */
public final class QualityCasePower {

    /** The improvement the chance is about: a version that misses 10 points less (plan 3.2). */
    public static final double DIFFERENCE = 0.10;
    /** How much the two versions' results on one root go together (plan 3.2). */
    public static final double CORRELATION = 0.7;
    /** Above this many roots the chance is the one of this many: it is 1 to the shown precision long before. */
    static final int MOST_ROOTS = 5000;

    private QualityCasePower() {
    }

    /**
     * The chance that the gate's comparison finds the better version better.
     *
     * @param roots        the distinct roots to stop
     * @param baseMiss     the miss rate of the version in use, more than {@link #DIFFERENCE}
     * @param significance the level of the sign test, such as 0.05
     */
    public static double of(int roots, double baseMiss, double significance) {
        if (roots <= 0) {
            return 0;
        }
        if (!(baseMiss > DIFFERENCE && baseMiss < 1)) {
            throw new IllegalArgumentException("The base miss rate lies above the difference and below 1: " + baseMiss);
        }
        int n = Math.min(roots, MOST_ROOTS);
        double worse = baseMiss;
        double better = baseMiss - DIFFERENCE;
        double both = bivariateNormal(inverseNormal(worse), inverseNormal(better), CORRELATION);
        // A root the version in use misses and the better one catches turns better; the reverse turns worse.
        double turnsBetter = Math.max(0, worse - both);
        double turnsWorse = Math.max(0, better - both);
        double turns = turnsBetter + turnsWorse;
        if (turns <= 0) {
            return 0;
        }
        double towardBetter = turnsBetter / turns;
        double[] logFactorial = logFactorials(n);
        double power = 0;
        for (int turned = 1; turned <= n; turned++) {
            double chanceTurned = Math.exp(logBinomial(logFactorial, n, turned, turns));
            if (chanceTurned < 1e-15) {
                continue;
            }
            int needed = critical(logFactorial, turned, significance);
            if (needed > turned) {
                continue;
            }
            double tail = 0;
            for (int k = needed; k <= turned; k++) {
                tail += Math.exp(logBinomial(logFactorial, turned, k, towardBetter));
            }
            power += chanceTurned * Math.min(1, tail);
        }
        return Math.min(1, Math.max(0, power));
    }

    /** The fewest of {@code trials} on one side that the one-sided exact sign test finds at the level. */
    static int critical(double[] logFactorial, int trials, double significance) {
        double tail = 0;
        for (int k = trials; k >= 1; k--) {
            tail += Math.exp(logFactorial[trials] - logFactorial[k] - logFactorial[trials - k] - trials * Math.log(2));
            if (tail > significance) {
                return k + 1;
            }
        }
        return 1;
    }

    private static double logBinomial(double[] logFactorial, int n, int k, double p) {
        double logP = k == 0 ? 0 : k * Math.log(p);
        double logQ = n - k == 0 ? 0 : (n - k) * Math.log1p(-p);
        return logFactorial[n] - logFactorial[k] - logFactorial[n - k] + logP + logQ;
    }

    private static double[] logFactorials(int n) {
        double[] values = new double[n + 1];
        for (int i = 2; i <= n; i++) {
            values[i] = values[i - 1] + Math.log(i);
        }
        return values;
    }

    /** P(X below a and Y below b) of two standard normals of the correlation, by Simpson's rule over X. */
    static double bivariateNormal(double a, double b, double correlation) {
        double lower = -9;
        if (a <= lower) {
            return 0;
        }
        int steps = 4000;
        double width = (a - lower) / steps;
        double spread = Math.sqrt(1 - correlation * correlation);
        double sum = 0;
        for (int i = 0; i <= steps; i++) {
            double x = lower + i * width;
            double value = density(x) * normal((b - correlation * x) / spread);
            sum += value * (i == 0 || i == steps ? 1 : i % 2 == 1 ? 4 : 2);
        }
        return sum * width / 3;
    }

    private static double density(double x) {
        return Math.exp(-x * x / 2) / Math.sqrt(2 * Math.PI);
    }

    /** The standard normal distribution (Abramowitz and Stegun 7.1.26, error below 1.5e-7). */
    static double normal(double x) {
        double z = Math.abs(x) / Math.sqrt(2);
        double t = 1 / (1 + 0.3275911 * z);
        double erf = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
                + 0.254829592) * t * Math.exp(-z * z);
        return x >= 0 ? (1 + erf) / 2 : (1 - erf) / 2;
    }

    /** The quantile of the standard normal distribution, by bisection. */
    static double inverseNormal(double p) {
        double low = -9;
        double high = 9;
        for (int i = 0; i < 100; i++) {
            double middle = (low + high) / 2;
            if (normal(middle) < p) {
                low = middle;
            }
            else {
                high = middle;
            }
        }
        return (low + high) / 2;
    }
}
