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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.MetricValue;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.RangedMetric;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Share;
import org.springframework.context.MessageSource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The metric definitions of the console (console design 5), in one place: every metric has a name and a definition
 * from the messages, a value, and for a ratio its numerator and denominator. A metric without data has no value and
 * says why: a value of 0 is never shown for an empty denominator.
 */
public final class ZeroTrustConsoleMetrics {

    /** No decision in the period. */
    public static final String NO_DECISIONS = "NO_DECISIONS";
    /** Nothing the ratio is a share of. */
    public static final String EMPTY_DENOMINATOR = "EMPTY_DENOMINATOR";
    /** The coverage counts are the nodes' over every tenant: a tenant's coverage cannot be read. */
    public static final String TENANT_FILTERED = "TENANT_FILTERED";
    /** Nothing records this number. */
    public static final String NOT_RECORDED = "NOT_RECORDED";
    /** The period's decisions were stored before this number was recorded (K22). */
    public static final String NOT_MEASURED = "NOT_MEASURED";
    /** No price is set, so no cost can be estimated. */
    public static final String NO_PRICE = "NO_PRICE";
    /** Nobody waited for a decision: no synchronous decision in the period. */
    public static final String NO_SYNCHRONOUS_DECISIONS = "NO_SYNCHRONOUS_DECISIONS";

    /** The upper bounds of the latency buckets, in milliseconds; the last bucket has none. */
    static final long[] LATENCY_BOUNDS = {100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000};

    private static final double Z = 1.959964;

    private final MessageSource messages;
    private final Locale locale;

    ZeroTrustConsoleMetrics(MessageSource messages, Locale locale) {
        this.messages = messages;
        this.locale = locale == null ? Locale.ENGLISH : locale;
    }

    String label(String key) {
        return message("zt.console.metric." + key + ".label", key);
    }

    String description(String key) {
        return message("zt.console.metric." + key + ".description", "");
    }

    String message(String key, String fallback, Object... args) {
        if (messages == null) {
            return fallback;
        }
        return messages.getMessage(key, args, fallback, locale);
    }

    MetricValue count(String key, long value) {
        return new MetricValue(key, label(key), description(key), (double) value, value, null, "COUNT", null);
    }

    MetricValue ratio(String key, long numerator, long denominator, String noDataReason) {
        return new MetricValue(key, label(key), description(key),
                denominator <= 0 ? null : (double) numerator / denominator, numerator, denominator, "RATIO",
                denominator <= 0 ? (noDataReason != null ? noDataReason : EMPTY_DENOMINATOR) : null);
    }

    MetricValue value(String key, Double value, String unit, String noDataReason) {
        return new MetricValue(key, label(key), description(key), value, null, null, unit,
                value == null ? (noDataReason != null ? noDataReason : EMPTY_DENOMINATOR) : null);
    }

    /**
     * A value shown as the bucket of a histogram it falls in (the unit names the buckets' words): the bucket's index,
     * with the count it was read from; without a count, "—" and why.
     */
    MetricValue bucket(String key, Integer index, long counted, String unit, String noDataReason) {
        return new MetricValue(key, label(key), description(key), index == null ? null : index.doubleValue(),
                counted, null, unit, index == null ? noDataReason : null);
    }

    MetricValue unavailable(String key, String unit, String reason) {
        return new MetricValue(key, label(key), description(key), null, null, null, unit, reason);
    }

    /** A ratio with its 95% range (Wilson score interval), so a small sample is read with its uncertainty. */
    RangedMetric ranged(String key, long numerator, long denominator, String noDataReason) {
        MetricValue metric = ratio(key, numerator, denominator, noDataReason);
        double[] range = wilson(numerator, denominator);
        return new RangedMetric(metric, range == null ? null : range[0], range == null ? null : range[1],
                Math.max(0, denominator));
    }

    /** The Wilson score interval at 95% of k successes in n trials; null for no trial. */
    static double[] wilson(long k, long n) {
        if (n <= 0) {
            return null;
        }
        double p = Math.min(1.0, Math.max(0.0, (double) k / n));
        double z2 = Z * Z;
        double denominator = 1 + z2 / n;
        double center = (p + z2 / (2.0 * n)) / denominator;
        double half = Z * Math.sqrt(p * (1 - p) / n + z2 / (4.0 * n * n)) / denominator;
        return new double[] {Math.max(0.0, center - half), Math.min(1.0, center + half)};
    }

    /**
     * The percentile of a latency histogram (counts per bucket of {@link #LATENCY_BOUNDS} and one past the last),
     * read linearly inside its bucket; a percentile past the last bound is the last bound. Null for no measurement.
     */
    static Long percentile(long[] buckets, double p) {
        return percentile(buckets, LATENCY_BOUNDS, p);
    }

    /** The bounds of the decision time buckets of the hourly table (1 s to 90 s, and one past the last). */
    static final long[] HOURLY_LATENCY_BOUNDS = {1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 90_000};

    /** As {@link #percentile(long[], double)}, for a histogram of the given bounds. */
    /**
     * The bucket of a histogram the p-th percentile falls in: the first bucket whose running count reaches p of the
     * whole, so the median of an even count is the bucket of the lower of the two middle values. Null for no count.
     */
    static Integer bucketOf(long[] buckets, double p) {
        long total = 0;
        for (long count : buckets) {
            total += count;
        }
        if (total == 0) {
            return null;
        }
        double rank = p * total;
        long below = 0;
        for (int i = 0; i < buckets.length; i++) {
            below += buckets[i];
            if (buckets[i] > 0 && below >= rank) {
                return i;
            }
        }
        return buckets.length - 1;
    }

    static Long percentile(long[] buckets, long[] bounds, double p) {
        long total = 0;
        for (long count : buckets) {
            total += count;
        }
        if (total == 0) {
            return null;
        }
        double rank = p * total;
        long below = 0;
        for (int i = 0; i < buckets.length; i++) {
            long inBucket = buckets[i];
            if (inBucket > 0 && below + inBucket >= rank) {
                if (i >= bounds.length) {
                    return bounds[bounds.length - 1];
                }
                long lower = i == 0 ? 0 : bounds[i - 1];
                long upper = bounds[i];
                double inside = (rank - below) / inBucket;
                return Math.round(lower + inside * (upper - lower));
            }
            below += inBucket;
        }
        return bounds[bounds.length - 1];
    }

    /** The value at a percentile of a list of values (nearest rank); null for an empty list. */
    static Double percentileOf(List<Double> values, double p) {
        if (values.isEmpty()) {
            return null;
        }
        List<Double> sorted = new ArrayList<>(values);
        sorted.sort(Comparator.naturalOrder());
        int rank = (int) Math.ceil(p * sorted.size());
        return sorted.get(Math.min(sorted.size() - 1, Math.max(0, rank - 1)));
    }

    /** The parts of a whole, largest first; each part's share of the sum. */
    static List<Share> shares(Map<String, Long> counts) {
        long total = counts.values().stream().mapToLong(Long::longValue).sum();
        List<Share> shares = new ArrayList<>();
        counts.forEach((key, count) -> shares.add(new Share(key, count, total == 0 ? null : (double) count / total)));
        shares.sort(Comparator.comparingLong(Share::count).reversed().thenComparing(Share::key));
        return shares;
    }

    /** The parts of a whole whose sum is given, largest first. */
    static List<Share> sharesOf(Map<String, Long> counts, long whole) {
        List<Share> shares = new ArrayList<>();
        counts.forEach((key, count) -> shares.add(new Share(key, count, whole <= 0 ? null : (double) count / whole)));
        shares.sort(Comparator.comparingLong(Share::count).reversed().thenComparing(Share::key));
        return shares;
    }

    static long sum(Collection<Long> values) {
        return values.stream().mapToLong(Long::longValue).sum();
    }
}
