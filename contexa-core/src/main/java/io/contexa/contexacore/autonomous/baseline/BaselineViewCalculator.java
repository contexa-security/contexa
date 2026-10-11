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
package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.ToLongFunction;

/**
 * Computes the observation dimensions of a {@link BaselineView}: one window, one decay and one rule for what is usual,
 * so that every reader of the subject's usual behaviour sees the same values.
 */
public final class BaselineViewCalculator {

    public static final int PRIMARY_WINDOW_DAYS = 7;
    public static final int FALLBACK_WINDOW_DAYS = 30;
    /** The observations the last 7 days need before they alone describe the subject. */
    public static final int MINIMUM_SAMPLE = 10;
    /** An observation this many days old weighs half as much as one made now. */
    static final double HALF_LIFE_DAYS = 14.0;
    /**
     * The usual values of a dimension are the heaviest ones that together carry this share of its weight, with every
     * value seen at least as often as one of them.
     */
    static final double USUAL_COVERAGE = 0.8;
    /**
     * The days the day of the week is read from: a day of the week comes once a week, so the 7-day window would hold
     * a single sample of each and the day a week ago would always weigh least (W2-3 correction).
     */
    public static final int DAY_OF_WEEK_DAYS = FALLBACK_WINDOW_DAYS;
    static final int RARE_MINIMUM_OBSERVATIONS = 20;
    static final int RARE_MAXIMUM_COUNT = 2;
    /** The servlet default session timeout: a longer pause ends an activity period. */
    static final long SESSION_IDLE_MS = 30L * 60L * 1_000L;
    /** The activity periods a usual session length needs: with fewer, the median is one of two values, not usual. */
    static final int MINIMUM_SESSION_PERIODS = 3;

    private static final long HOUR_MS = 60L * 60L * 1_000L;
    private static final long DAY_MS = 24L * HOUR_MS;

    private BaselineViewCalculator() {
    }

    /**
     * One observation confirmed after a decision.
     *
     * @param actionSourceKey the event key the action family was read from
     * @param actionInferred  whether the action family was inferred rather than declared by the host
     * @param pathTemplate    the URL template the host matched, null when it gave none
     * @param sessionKey      a key of the session the request belonged to, null when unknown
     * @param allowed         whether the request was allowed
     * @param items           how many items the request asked for, null when the host did not say (W2-6)
     */
    public record Observation(
            long timestampMs,
            String actionFamily,
            String actionSourceKey,
            boolean actionInferred,
            String resourceClass,
            String pathTemplate,
            String requestPath,
            String sessionKey,
            boolean allowed,
            Integer items) {

        /** An observation without an item count. */
        public Observation(
                long timestampMs,
                String actionFamily,
                String actionSourceKey,
                boolean actionInferred,
                String resourceClass,
                String pathTemplate,
                String requestPath,
                String sessionKey,
                boolean allowed) {
            this(timestampMs, actionFamily, actionSourceKey, actionInferred, resourceClass, pathTemplate, requestPath,
                    sessionKey, allowed, null);
        }
    }

    /** The observations a view describes and why the window is what it is. */
    public record Window(List<Observation> observations, int days, String basis) {
    }

    /** The last 7 days when they hold the minimum sample, else the last 30 days (observations after now are left out). */
    public static Window window(List<Observation> history, long nowMs) {
        List<Observation> selected = windowed(history, Observation::timestampMs, nowMs);
        int primary = (int) selected.stream()
                .filter(observation -> nowMs - observation.timestampMs() <= PRIMARY_WINDOW_DAYS * DAY_MS)
                .count();
        if (primary >= MINIMUM_SAMPLE) {
            return new Window(selected, PRIMARY_WINDOW_DAYS,
                    "the last " + PRIMARY_WINDOW_DAYS + " days hold " + primary + " observations");
        }
        return new Window(selected, FALLBACK_WINDOW_DAYS,
                "the last " + PRIMARY_WINDOW_DAYS + " days hold " + primary
                        + " observations, below the minimum " + MINIMUM_SAMPLE + "; the view uses the last "
                        + FALLBACK_WINDOW_DAYS + " days");
    }

    /**
     * The observations without the activity period the current request belongs to: those of the same session that
     * lead up to now with no pause longer than {@link #SESSION_IDLE_MS}. That period is what the usual behaviour is
     * compared with, so the usual behaviour never includes it.
     */
    public static <T> List<T> withoutCurrentPeriod(
            List<T> history,
            ToLongFunction<T> timestampMs,
            Function<T, String> sessionKey,
            String currentSessionKey,
            long nowMs) {
        return withoutCurrentSessionPeriod(history, timestampMs, sessionKey,
                StringUtils.hasText(currentSessionKey) ? List.of(currentSessionKey) : List.of(), nowMs);
    }

    /**
     * The same, for a session known under several keys: the session's current key and the keys of the ids it had
     * before its id was replaced, as at a step-up check (P2 correction 5).
     */
    public static <T> List<T> withoutCurrentSessionPeriod(
            List<T> history,
            ToLongFunction<T> timestampMs,
            Function<T, String> sessionKey,
            List<String> currentSessionKeys,
            long nowMs) {
        if (history == null || history.isEmpty() || currentSessionKeys == null || currentSessionKeys.isEmpty()) {
            return history == null ? List.of() : history;
        }
        List<T> sameSession = history.stream()
                .filter(observation -> observation != null
                        && currentSessionKeys.contains(sessionKey.apply(observation)))
                .sorted(Comparator.comparingLong(timestampMs).reversed())
                .toList();
        Set<T> currentPeriod = Collections.newSetFromMap(new IdentityHashMap<>());
        long next = nowMs;
        for (T observation : sameSession) {
            long time = timestampMs.applyAsLong(observation);
            if (next - time > SESSION_IDLE_MS) {
                break;
            }
            currentPeriod.add(observation);
            next = time;
        }
        if (currentPeriod.isEmpty()) {
            return history;
        }
        return history.stream().filter(observation -> !currentPeriod.contains(observation)).toList();
    }

    /** The window rule for any kind of observation, so that every summary of the subject reads the same ones (A-19). */
    public static <T> List<T> windowed(List<T> history, ToLongFunction<T> timestampMs, long nowMs) {
        List<T> fallback = new ArrayList<>();
        List<T> primary = new ArrayList<>();
        if (history != null) {
            for (T observation : history) {
                if (observation == null || timestampMs.applyAsLong(observation) > nowMs) {
                    continue;
                }
                long age = nowMs - timestampMs.applyAsLong(observation);
                if (age <= FALLBACK_WINDOW_DAYS * DAY_MS) {
                    fallback.add(observation);
                    if (age <= PRIMARY_WINDOW_DAYS * DAY_MS) {
                        primary.add(observation);
                    }
                }
            }
        }
        return List.copyOf(primary.size() >= MINIMUM_SAMPLE ? primary : fallback);
    }

    public static BaselineView calculate(List<Observation> history, long nowMs, ZoneId zone) {
        Window window = window(history, nowMs);
        List<Observation> observations = window.observations();
        int count = observations.size();
        if (count == 0) {
            return new BaselineView(BaselineView.State.NONE, null, 0, 0, window.days(), window.basis(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), Map.of(), null, null, List.of(), null, null, 0,
                    List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), BaselineView.EvidenceGrade.WEAK,
                    List.of("no observation confirmed after a decision in the last " + FALLBACK_WINDOW_DAYS + " days"));
        }

        Map<Integer, Double> hourWeights = new TreeMap<>();
        Map<Integer, Double> dayWeights = new TreeMap<>();
        Map<Integer, Integer> hourCounts = new TreeMap<>();
        Map<Integer, Integer> dayCounts = new TreeMap<>();
        int dayObservations = 0;
        // The day of the week reads several weeks, every other dimension the window.
        for (Observation observation : history == null ? List.<Observation>of() : history) {
            if (observation == null || observation.timestampMs() > nowMs
                    || nowMs - observation.timestampMs() > DAY_OF_WEEK_DAYS * DAY_MS) {
                continue;
            }
            double weight = Math.pow(0.5, (nowMs - observation.timestampMs()) / (HALF_LIFE_DAYS * DAY_MS));
            int day = LocalDateTime.ofInstant(Instant.ofEpochMilli(observation.timestampMs()), zone)
                    .getDayOfWeek().getValue();
            dayWeights.merge(day, weight, Double::sum);
            dayCounts.merge(day, 1, Integer::sum);
            dayObservations++;
        }
        Map<Long, Integer> activeHourCounts = new HashMap<>();
        Map<String, Double> targetWeights = new TreeMap<>();
        Map<String, Integer> targetCounts = new TreeMap<>();
        Map<String, Integer> familyCounts = new TreeMap<>();
        Map<String, Integer> classCounts = new TreeMap<>();
        Map<String, Integer> inferredBySource = new TreeMap<>();
        Map<String, Integer> allowedTasks = new TreeMap<>();
        Map<String, List<Long>> sessionTimes = new TreeMap<>();
        Set<LocalDate> days = new HashSet<>();
        Set<Long> activeHours = new HashSet<>();
        List<Integer> exportItems = new ArrayList<>();
        int privileged = 0;

        for (Observation observation : observations) {
            double weight = Math.pow(0.5, (nowMs - observation.timestampMs()) / (HALF_LIFE_DAYS * DAY_MS));
            LocalDateTime at = LocalDateTime.ofInstant(Instant.ofEpochMilli(observation.timestampMs()), zone);
            hourWeights.merge(at.getHour(), weight, Double::sum);
            hourCounts.merge(at.getHour(), 1, Integer::sum);
            days.add(at.toLocalDate());
            activeHours.add(observation.timestampMs() / HOUR_MS);
            activeHourCounts.merge(observation.timestampMs() / HOUR_MS, 1, Integer::sum);

            String target = target(observation.pathTemplate(), observation.requestPath());
            if (target != null) {
                targetWeights.merge(target, weight, Double::sum);
                targetCounts.merge(target, 1, Integer::sum);
            }
            ActionFamily family = ActionFamily.of(observation.actionFamily());
            if (family != null) {
                familyCounts.merge(family.name(), 1, Integer::sum);
                if (family == ActionFamily.ADMIN) {
                    privileged++;
                }
                if (family == ActionFamily.EXPORT && observation.items() != null && observation.items() > 0) {
                    exportItems.add(observation.items());
                }
                if (observation.allowed()) {
                    allowedTasks.merge(family.name() + " " + pathOf(observation), 1, Integer::sum);
                }
            }
            if (observation.actionInferred()) {
                inferredBySource.merge(StringUtils.hasText(observation.actionSourceKey())
                        ? observation.actionSourceKey() : "an unnamed source", 1, Integer::sum);
            }
            String resourceClass = SecuritySemanticNormalizer.normalizeResourceFamily(observation.resourceClass());
            if (StringUtils.hasText(resourceClass)) {
                classCounts.merge(resourceClass, 1, Integer::sum);
            }
            if (StringUtils.hasText(observation.sessionKey())) {
                sessionTimes.computeIfAbsent(observation.sessionKey(), key -> new ArrayList<>())
                        .add(observation.timestampMs());
            }
        }

        Map<String, Integer> actionCounts = new LinkedHashMap<>();
        for (ActionFamily family : ActionFamily.values()) {
            Integer familyCount = familyCounts.get(family.name());
            if (familyCount != null) {
                actionCounts.put(family.name(), familyCount);
            }
        }
        List<String> causes = new ArrayList<>();
        if (count < MINIMUM_SAMPLE) {
            causes.add("only " + count + " observations in the window, below the minimum " + MINIMUM_SAMPLE);
        }
        if (window.days() == FALLBACK_WINDOW_DAYS) {
            causes.add(window.basis());
        }
        int inferredFromHttpMethod = 0;
        for (Map.Entry<String, Integer> source : byCountDescending(inferredBySource)) {
            causes.add("action family inferred from " + source.getKey() + " in " + source.getValue() + " of " + count
                    + " observations");
            if ("httpMethod".equals(source.getKey()) || "method".equals(source.getKey())) {
                inferredFromHttpMethod += source.getValue();
            }
        }
        BaselineView.EvidenceGrade grade = count < MINIMUM_SAMPLE || inferredFromHttpMethod * 2 > count
                ? BaselineView.EvidenceGrade.WEAK
                : causes.isEmpty() ? BaselineView.EvidenceGrade.STRONG : BaselineView.EvidenceGrade.LIMITED;

        return new BaselineView(
                BaselineView.State.NONE,
                null,
                count,
                days.size(),
                window.days(),
                window.basis(),
                ascending(usual(hourWeights, hourCounts)),
                List.copyOf(hourWeights.keySet()),
                ascending(usual(dayWeights, dayCounts)),
                List.copyOf(dayWeights.keySet()),
                usual(recurring(targetWeights, targetCounts), targetCounts),
                actionCounts,
                readWriteExportRatio(actionCounts),
                exportSize(exportItems),
                byCountDescending(classCounts).stream().map(entry -> entry.getKey() + "=" + entry.getValue()).toList(),
                Math.round(count * 100.0 / Math.max(1, activeHours.size())) / 100.0,
                usualSessionMinutes(sessionTimes),
                privileged,
                knownRareTasks(allowedTasks, count),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                grade,
                causes,
                new BaselineView.Counts(hourCounts, dayCounts, targetCounts,
                        activeHourCounts.values().stream().mapToInt(Integer::intValue).max().orElse(0),
                        dayObservations));
    }

    /**
     * The URL template's variables bound to the request path's segments ({@code projectKey=PLM-OPS}), or null when
     * there is no template or the path does not have its shape.
     */
    public static String target(String template, String path) {
        if (!StringUtils.hasText(template) || !StringUtils.hasText(path) || !template.contains("{")) {
            return null;
        }
        String[] templateSegments = segments(template);
        String[] pathSegments = segments(path);
        if (templateSegments.length != pathSegments.length) {
            return null;
        }
        List<String> bindings = new ArrayList<>();
        for (int index = 0; index < templateSegments.length; index++) {
            String segment = templateSegments[index];
            if (segment.length() > 2 && segment.startsWith("{") && segment.endsWith("}")) {
                bindings.add(segment.substring(1, segment.length() - 1) + "=" + pathSegments[index]);
            }
            else if (!segment.equals(pathSegments[index])) {
                return null;
            }
        }
        return bindings.isEmpty() ? null : String.join(",", bindings);
    }

    private static String[] segments(String path) {
        String withoutQuery = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        return Arrays.stream(withoutQuery.split("/")).filter(StringUtils::hasText).toArray(String[]::new);
    }

    private static String pathOf(Observation observation) {
        return StringUtils.hasText(observation.pathTemplate())
                ? observation.pathTemplate()
                : SecuritySemanticNormalizer.normalizePathFamily(observation.requestPath());
    }

    /**
     * The heaviest values that together carry {@link #USUAL_COVERAGE} of the weight, the heaviest first, then every
     * other value seen at least as often as the least seen of them: the decay orders values, it does not make one of
     * two equally frequent values unusual (W2-3 correction).
     */
    private static <K extends Comparable<K>> List<K> usual(Map<K, Double> weights, Map<K, Integer> counts) {
        double total = weights.values().stream().mapToDouble(Double::doubleValue).sum();
        List<K> usual = new ArrayList<>();
        List<K> rest = new ArrayList<>();
        double covered = 0;
        int leastSeen = Integer.MAX_VALUE;
        for (Map.Entry<K, Double> entry : weights.entrySet().stream()
                .sorted(Map.Entry.<K, Double>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .toList()) {
            if (covered >= total * USUAL_COVERAGE) {
                rest.add(entry.getKey());
                continue;
            }
            usual.add(entry.getKey());
            covered += entry.getValue();
            leastSeen = Math.min(leastSeen, counts.getOrDefault(entry.getKey(), 0));
        }
        for (K value : rest) {
            if (counts.getOrDefault(value, 0) >= leastSeen) {
                usual.add(value);
            }
        }
        return List.copyOf(usual);
    }

    private static List<Integer> ascending(List<Integer> values) {
        return values.stream().sorted().toList();
    }

    private static List<Map.Entry<String, Integer>> byCountDescending(Map<String, Integer> counts) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .toList();
    }

    /** Read, write (with delete) and export shares in whole percent that add up to 100. */
    static String readWriteExportRatio(Map<String, Integer> actionCounts) {
        int read = actionCounts.getOrDefault(ActionFamily.READ.name(), 0);
        int write = actionCounts.getOrDefault(ActionFamily.WRITE.name(), 0)
                + actionCounts.getOrDefault(ActionFamily.DELETE.name(), 0);
        int export = actionCounts.getOrDefault(ActionFamily.EXPORT.name(), 0);
        int total = read + write + export;
        if (total == 0) {
            return null;
        }
        double[] exact = {read * 100.0 / total, write * 100.0 / total, export * 100.0 / total};
        int[] rounded = {(int) Math.floor(exact[0]), (int) Math.floor(exact[1]), (int) Math.floor(exact[2])};
        int remainder = 100 - rounded[0] - rounded[1] - rounded[2];
        List<Integer> order = List.of(0, 1, 2).stream()
                .sorted(Comparator.comparingDouble((Integer index) -> exact[index] - Math.floor(exact[index])).reversed())
                .toList();
        for (int index = 0; index < remainder; index++) {
            rounded[order.get(index)]++;
        }
        return rounded[0] + ":" + rounded[1] + ":" + rounded[2];
    }

    /**
     * The median length of the subject's activity periods with two or more requests, when there are at least
     * {@link #MINIMUM_SESSION_PERIODS} of them. A session idle longer than the servlet default session timeout starts a
     * new period, so a session key reused across days is not one long session.
     */
    private static Integer usualSessionMinutes(Map<String, List<Long>> sessionTimes) {
        List<Long> minutes = new ArrayList<>();
        for (List<Long> times : sessionTimes.values()) {
            List<Long> ordered = times.stream().sorted().toList();
            long start = ordered.get(0);
            long last = start;
            int count = 1;
            for (int index = 1; index < ordered.size(); index++) {
                long time = ordered.get(index);
                if (time - last > SESSION_IDLE_MS) {
                    if (count >= 2) {
                        minutes.add(Math.round((last - start) / 60_000.0));
                    }
                    start = time;
                    count = 0;
                }
                last = time;
                count++;
            }
            if (count >= 2) {
                minutes.add(Math.round((last - start) / 60_000.0));
            }
        }
        if (minutes.size() < MINIMUM_SESSION_PERIODS) {
            return null;
        }
        List<Long> ordered = minutes.stream().sorted().toList();
        return Math.toIntExact(ordered.get((ordered.size() - 1) / 2));
    }

    /** The item counts of the exports that said theirs; null when none did. */
    private static BaselineView.ExportSize exportSize(List<Integer> items) {
        if (items.isEmpty()) {
            return null;
        }
        List<Integer> ordered = items.stream().sorted().toList();
        return new BaselineView.ExportSize(ordered.size(), ordered.get((ordered.size() - 1) / 2),
                ordered.get(ordered.size() - 1));
    }

    /** The values seen at least twice: one document read once is not a usual target. */
    private static Map<String, Double> recurring(Map<String, Double> weights, Map<String, Integer> counts) {
        Map<String, Double> recurring = new TreeMap<>();
        weights.forEach((value, weight) -> {
            if (counts.getOrDefault(value, 0) >= 2) {
                recurring.put(value, weight);
            }
        });
        return recurring;
    }

    private static List<String> knownRareTasks(Map<String, Integer> allowedTasks, int count) {
        if (count < RARE_MINIMUM_OBSERVATIONS) {
            return List.of();
        }
        return allowedTasks.entrySet().stream()
                .filter(entry -> entry.getValue() <= RARE_MAXIMUM_COUNT)
                .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                .toList();
    }
}
